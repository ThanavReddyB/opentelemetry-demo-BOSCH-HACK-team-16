# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Allowlisted Action API, Remediation Policy, Human Approval Gate, Kill Switch & Recovery Verifier.

Enforces Architecture v2 (Sections 7, 8, 9, 10):
- LLM never executes actions directly; deterministic code validates policy and requires human approval.
- Approval is bound to a SHA-256 digest of (incident_id, action_type, target, parameters, rollback).
- Kill switch ('kill_switch.flag') immediately halts investigation and blocks execution.
- Supports --dry-run mode and writes append-only audit logs to oncall-agent/logs/audit.jsonl.
"""
import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

import requests

import ops_tools

AGENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = AGENT_DIR.parent
DEMO_DIR = Path(os.environ.get("DEMO_DIR", str(REPO_ROOT))).expanduser().resolve()
COMPOSE = ["docker", "compose"] + shlex.split(os.environ.get("COMPOSE_ARGS", ""))

KILL_SWITCH_FILE = AGENT_DIR / "KILL_SWITCH"
LOGS_DIR = AGENT_DIR / "logs"
REPORTS_DIR = AGENT_DIR / "reports"
AUDIT_LOG_FILE = LOGS_DIR / "audit.jsonl"

FLAGD_UI_API = os.environ.get("FLAGD_UI_API_URL", "http://localhost:8080/feature/api").rstrip("/")
LOCUST_API = os.environ.get("LOCUST_API_URL", "http://localhost:8080/loadgen").rstrip("/")

# Runbook Allowlist: Only these 4 action types are permitted.
ALLOWED_ACTIONS = {
    "restart_service",
    "toggle_feature_flag",
    "throttle_load_generator",
    "scale_service",
}

ALLOWED_SERVICES = {
    "ad",
    "accounting",
    "astronomy-db",
    "cart",
    "checkout",
    "currency",
    "email",
    "fraud-detection",
    "frontend",
    "frontend-proxy",
    "image-provider",
    "kafka",
    "load-generator",
    "payment",
    "product-catalog",
    "quote",
    "recommendation",
    "shipping",
    "valkey-cart",
}

# Static runbook mapping from fault service / symptom to allowlisted feature flag names.
# Note: The agent NEVER reads flagd to diagnose; this allowlist is used ONLY in the remediation layer.
ALLOWED_FLAGS = {
    "adFailure",
    "adHighCpu",
    "adManualGc",
    "cartFailure",
    "emailMemoryLeak",
    "failedReadinessProbe",
    "imageSlowLoad",
    "intlShippingSlowdown",
    "kafkaConsumerDead",
    "kafkaQueueProblems",
    "loadGeneratorFloodHomepage",
    "paymentFailure",
    "paymentUnreachable",
    "productCatalogFailure",
    "productCatalogLockContention",
    "recommendationCacheFailure",
}

SERVICE_TO_FAULT_FLAG = {
    ("payment", "app_error"): "paymentFailure",
    ("payment", "dependency_down"): "paymentUnreachable",
    ("checkout", "dependency_down"): "paymentUnreachable",
    ("cart", "app_error"): "cartFailure",
    ("cart", "partial_failure"): "cartFailure",
    ("product-catalog", "partial_failure"): "productCatalogFailure",
    ("product-catalog", "app_error"): "productCatalogFailure",
    ("recommendation", "memory_leak"): "recommendationCacheFailure",
    ("email", "memory_leak"): "emailMemoryLeak",
    ("ad", "app_error"): "adFailure",
    ("ad", "cpu_saturation"): "adHighCpu",
    ("frontend", "traffic_flood"): "loadGeneratorFloodHomepage",
    ("load-generator", "traffic_flood"): "loadGeneratorFloodHomepage",
    ("fraud-detection", "app_error"): "kafkaQueueProblems",
}


# ---------- Kill Switch & Audit Log ----------
def is_kill_switch_active() -> bool:
    if os.environ.get("KILL_SWITCH", "").lower() in ("1", "true", "on"):
        return True
    return KILL_SWITCH_FILE.exists()


def set_kill_switch(active: bool, reason: str = "operator command") -> dict:
    if active:
        KILL_SWITCH_FILE.write_text(
            json.dumps({"activated_at": _now(), "reason": reason}) + "\n",
            encoding="utf-8",
        )
        log_audit("kill_switch_on", {"reason": reason})
        return {"kill_switch": "ON", "file": str(KILL_SWITCH_FILE)}
    else:
        KILL_SWITCH_FILE.unlink(missing_ok=True)
        log_audit("kill_switch_off", {"reason": reason})
        return {"kill_switch": "OFF"}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def log_audit(event: str, payload: dict) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": _now(), "event": event, **payload}
    with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


# ---------- Remediation Policy & Plan Builder ----------
def build_action_plan(incident_id: str, diagnosis: dict, observed_services: set) -> dict:
    """Deterministic policy: map diagnosis onto a concrete allowlisted Action API call and check policy."""
    if diagnosis.get("escalate_to_human") or diagnosis.get("confidence") == "low":
        return {
            "allowed": False,
            "escalate": True,
            "reason": "Diagnosis confidence is low or escalation was requested by agent.",
        }

    remedy_text = str(diagnosis.get("suggested_remedy", "")).lower()
    comp = str(diagnosis.get("failing_component", "")).strip()
    fault_class = str(diagnosis.get("fault_class", "unknown")).strip()
    cause_text = str(diagnosis.get("cause", "")).lower()

    # Map natural language remedy type to canonical allowlisted action_type
    action_type = None
    if "toggle" in remedy_text or "flag" in remedy_text:
        action_type = "toggle_feature_flag"
    elif "throttle" in remedy_text or "load" in remedy_text:
        action_type = "throttle_load_generator"
    elif "restart" in remedy_text:
        action_type = "restart_service"
    elif "scale" in remedy_text:
        action_type = "scale_service"

    if not action_type or action_type not in ALLOWED_ACTIONS:
        return {
            "allowed": False,
            "escalate": True,
            "reason": f"Proposed remedy '{diagnosis.get('suggested_remedy')}' is not in the Action API allowlist.",
        }

    # Check that target component was actually observed in this incident's telemetry
    if comp not in ALLOWED_SERVICES:
        return {
            "allowed": False,
            "escalate": True,
            "reason": f"Failing component '{comp}' is not an allowlisted service.",
        }
    if observed_services and comp not in observed_services and action_type != "throttle_load_generator":
        return {
            "allowed": False,
            "escalate": True,
            "reason": f"Policy rejected action: target service '{comp}' was never observed in tool telemetry.",
        }

    params = {}
    rollback = None

    if action_type == "toggle_feature_flag":
        # Infer flag name from explicit mention or deterministic (service, fault_class) table
        flag_name = diagnosis.get("target_flag")
        if not flag_name:
            for candidate in ALLOWED_FLAGS:
                if candidate.lower() in cause_text:
                    flag_name = candidate
                    break
        if not flag_name:
            if comp == "ad" and "gc" in cause_text:
                flag_name = "adManualGc"
            elif comp == "payment" and ("unreachable" in cause_text or "refused" in cause_text):
                flag_name = "paymentUnreachable"
            else:
                flag_name = SERVICE_TO_FAULT_FLAG.get((comp, fault_class))
        if not flag_name or flag_name not in ALLOWED_FLAGS:
            return {
                "allowed": False,
                "escalate": True,
                "reason": f"Could not deterministically map ({comp}, {fault_class}) to an allowlisted feature flag.",
            }
        params = {"flag_name": flag_name, "variant": "off", "service": comp}
        rollback = {
            "reversible": True,
            "description": f"Restore feature flag '{flag_name}' to its previous variant if verification fails.",
        }

    elif action_type == "restart_service":
        reset_limits = fault_class in ("resource_starvation", "cpu_saturation") or "limit" in cause_text or "starv" in cause_text
        params = {"service_name": comp, "reset_limits": reset_limits}
        rollback = {
            "reversible": False,
            "description": "Service restart has no natural inverse; if verification fails, escalate to human.",
        }

    elif action_type == "throttle_load_generator":
        params = {"user_count": 5, "spawn_rate": 1, "disable_flood_flag": True}
        rollback = {
            "reversible": True,
            "description": "Restore Locust user_count to pre-action value.",
        }

    elif action_type == "scale_service":
        # Section 12 of Architecture v2: Docker Compose environment does not support K8s HorizontalPodAutoscaler,
        # unless resetting container resource limits via recreate.
        if fault_class in ("resource_starvation", "cpu_saturation"):
            action_type = "restart_service"
            params = {"service_name": comp, "reset_limits": True}
            rollback = {
                "reversible": False,
                "description": "Recreating container to clear CPU/memory starvation limits; escalate if unrecovered.",
            }
        else:
            return {
                "allowed": False,
                "escalate": True,
                "reason": "scale_service is Kubernetes-only and not supported on local Docker Compose.",
            }

    plan = {
        "allowed": True,
        "escalate": False,
        "incident_id": incident_id,
        "proposal_version": 1,
        "action_type": action_type,
        "target": comp,
        "parameters": params,
        "reason": diagnosis.get("cause", ""),
        "rollback": rollback,
    }
    plan["approval_digest"] = compute_approval_digest(plan)
    return plan


def compute_approval_digest(plan: dict) -> str:
    canonical = json.dumps(
        {
            "incident_id": plan.get("incident_id"),
            "proposal_version": plan.get("proposal_version", 1),
            "action_type": plan.get("action_type"),
            "target": plan.get("target"),
            "parameters": plan.get("parameters"),
            "rollback": plan.get("rollback"),
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


# ---------- Interactive Human Approval Gate ----------
def request_human_approval(diagnosis: dict, plan: dict, dry_run: bool = False, auto_mode: str | None = None) -> dict:
    """Show diagnosis, evidence, and exact Action API plan to human and wait for explicit 'yes'."""
    if is_kill_switch_active():
        log_audit("approval_blocked_by_kill_switch", {"incident_id": plan.get("incident_id")})
        return {"approved": False, "status": "kill_switch_active", "reason": "Kill switch is ON"}

    print("\n" + "=" * 78)
    print("  AI ON-CALL ENGINEER — HUMAN APPROVAL GATE")
    print("=" * 78)
    print(f"  Incident ID       : {plan.get('incident_id')}")
    print(f"  Failing Component : {diagnosis.get('failing_component')} ({diagnosis.get('fault_class')})")
    print(f"  Confidence        : {diagnosis.get('confidence')}")
    print(f"  Root Cause        : {diagnosis.get('cause')}")
    print("  Grounded Evidence :")
    for ev in diagnosis.get("evidence", []):
        print(f"    - {ev}")
    if diagnosis.get("secondary_findings"):
        print("  Secondary Findings:")
        for sf in diagnosis["secondary_findings"]:
            print(f"    - {sf}")
    print("-" * 78)
    print(f"  Proposed Action   : {plan['action_type']}")
    print(f"  Target            : {plan['target']}")
    print(f"  Parameters        : {json.dumps(plan['parameters'])}")
    print(f"  Rollback Policy   : {plan['rollback']['description']}")
    print(f"  Approval Digest   : {plan['approval_digest']} (SHA-256 bound to exact plan)")
    if dry_run:
        print("  Mode              : DRY-RUN (No actual changes will be made)")
    print("=" * 78)

    log_audit("approval_requested", {"incident_id": plan["incident_id"], "plan": plan, "dry_run": dry_run})

    if auto_mode in ("yes", "no", "dry-run"):
        choice = auto_mode
        print(f"  [Non-interactive decision supplied: {choice}]")
    else:
        try:
            choice = input("  Approve execution of this action? Type 'yes', 'dry-run', or 'no': ").strip().lower()
        except EOFError:
            choice = "no"

    if choice == "dry-run":
        dry_run = True
        choice = "yes"

    approved = choice == "yes"
    decision = {
        "approved": approved,
        "dry_run": dry_run,
        "decided_at": _now(),
        "approval_digest": plan["approval_digest"],
        "consumed": False,
        "operator_input": choice,
    }
    log_audit("approval_decision", {"incident_id": plan["incident_id"], **decision})
    return decision


# ---------- Action API Executor ----------
def execute_action(plan: dict, approval: dict) -> dict:
    """Execute the approved plan ONLY if kill switch is off, digest matches, and approval is unconsumed."""
    if is_kill_switch_active():
        log_audit("execution_aborted_kill_switch", {"incident_id": plan.get("incident_id")})
        return {"executed": False, "status": "aborted_kill_switch", "detail": "Kill switch is ON; refusing Action API call."}

    if not approval.get("approved"):
        return {"executed": False, "status": "rejected_by_human", "detail": "Human did not approve the action."}

    if approval.get("consumed"):
        return {"executed": False, "status": "replay_blocked", "detail": "Approval token was already consumed."}

    recomputed_digest = compute_approval_digest(plan)
    if approval.get("approval_digest") != recomputed_digest:
        return {"executed": False, "status": "digest_mismatch", "detail": "Plan changed after approval; voiding approval."}

    # Consume single-use approval token
    approval["consumed"] = True

    action_type = plan["action_type"]
    params = plan["parameters"]

    if approval.get("dry_run"):
        msg = f"WOULD CALL ActionAPI.{action_type}({json.dumps(params)})"
        print(f"\n[DRY-RUN] {msg}")
        res = {"executed": False, "dry_run": True, "status": "simulated", "detail": msg}
        log_audit("action_dry_run", {"incident_id": plan["incident_id"], **res})
        return res

    print(f"\n[EXECUTOR] Executing ActionAPI.{action_type}({json.dumps(params)})...")
    try:
        if action_type == "restart_service":
            svc = params["service_name"]
            if params.get("reset_limits"):
                cmd = COMPOSE + ["up", "-d", "--force-recreate", "--no-deps", svc]
            else:
                cmd = COMPOSE + ["up", "-d", "--no-deps", svc]
                subprocess.run(cmd, cwd=str(DEMO_DIR), check=True, capture_output=True, text=True)
                cmd = COMPOSE + ["restart", svc]
            subprocess.run(cmd, cwd=str(DEMO_DIR), check=True, capture_output=True, text=True)
            res = {"executed": True, "status": "success", "action_type": action_type, "detail": f"Restarted service {svc}"}

        elif action_type == "toggle_feature_flag":
            flag_name = params["flag_name"]
            variant = params.get("variant", "off")
            prev_variant = _set_flag_via_action_api(flag_name, variant)
            res = {
                "executed": True,
                "status": "success",
                "action_type": action_type,
                "previous_variant": prev_variant,
                "detail": f"Toggled feature flag {flag_name} -> {variant} (was {prev_variant})",
            }

        elif action_type == "throttle_load_generator":
            users = int(params.get("user_count", 5))
            spawn_rate = int(params.get("spawn_rate", 1))
            if params.get("disable_flood_flag"):
                try:
                    _set_flag_via_action_api("loadGeneratorFloodHomepage", "off")
                except Exception:
                    pass
            try:
                requests.post(
                    f"{LOCUST_API}/swarm",
                    data={"user_count": users, "spawn_rate": spawn_rate},
                    timeout=5,
                )
            except Exception:
                pass
            res = {
                "executed": True,
                "status": "success",
                "action_type": action_type,
                "detail": f"Throttled load-generator to user_count={users}, spawn_rate={spawn_rate}",
            }

        else:
            res = {"executed": False, "status": "unsupported_action", "detail": f"Action {action_type} not supported"}

    except Exception as e:
        res = {"executed": False, "status": "execution_error", "detail": f"{type(e).__name__}: {e}"}

    log_audit("action_executed", {"incident_id": plan["incident_id"], **res})
    return res


def _set_flag_via_action_api(flag_name: str, variant: str) -> str:
    """Action API adapter for toggling a specific flag without exposing flagd state to the LLM."""
    flag_file = DEMO_DIR / "src" / "flagd" / "demo.flagd.json"
    data = json.loads(flag_file.read_text(encoding="utf-8"))
    if flag_name not in data.get("flags", {}):
        raise ValueError(f"Flag {flag_name} not found")
    prev = data["flags"][flag_name].get("defaultVariant", "off")
    data["flags"][flag_name]["defaultVariant"] = variant
    with open(flag_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    try:
        requests.post(f"{FLAGD_UI_API}/write", json={"data": data}, timeout=3)
    except Exception:
        pass
    try:
        subprocess.run(COMPOSE + ["restart", "flagd"], cwd=str(DEMO_DIR), check=False, capture_output=True)
    except Exception:
        pass
    return prev


def rollback_action(plan: dict, exec_result: dict) -> dict:
    """Execute natural inverse if verification fails and rollback is reversible."""
    if not plan.get("rollback", {}).get("reversible"):
        return {"rolled_back": False, "reason": "Action is not naturally reversible; escalating to human."}
    action_type = plan["action_type"]
    params = plan["parameters"]
    prev = exec_result.get("previous_variant")
    if action_type == "toggle_feature_flag" and prev:
        _set_flag_via_action_api(params["flag_name"], prev)
        out = {"rolled_back": True, "detail": f"Reverted {params['flag_name']} back to {prev}"}
        log_audit("action_rolled_back", {"incident_id": plan["incident_id"], **out})
        return out
    return {"rolled_back": False, "reason": "No rollback handler applicable."}


# ---------- Post-Action Recovery Verifier ----------
def verify_recovery(target_service: str, settle_seconds: int = 15, samples: int = 2) -> dict:
    """Wait settle period, then check fresh telemetry across consecutive samples."""
    print(f"\n[VERIFIER] Waiting {settle_seconds}s settle window before checking recovery of '{target_service}'...")
    time.sleep(max(1, settle_seconds))

    passing = 0
    checks = []
    for i in range(samples):
        if is_kill_switch_active():
            return {"verified": False, "status": "aborted_kill_switch", "checks": checks}
        scan = ops_tools.triage(window_min=2)
        svc_anomalies = [a for a in scan.get("anomalies", []) if a.get("service") == target_service]
        not_running = [
            c for c in scan.get("containers", {}).get("not_running", []) if c.get("service") == target_service
        ]
        cpu_lim = [
            c for c in scan.get("containers", {}).get("cpu_limited", []) if c.get("service") == target_service
        ]
        sample_ok = not svc_anomalies and not not_running and not cpu_lim
        checks.append({
            "sample": i + 1,
            "timestamp": _now(),
            "passed": sample_ok,
            "remaining_service_anomalies": svc_anomalies,
            "not_running": not_running,
        })
        if sample_ok:
            passing += 1
        if i + 1 < samples:
            time.sleep(5)

    verified = passing == samples
    result = {
        "verified": verified,
        "status": "Resolved" if verified else "Failed_Verification_Escalated",
        "target_service": target_service,
        "passing_samples": passing,
        "required_samples": samples,
        "checks": checks,
    }
    log_audit("recovery_verified", result)
    return result


# ---------- Incident Report Builder ----------
def write_incident_report(
    incident_id: str,
    alert: str,
    started_at: str,
    diagnosis: dict,
    plan: dict | None,
    approval: dict | None,
    execution: dict | None,
    verification: dict | None,
    observations: list,
) -> dict:
    """Write both JSON report and readable Markdown postmortem."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    finished_at = _now()

    final_status = "Escalated"
    if approval and approval.get("dry_run"):
        final_status = "Simulated"
    elif verification and verification.get("verified"):
        final_status = "Resolved"
    elif approval and not approval.get("approved"):
        final_status = "Rejected"

    prevention_map = {
        "app_error": "Add automated canary checks and expiration TTLs on synthetic fault flags before production rollout.",
        "partial_failure": "Add input-specific regression tests and per-attribute error-rate alerts on catalog/cart operations.",
        "dependency_down": "Configure container restart policies, readiness probes, and circuit breakers with fallback handling.",
        "container_crash_or_restart": "Set memory alerts at 80% of container limit and enforce healthcheck liveness probes.",
        "memory_leak": "Bound in-memory cache size with an LRU eviction policy and alert on monotonic heap growth.",
        "cpu_saturation": "Configure CPU request/limit guardrails and profile GC pause durations under load.",
        "traffic_flood": "Configure Envoy rate-limiting filters at frontend-proxy to shed excess load gracefully.",
        "resource_starvation": "Enforce minimum CPU/memory resource reservations in deployment manifests.",
    }
    prevention = prevention_map.get(
        diagnosis.get("fault_class", "unknown"),
        "Add targeted service-level alerts and runbook automation for this failure mode.",
    )

    report = {
        "incident_id": incident_id,
        "status": final_status,
        "alert": alert,
        "timeline": {
            "detected_at": started_at,
            "completed_at": finished_at,
            "tool_calls_count": len(observations),
        },
        "diagnosis": diagnosis,
        "action_plan": plan,
        "human_approval": approval,
        "execution": execution,
        "verification": verification,
        "prevention_recommendation": prevention,
    }

    json_path = REPORTS_DIR / f"{incident_id}.json"
    md_path = REPORTS_DIR / f"{incident_id}.md"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    md_lines = [
        f"# Incident Report: `{incident_id}`",
        "",
        f"- **Final Status**: `{final_status}`",
        f"- **Detected At**: `{started_at}`",
        f"- **Completed At**: `{finished_at}`",
        f"- **Trigger Alert**: {alert}",
        "",
        "## 1. Diagnosis & Root Cause",
        f"- **Failing Component**: `{diagnosis.get('failing_component')}`",
        f"- **Fault Class**: `{diagnosis.get('fault_class')}`",
        f"- **Confidence**: `{diagnosis.get('confidence')}`",
        f"- **Root Cause**: {diagnosis.get('cause')}",
        f"- **Escalate to Human**: `{diagnosis.get('escalate_to_human')}`",
        "",
        "## 2. Verifiable Evidence",
    ]
    for ev in diagnosis.get("evidence", []):
        md_lines.append(f"- {ev}")
    if not diagnosis.get("evidence"):
        md_lines.append("- *(No grounded evidence verified; escalated to human)*")

    md_lines += [
        "",
        "## 3. Investigation Timeline (Tool Calls)",
    ]
    for obs in observations:
        md_lines.append(f"- `{obs['timestamp']}` **{obs['tool']}**(`{json.dumps(obs['args'])}`)")

    md_lines += [
        "",
        "## 4. Remediation & Human Approval",
    ]
    if plan and plan.get("allowed"):
        md_lines.append(f"- **Proposed Action**: `{plan['action_type']}` on `{plan['target']}`")
        md_lines.append(f"- **Parameters**: `{json.dumps(plan['parameters'])}`")
        md_lines.append(f"- **Approval Digest**: `{plan['approval_digest']}`")
        md_lines.append(f"- **Human Decision**: `{approval.get('operator_input') if approval else 'N/A'}`")
        md_lines.append(f"- **Execution Outcome**: `{execution.get('detail') if execution else 'Not executed'}`")
    else:
        md_lines.append(f"- **Escalated without automated action**: {plan.get('reason') if plan else 'N/A'}")

    md_lines += [
        "",
        "## 5. Recovery Verification",
        f"- **Verified**: `{verification.get('verified') if verification else False}`",
        f"- **Status**: `{verification.get('status') if verification else 'Not run'}`",
        "",
        "## 6. Prevention Recommendation",
        f"- {prevention}",
        "",
    ]
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    report["report_files"] = {"json": str(json_path), "markdown": str(md_path)}
    return report


# ---------- Kill Switch CLI ----------
def main():
    p = argparse.ArgumentParser(description="Kill switch and Action API control CLI")
    sub = p.add_subparsers(dest="cmd", required=True)
    on_p = sub.add_parser("on", help="Activate the kill switch immediately")
    on_p.add_argument("--reason", default="Manual operator kill switch activation")
    sub.add_parser("off", help="Deactivate the kill switch")
    sub.add_parser("status", help="Check whether the kill switch is active")
    args = p.parse_args()

    if args.cmd == "on":
        print(json.dumps(set_kill_switch(True, args.reason), indent=2))
    elif args.cmd == "off":
        print(json.dumps(set_kill_switch(False), indent=2))
    elif args.cmd == "status":
        print(json.dumps({"kill_switch_active": is_kill_switch_active()}, indent=2))


if __name__ == "__main__":
    main()
