# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Our Action API: allowlist, remediation policy, human approval gate, kill switch, executor, verifier, reports.

The LLM never calls anything here. Deterministic code (this module) turns a diagnosis into ONE plan, a human
approves that exact plan, and only then does execute_action() reach remediation_adapters.py.

Guarantees (each is unit-tested in tests/test_offline.py):
  * only four allowlisted action types, each with strict parameter validation
  * approval is bound to the SHA-256 digest of (incident, version, action, target, params, rollback);
    single-use, expires after APPROVAL_TTL_S, voided if the plan changes
  * no auto-approval path: a human must type "yes" (or "dry-run") at the prompt
  * kill switch (file KILL_SWITCH or env KILL_SWITCH=1) halts investigation, approval, execution, rollback
  * dry-run prints WOULD CALL and changes nothing
  * blast-radius limits: protected services, max executed actions per hour
  * every step appended to logs/audit.jsonl
  * recovery is verified on fresh telemetry (consecutive samples) and a failed verification is escalated
"""
import argparse
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

import ops_tools
import remediation_adapters as adapters

AGENT_DIR = Path(__file__).resolve().parent
KILL_SWITCH_FILE = AGENT_DIR / "KILL_SWITCH"
LOGS_DIR = AGENT_DIR / "logs"
REPORTS_DIR = AGENT_DIR / "reports"
AUDIT_LOG_FILE = LOGS_DIR / "audit.jsonl"

APPROVAL_TTL_S = int(os.environ.get("APPROVAL_TTL_S", "600"))
MAX_ACTIONS_PER_HOUR = int(os.environ.get("MAX_ACTIONS_PER_HOUR", "3"))

ALLOWED_ACTIONS = {"restart_service", "toggle_feature_flag", "throttle_load_generator", "scale_service"}

ALLOWED_SERVICES = {
    "ad", "accounting", "astronomy-db", "cart", "checkout", "currency", "email", "fraud-detection",
    "frontend", "frontend-proxy", "image-provider", "kafka", "load-generator", "payment",
    "product-catalog", "quote", "recommendation", "shipping", "valkey-cart",
}
# Restarting these drops access to the whole demo (and to our own telemetry UIs): escalate instead.
PROTECTED_FROM_RESTART = {"frontend-proxy"}

# Static runbook: which remediation switch undoes which fault. Used ONLY to build the post-diagnosis fix;
# the agent never reads switch state to diagnose.
ALLOWED_FLAGS = {
    "adFailure", "adHighCpu", "adManualGc", "cartFailure", "emailMemoryLeak", "failedReadinessProbe",
    "imageSlowLoad", "kafkaQueueProblems", "loadGeneratorFloodHomepage", "paymentFailure",
    "paymentUnreachable", "productCatalogFailure", "recommendationCacheFailure",
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
# Fault classes caused by an application-level fault switch: a restart cannot clear these, the switch must be turned off.
SWITCH_FIXABLE = {"app_error", "partial_failure", "traffic_flood", "memory_leak", "cpu_saturation", "dependency_down"}
# "restart" is checked before the others so "restart the load generator" is not mistaken for throttling.
REMEDY_KEYWORDS = [
    ("restart", "restart_service"),
    ("toggle", "toggle_feature_flag"),
    ("flag", "toggle_feature_flag"),
    ("throttle", "throttle_load_generator"),
    ("scale", "scale_service"),
]


# ------------------------------------------------------------------ kill switch + audit
def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def is_kill_switch_active() -> bool:
    if os.environ.get("KILL_SWITCH", "").lower() in ("1", "true", "on"):
        return True
    return KILL_SWITCH_FILE.exists()


def log_audit(event: str, payload: dict) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": _now(), "ts_epoch": time.time(), "event": event, **payload}
    with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")


def set_kill_switch(active: bool, reason: str = "operator command") -> dict:
    if active:
        KILL_SWITCH_FILE.write_text(json.dumps({"activated_at": _now(), "reason": reason}) + "\n", encoding="utf-8")
        log_audit("kill_switch_on", {"reason": reason})
        return {"kill_switch": "ON", "file": str(KILL_SWITCH_FILE)}
    KILL_SWITCH_FILE.unlink(missing_ok=True)
    log_audit("kill_switch_off", {"reason": reason})
    return {"kill_switch": "OFF"}


# ------------------------------------------------------------------ parameter validation
def validate_params(action_type: str, p: dict) -> None:
    """Raise ValueError if the parameters are outside the allowlist. Runs again at execution time."""
    if action_type not in ALLOWED_ACTIONS:
        raise ValueError(f"action {action_type!r} is not allowlisted")
    if action_type == "restart_service":
        if p.get("service_name") not in ALLOWED_SERVICES:
            raise ValueError("service_name not allowlisted")
        if p["service_name"] in PROTECTED_FROM_RESTART:
            raise ValueError(f"{p['service_name']} is protected from automated restart")
        if not isinstance(p.get("reset_limits", False), bool):
            raise ValueError("reset_limits must be boolean")
    elif action_type == "toggle_feature_flag":
        if p.get("flag_name") not in ALLOWED_FLAGS:
            raise ValueError("flag_name not allowlisted")
        if p.get("variant") != "off":
            raise ValueError("automated flag changes may only set variant 'off'")
    elif action_type == "throttle_load_generator":
        if not (isinstance(p.get("user_count"), int) and 1 <= p["user_count"] <= 50):
            raise ValueError("user_count must be an integer 1..50")
        if not (isinstance(p.get("spawn_rate"), int) and 1 <= p["spawn_rate"] <= 10):
            raise ValueError("spawn_rate must be an integer 1..10")
    elif action_type == "scale_service":
        raise ValueError("scale_service is not supported on local Docker Compose")


# ------------------------------------------------------------------ remediation policy
def _escalate(incident_id, reason):
    return {"allowed": False, "escalate": True, "incident_id": incident_id, "reason": reason}


def build_action_plan(incident_id: str, diagnosis: dict, observed_services: set, down_services=frozenset()) -> dict:
    """Deterministic policy: map the diagnosis onto one concrete allowlisted action, or escalate.

    The LLM's suggested remedy is only a hint. The runbook decides: a container that is actually down is
    restarted; an application-level fault with a known remediation switch gets that switch turned off
    (a restart cannot clear it). Any override is recorded in plan["policy_note"] and shown to the human."""
    if diagnosis.get("escalate_to_human") or diagnosis.get("confidence") == "low":
        return _escalate(incident_id, "Diagnosis confidence is low or escalation was requested by the agent.")

    remedy = str(diagnosis.get("suggested_remedy", "")).lower()
    comp = str(diagnosis.get("failing_component", "")).strip()
    fault_class = str(diagnosis.get("fault_class", "unknown")).strip()
    cause = str(diagnosis.get("cause", "")).lower()

    action_type = next((a for kw, a in REMEDY_KEYWORDS if kw in remedy), None)
    if action_type not in ALLOWED_ACTIONS:
        return _escalate(incident_id, f"Proposed remedy {diagnosis.get('suggested_remedy')!r} is not in the Action API allowlist.")
    if comp not in ALLOWED_SERVICES:
        return _escalate(incident_id, f"Failing component {comp!r} is not an allowlisted service.")
    if observed_services and comp not in observed_services and action_type != "throttle_load_generator":
        return _escalate(incident_id, f"Policy rejected action: target service {comp!r} was never observed in tool telemetry.")

    policy_note = None
    if comp in down_services:
        preferred = "restart_service"          # the container is down: a switch cannot help
    elif fault_class in SWITCH_FIXABLE and (comp, fault_class) in SERVICE_TO_FAULT_FLAG:
        preferred = "toggle_feature_flag"      # app-level fault: restarting would not clear it
    else:
        preferred = action_type
    if preferred != action_type and action_type != "throttle_load_generator":
        policy_note = f"Runbook override: agent suggested {action_type}, policy chose {preferred} for ({comp}, {fault_class})."
        action_type = preferred

    params, rollback = {}, None
    if action_type == "toggle_feature_flag":
        flag = diagnosis.get("target_flag")
        if flag not in ALLOWED_FLAGS:
            flag = next((c for c in ALLOWED_FLAGS if c.lower() in cause), None)
        if not flag:
            if comp == "ad" and "gc" in cause:
                flag = "adManualGc"
            elif comp == "payment" and ("unreachable" in cause or "refused" in cause):
                flag = "paymentUnreachable"
            else:
                flag = SERVICE_TO_FAULT_FLAG.get((comp, fault_class))
        if flag not in ALLOWED_FLAGS:
            return _escalate(incident_id, f"Could not deterministically map ({comp}, {fault_class}) to an allowlisted remediation switch.")
        params = {"flag_name": flag, "variant": "off", "service": comp}
        rollback = {"reversible": True, "description": f"Restore '{flag}' to its previous variant if verification fails."}

    elif action_type == "restart_service":
        reset = fault_class == "resource_starvation" or "limit" in cause or "starv" in cause
        params = {"service_name": comp, "reset_limits": reset}
        rollback = {"reversible": False, "description": "A restart has no natural inverse; if verification fails, escalate to a human."}

    elif action_type == "throttle_load_generator":
        if fault_class != "traffic_flood":
            return _escalate(incident_id, "Throttling is only allowed for traffic_flood faults.")
        params = {"user_count": 5, "spawn_rate": 1}
        rollback = {"reversible": True, "description": "Restore the previous Locust user count."}

    elif action_type == "scale_service":
        if fault_class in ("resource_starvation", "cpu_saturation"):
            action_type = "restart_service"
            params = {"service_name": comp, "reset_limits": True}
            rollback = {"reversible": False, "description": "Recreating the container clears CPU/memory limits; escalate if unrecovered."}
        else:
            return _escalate(incident_id, "scale_service is not supported on local Docker Compose.")

    try:
        validate_params(action_type, params)
    except ValueError as e:
        return _escalate(incident_id, f"Policy rejected action: {e}")

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
        "policy_note": policy_note,
    }
    plan["approval_digest"] = compute_approval_digest(plan)
    return plan


def compute_approval_digest(plan: dict) -> str:
    canonical = json.dumps(
        {k: plan.get(k) for k in ("incident_id", "proposal_version", "action_type", "target", "parameters", "rollback")},
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ human approval gate
def request_human_approval(diagnosis: dict, plan: dict, dry_run: bool = False) -> dict:
    """Show diagnosis, evidence and the exact call; a human must type 'yes' or 'dry-run'. No auto mode."""
    if is_kill_switch_active():
        log_audit("approval_blocked_by_kill_switch", {"incident_id": plan.get("incident_id")})
        return {"approved": False, "status": "kill_switch_active", "reason": "Kill switch is ON"}

    print("\n" + "=" * 78)
    print("  AI ON-CALL ENGINEER - HUMAN APPROVAL GATE")
    print("=" * 78)
    print(f"  Incident ID       : {plan.get('incident_id')}")
    print(f"  Failing Component : {diagnosis.get('failing_component')} ({diagnosis.get('fault_class')})")
    print(f"  Confidence        : {diagnosis.get('confidence')}")
    print(f"  Root Cause        : {diagnosis.get('cause')}")
    print("  Grounded Evidence :")
    for ev in diagnosis.get("evidence", []):
        print(f"    - {ev}")
    for sf in diagnosis.get("secondary_findings", []) or []:
        print(f"  Secondary finding : {sf}")
    print("-" * 78)
    print(f"  Proposed Action   : {plan['action_type']}")
    print(f"  Target            : {plan['target']}")
    print(f"  Parameters        : {json.dumps(plan['parameters'])}")
    print(f"  Rollback Policy   : {plan['rollback']['description']}")
    if plan.get("policy_note"):
        print(f"  Policy Note       : {plan['policy_note']}")
    print(f"  Approval Digest   : {plan['approval_digest'][:16]}... (SHA-256 of this exact plan)")
    if dry_run:
        print("  Mode              : DRY-RUN (nothing will be changed)")
    print("=" * 78)
    log_audit("approval_requested", {"incident_id": plan["incident_id"], "plan": plan, "dry_run": dry_run})

    try:
        choice = input("  Approve execution? Type 'yes', 'dry-run' or 'no': ").strip().lower()
    except EOFError:
        choice = "no"
    if choice == "dry-run":
        dry_run, choice = True, "yes"
    decision = {
        "approved": choice == "yes",
        "dry_run": dry_run,
        "decided_at": _now(),
        "decided_epoch": time.time(),
        "approval_digest": plan["approval_digest"],
        "consumed": False,
        "operator_input": choice,
    }
    log_audit("approval_decision", {"incident_id": plan["incident_id"], **decision})
    return decision


# ------------------------------------------------------------------ executor
def _executed_last_hour() -> int:
    if not AUDIT_LOG_FILE.exists():
        return 0
    cutoff, n = time.time() - 3600, 0
    for line in AUDIT_LOG_FILE.read_text(encoding="utf-8").splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("event") == "action_executed" and e.get("executed") and e.get("ts_epoch", 0) >= cutoff:
            n += 1
    return n


def execute_action(plan: dict, approval: dict) -> dict:
    """Run the approved plan ONLY if every gate passes. This is the single door to remediation_adapters."""
    iid = plan.get("incident_id")

    def refuse(status, detail):
        log_audit("execution_refused", {"incident_id": iid, "status": status, "detail": detail})
        return {"executed": False, "status": status, "detail": detail}

    if is_kill_switch_active():
        return refuse("aborted_kill_switch", "Kill switch is ON; refusing to act.")
    if not approval.get("approved"):
        return refuse("rejected_by_human", "Human did not approve the action.")
    if approval.get("consumed"):
        return refuse("replay_blocked", "Approval token was already used.")
    if time.time() - approval.get("decided_epoch", 0) > APPROVAL_TTL_S:
        return refuse("approval_expired", f"Approval is older than {APPROVAL_TTL_S}s; request a new one.")
    if not hmac.compare_digest(str(approval.get("approval_digest", "")), compute_approval_digest(plan)):
        return refuse("digest_mismatch", "Plan changed after approval; approval voided.")
    try:
        validate_params(plan["action_type"], plan["parameters"])
    except ValueError as e:
        return refuse("policy_violation", str(e))
    if not approval.get("dry_run") and _executed_last_hour() >= MAX_ACTIONS_PER_HOUR:
        return refuse("circuit_breaker_open", f"{MAX_ACTIONS_PER_HOUR} actions already executed in the last hour; escalate.")

    approval["consumed"] = True
    action_type, p = plan["action_type"], plan["parameters"]

    if approval.get("dry_run"):
        msg = f"WOULD CALL ActionAPI.{action_type}({json.dumps(p)})"
        print(f"\n[DRY-RUN] {msg}")
        res = {"executed": False, "dry_run": True, "status": "simulated", "detail": msg}
        log_audit("action_dry_run", {"incident_id": iid, **res})
        return res

    print(f"\n[EXECUTOR] ActionAPI.{action_type}({json.dumps(p)})")
    try:
        if action_type == "restart_service":
            detail = adapters.restart_service(p["service_name"], p.get("reset_limits", False))
            res = {"executed": True, "status": "success", "action_type": action_type, "detail": detail}
        elif action_type == "toggle_feature_flag":
            prev = adapters.set_flag(p["flag_name"], p["variant"])
            res = {"executed": True, "status": "success", "action_type": action_type, "previous_variant": prev,
                   "detail": f"Set {p['flag_name']} -> {p['variant']} (was {prev})"}
        elif action_type == "throttle_load_generator":
            prev = adapters.throttle_load(p["user_count"], p["spawn_rate"])
            res = {"executed": True, "status": "success", "action_type": action_type, "previous_user_count": prev,
                   "detail": f"Throttled load generator to {p['user_count']} users (was {prev})"}
        else:
            res = {"executed": False, "status": "unsupported_action", "detail": f"{action_type} is not supported"}
    except Exception as e:  # noqa: BLE001
        res = {"executed": False, "status": "execution_error", "detail": f"{type(e).__name__}: {e}"}
    log_audit("action_executed", {"incident_id": iid, **res})
    return res


def rollback_action(plan: dict, exec_result: dict) -> dict:
    """Undo our own change when verification fails (covered by the same approval). Never while the kill switch is on."""
    if is_kill_switch_active():
        return {"rolled_back": False, "reason": "Kill switch is ON; no further changes."}
    if not (plan.get("rollback") or {}).get("reversible"):
        return {"rolled_back": False, "reason": "Action is not naturally reversible; escalating to a human."}
    p = plan["parameters"]
    try:
        if plan["action_type"] == "toggle_feature_flag" and exec_result.get("previous_variant"):
            adapters.set_flag(p["flag_name"], exec_result["previous_variant"])
            out = {"rolled_back": True, "detail": f"Restored {p['flag_name']} to {exec_result['previous_variant']}"}
        elif plan["action_type"] == "throttle_load_generator" and exec_result.get("previous_user_count"):
            adapters.throttle_load(int(exec_result["previous_user_count"]), 5)
            out = {"rolled_back": True, "detail": f"Restored load generator to {exec_result['previous_user_count']} users"}
        else:
            return {"rolled_back": False, "reason": "No rollback handler applicable."}
    except Exception as e:  # noqa: BLE001
        return {"rolled_back": False, "reason": f"Rollback failed: {type(e).__name__}: {e}"}
    log_audit("action_rolled_back", {"incident_id": plan["incident_id"], **out})
    return out


# ------------------------------------------------------------------ recovery verifier
FAIL_TYPES = {"error_rate", "operation_error_rate", "traffic_drop_or_service_gone"}


def verify_recovery(target_service: str, settle_seconds: int = 75, samples: int = 2, spacing_seconds: int = 20) -> dict:
    """Wait for the old errors to leave the 1-minute window, then require `samples` consecutive clean scans of
    the target and its callers. A scan that cannot read telemetry counts as a FAILED sample, never a pass."""
    print(f"\n[VERIFIER] Waiting {settle_seconds}s for fresh telemetry before checking '{target_service}'...")
    time.sleep(max(1, settle_seconds))
    watch = {target_service} | set(ops_tools.topology(target_service)["called_by"])
    checks, passing = [], 0
    for i in range(samples):
        if is_kill_switch_active():
            return {"verified": False, "status": "aborted_kill_switch", "checks": checks}
        scan = ops_tools.triage(window_min=1)
        blind = [n for n in scan.get("notes", []) if "failed" in n]
        left = [
            a for a in scan.get("anomalies", [])
            if (a.get("service") == target_service) or (a.get("service") in watch and a.get("type") in FAIL_TYPES)
        ]
        down = [c for c in scan.get("containers", {}).get("not_running", []) if c.get("service") == target_service]
        ok = not blind and not left and not down
        checks.append({"sample": i + 1, "timestamp": _now(), "passed": ok, "blind": blind,
                       "remaining_anomalies": left, "not_running": down})
        passing += ok
        if i + 1 < samples:
            time.sleep(spacing_seconds)
    verified = passing == samples
    result = {
        "verified": verified,
        "status": "Resolved" if verified else "Failed_Verification_Escalated",
        "target_service": target_service,
        "watched_services": sorted(watch),
        "passing_samples": passing,
        "required_samples": samples,
        "checks": checks,
    }
    log_audit("recovery_verified", result)
    return result


# ------------------------------------------------------------------ incident report
PREVENTION = {
    "app_error": "Add canary checks and automatic rollback for faulty releases; alert on per-operation error rate.",
    "partial_failure": "Add input-specific regression tests and per-attribute error-rate alerts on catalog/cart operations.",
    "dependency_down": "Set restart policies, readiness probes and circuit breakers with fallbacks for critical dependencies.",
    "container_crash_or_restart": "Alert at 80% of the memory limit and enforce liveness/readiness probes.",
    "memory_leak": "Bound in-memory caches (LRU) and alert on monotonic heap growth.",
    "cpu_saturation": "Set CPU request/limit guardrails and profile GC pauses under load.",
    "traffic_flood": "Add rate limiting at the edge proxy to shed excess load gracefully.",
    "network_degradation": "Add timeouts, retries with budgets and per-edge latency SLO alerts.",
    "resource_starvation": "Reserve minimum CPU/memory per service and alert on throttling.",
}


def _final_status(plan, approval, execution, verification):
    if not plan or not plan.get("allowed"):
        return "Escalated"
    if approval and approval.get("status") == "kill_switch_active":
        return "Halted_Kill_Switch"
    if approval and not approval.get("approved"):
        return "Rejected"
    if approval and approval.get("dry_run"):
        return "Simulated"
    if execution and not execution.get("executed"):
        return "Failed_Escalated"
    if verification and verification.get("verified"):
        return "Resolved"
    return "Failed_Verification_Escalated"


def write_incident_report(incident_id, alert, started_at, diagnosis, plan, approval, execution, verification, observations) -> dict:
    """Write the machine-readable JSON report and a readable Markdown post-mortem."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    finished_at = _now()
    status = _final_status(plan, approval, execution, verification)
    prevention = PREVENTION.get(diagnosis.get("fault_class", "unknown"),
                                "Add targeted service-level alerts and runbook automation for this failure mode.")
    report = {
        "incident_id": incident_id,
        "status": status,
        "alert": alert,
        "timeline": {"detected_at": started_at, "completed_at": finished_at, "tool_calls_count": len(observations)},
        "diagnosis": diagnosis,
        "action_plan": plan,
        "human_approval": approval,
        "execution": execution,
        "verification": verification,
        "prevention_recommendation": prevention,
        "observations": observations,
    }
    json_path, md_path = REPORTS_DIR / f"{incident_id}.json", REPORTS_DIR / f"{incident_id}.md"
    json_path.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")

    md = [
        f"# Incident Report: `{incident_id}`", "",
        f"- **Final status**: `{status}`",
        f"- **Detected**: `{started_at}`   **Completed**: `{finished_at}`",
        f"- **Trigger**: {alert}", "",
        "## 1. Diagnosis",
        f"- **Failing component**: `{diagnosis.get('failing_component')}` (`{diagnosis.get('fault_class')}`)",
        f"- **Confidence**: `{diagnosis.get('confidence')}`   **Escalate**: `{diagnosis.get('escalate_to_human')}`",
        f"- **Cause**: {diagnosis.get('cause')}", "",
        "## 2. Evidence (grounded in tool output)",
    ]
    md += [f"- {e}" for e in diagnosis.get("evidence", [])] or ["- *(none verified; escalated)*"]
    for d in diagnosis.get("dropped_ungrounded_evidence", []):
        md.append(f"- ~~{d}~~ *(dropped: not found in tool output)*")
    for sf in diagnosis.get("secondary_findings", []) or []:
        md.append(f"- Secondary: {sf}")
    md += ["", "## 3. Investigation timeline"]
    md += [f"- `{o['timestamp']}` **{o['tool']}**(`{json.dumps(o['args'])}`) -> `{o['id']}`" for o in observations]
    md += ["", "## 4. Remediation and approval"]
    if plan and plan.get("allowed"):
        md += [
            f"- **Action**: `{plan['action_type']}` on `{plan['target']}`  params `{json.dumps(plan['parameters'])}`",
            f"- **Approval digest**: `{plan['approval_digest']}`",
            f"- **Human decision**: `{approval.get('operator_input') if approval else 'n/a'}`",
            f"- **Outcome**: {execution.get('detail') if execution else 'not executed'}",
        ]
    else:
        md.append(f"- Escalated without automated action: {plan.get('reason') if plan else 'n/a'}")
    md += ["", "## 5. Recovery verification",
           f"- **Verified**: `{verification.get('verified') if verification else False}`  "
           f"(`{verification.get('status') if verification else 'not run'}`)"]
    if verification and verification.get("rollback"):
        md.append(f"- **Rollback**: {json.dumps(verification['rollback'])}")
    md += ["", "## 6. Prevention", f"- {prevention}", ""]
    md_path.write_text("\n".join(md), encoding="utf-8")
    report["report_files"] = {"json": str(json_path), "markdown": str(md_path)}
    return report


# ------------------------------------------------------------------ CLI: kill switch
def main():
    p = argparse.ArgumentParser(description="Kill switch control")
    sub = p.add_subparsers(dest="cmd", required=True)
    on_p = sub.add_parser("on", help="Activate the kill switch")
    on_p.add_argument("--reason", default="Manual operator kill switch activation")
    sub.add_parser("off", help="Deactivate the kill switch")
    sub.add_parser("status", help="Show kill switch state")
    args = p.parse_args()
    if args.cmd == "on":
        print(json.dumps(set_kill_switch(True, args.reason), indent=2))
    elif args.cmd == "off":
        print(json.dumps(set_kill_switch(False), indent=2))
    else:
        print(json.dumps({"kill_switch_active": is_kill_switch_active()}, indent=2))


if __name__ == "__main__":
    main()
