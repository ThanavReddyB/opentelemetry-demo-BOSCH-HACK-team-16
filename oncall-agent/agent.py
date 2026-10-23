# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""On-call agent: alert -> tool-calling investigation -> grounded diagnosis JSON -> human approval -> Action API -> verify -> report.

Supports both:
  1. Diagnose-only mode (--diagnose-only): outputs strict grounded diagnosis JSON (Checkpoints 1 & 2).
  2. Full On-Call loop (default / --act): runs diagnosis -> policy check -> interactive Human Approval Gate
     -> Allowlisted Action API (or --dry-run) -> Recovery Verification -> Incident Report (Checkpoint 3 & 4).

Configured via oncall-agent/.env (GROQ_API_KEY / GROQ_MODEL, or OpenAI-compatible LLM_BASE_URL / API_KEY).
"""
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

import action_api
from registry import OBSERVATIONS, OBSERVED_SERVICES, TOOL_SPECS, call_tool, grounded, missing_signal_categories, reset_session

AGENT_DIR = Path(__file__).resolve().parent
load_dotenv(AGENT_DIR / ".env")
load_dotenv(AGENT_DIR / ".env.example")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def _build_llm_client():
    """Build Groq or OpenAI-compatible client from environment variables."""
    groq_key = os.environ.get("GROQ_API_KEY")
    if groq_key:
        from groq import Groq

        model = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
        return Groq(api_key=groq_key), model

    api_key = os.environ.get("API_KEY") or os.environ.get("OPENAI_API_KEY") or os.environ.get("XAI_API_KEY")
    base_url = os.environ.get("LLM_BASE_URL") or ("https://api.x.ai/v1" if os.environ.get("XAI_API_KEY") else None)
    model = os.environ.get("LLM_MODEL", "openai/gpt-oss-120b")
    if not api_key:
        sys.exit(
            "Error: No LLM API key found. Set GROQ_API_KEY in oncall-agent/.env "
            "(or API_KEY / LLM_BASE_URL in environment)."
        )
    from openai import OpenAI

    return OpenAI(api_key=api_key, base_url=base_url), model


SYSTEM = """You are an on-call SRE agent investigating a production incident in the OpenTelemetry Astronomy Shop.
Work only from tool results; cite only values/IDs/lines that tools returned, copied exactly. Never invent evidence.
Never ask for or look at feature-flag state.

Mandatory Method (You MUST query all 5 observability pillars before giving your final JSON)
1. METRICS & CONTAINERS: Call `triage` first (scans Prometheus RED metrics + container health across all services) and `container_health` if needed.
2. TRACES & TOPOLOGY: Call `error_hotspots` (and `trace_detail`, `attribute_skew`, or `edge_latency_gap`) on the alerting/suspect service to find the deepest root-cause span and exact trace_id. Call `topology` to verify upstream/downstream dependencies.
3. LOGS: Call `get_logs` on the suspect failing service (and caller if relevant) to capture exact error log lines.
4. DEPLOY HISTORY: Call `deploy_history` to check recent commits and remediation history.
5. Distinguish lookalike faults carefully:
   - If checkout fails calling payment AND payment has error spans/traffic -> payment app_error (paymentFailure).
   - If checkout fails connecting to payment AND payment receives zero traffic -> payment dependency_down / unreachable (paymentUnreachable).
   - If cart fails AND valkey-cart container is not_running -> valkey-cart container_crash_or_restart / dependency_down.
   - If cart fails on EmptyCart AND valkey-cart container IS running -> cart app_error (cartFailure).
   - If product-catalog fails AND astronomy-db container is not_running -> astronomy-db dependency_down.
   - If product-catalog fails only on one product ID (check `attribute_skew`) -> product-catalog partial_failure.
6. There may be more than one simultaneous fault. Keep going until every significant anomaly from triage is
   explained or dismissed as noise; report extra faults in secondary_findings.

Playbook (signature -> confirm with)
- app_error: one service/operation errors -> error_hotspots, trace_detail, get_logs.
- partial_failure: only some requests fail (one product/user) -> attribute_skew on the failing operation.
- dependency_down: callers show connection refused/unavailable; callee or its DB/cache/queue is down
  -> container_health (not_running), get_logs on caller, topology.
- container_crash_or_restart: restarts/OOM/exited, request rate dropped -> container_health, get_logs.
- memory_leak: latency or restarts creep up, no clear errors early -> list_metrics("memory"), then metric_trend
  over 30+ min for the suspect service (steady rise, monotonic_up_share near 1).
- cpu_saturation: container hot or cpu_limited, latency up, little erroring -> container_health, metric_trend on
  cpu/gc metrics (list_metrics("cpu"), list_metrics("gc")).
- traffic_flood: request rate surge at the entry service, latency up broadly, no specific error source
  -> triage traffic_surge, metric_query on rates.
- network_degradation: latency on one edge, callee's own time normal -> edge_latency_gap, then get_logs for
  timeouts/resets. Distinguish from a slow callee.
- resource_starvation: CPU/memory limits (cpu_limited in container_health), throttling, OOM -> container_health.
If evidence is thin, conflicting, or no hypothesis is confirmed, set confidence "low" and escalate_to_human true.

Final answer: ONLY a JSON object:
{"fault_class": one of ["app_error", "partial_failure", "dependency_down", "container_crash_or_restart", "memory_leak",
  "cpu_saturation", "traffic_flood", "network_degradation", "resource_starvation", "unknown"],
 "failing_component": str,
 "cause": str,
 "confidence": "low"|"medium"|"high",
 "evidence": [str, ...],
 "secondary_findings": [str, ...],
 "suggested_remedy": str (an action type from: "restart a service", "toggle a feature flag", "throttle the load generator", "scale a service", or "none/escalate"),
 "escalate_to_human": bool}"""


def _parse(text):
    m = re.search(r"\{.*\}", text or "", re.S)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return {}


def finalize(text):
    d = _parse(text)
    if not d:
        return {
            "fault_class": "unknown",
            "failing_component": "unknown",
            "cause": "Agent output was not valid JSON; escalating safely to human.",
            "confidence": "low",
            "evidence": [],
            "dropped_ungrounded_evidence": [],
            "secondary_findings": [],
            "suggested_remedy": "none/escalate",
            "escalate_to_human": True,
        }
    good, dropped = [], []
    for item in d.get("evidence", []):
        (good if grounded(item) else dropped).append(item)
    d["evidence"], d["dropped_ungrounded_evidence"] = good, dropped
    if not good:  # nothing verifiable -> do not claim a confident fix
        d["confidence"], d["escalate_to_human"] = "low", True
        d["suggested_remedy"] = "none/escalate"
    return d


def investigate(alert, max_steps=12, enforce_all_pillars=True, verbose=False):
    reset_session()
    client, model = _build_llm_client()
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": f"ALERT: {alert}"},
    ]
    nudged_pillars = False

    for step in range(1, max_steps + 1):
        if action_api.is_kill_switch_active():
            return {
                "fault_class": "unknown",
                "failing_component": "unknown",
                "cause": "Investigation halted immediately because the Kill Switch is active.",
                "confidence": "low",
                "evidence": [],
                "dropped_ungrounded_evidence": [],
                "secondary_findings": [],
                "suggested_remedy": "none/escalate",
                "escalate_to_human": True,
                "kill_switch_aborted": True,
            }

        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=TOOL_SPECS,
            temperature=0,
        )
        msg = resp.choices[0].message
        messages.append(msg)
        if not msg.tool_calls:
            missing = missing_signal_categories()
            if enforce_all_pillars and missing and not nudged_pillars and step < max_steps:
                nudged_pillars = True
                hint_map = {
                    "metrics": "triage or metric_query",
                    "containers": "container_health",
                    "traces": "error_hotspots or trace_detail",
                    "logs": "get_logs on the suspect service",
                    "deploys": "deploy_history",
                }
                needed = ", ".join(f"{cat} ({hint_map[cat]})" for cat in missing)
                if verbose:
                    print(f"[Step {step}] Prompting agent to query remaining signal pillars: {needed}", file=sys.stderr)
                messages.append({
                    "role": "user",
                    "content": (
                        f"Before finalizing your JSON diagnosis, query the remaining observability pillars "
                        f"so all 5 read tool categories are checked: {needed}."
                    ),
                })
                continue
            return finalize(msg.content)

        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            if verbose:
                print(f"[Step {step}] Calling tool: {tc.function.name}({json.dumps(args)})", file=sys.stderr)
            out = call_tool(tc.function.name, args)
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": out})

    messages.append({
        "role": "user",
        "content": "Step limit reached. Give your final JSON now; use low confidence if unsure.",
    })
    msg = client.chat.completions.create(model=model, messages=messages, temperature=0).choices[0].message
    return finalize(msg.content)


def run_full_incident_loop(
    alert: str,
    max_steps: int = 10,
    diagnose_only: bool = False,
    dry_run: bool = False,
    approval_mode: str | None = None,
    settle_seconds: int = 15,
    verbose: bool = True,
) -> dict:
    incident_id = f"inc-{int(time.time())}"
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    action_api.log_audit("incident_opened", {"incident_id": incident_id, "alert": alert})

    diagnosis = investigate(alert, max_steps=max_steps, verbose=verbose)
    action_api.log_audit("incident_diagnosed", {"incident_id": incident_id, "diagnosis": diagnosis})

    if diagnose_only:
        return diagnosis

    plan = action_api.build_action_plan(incident_id, diagnosis, OBSERVED_SERVICES)
    approval = None
    execution = None
    verification = None

    if plan.get("allowed") and not plan.get("escalate"):
        approval = action_api.request_human_approval(
            diagnosis=diagnosis,
            plan=plan,
            dry_run=dry_run,
            auto_mode=approval_mode,
        )
        if approval.get("approved"):
            execution = action_api.execute_action(plan, approval)
            if execution.get("executed") and not approval.get("dry_run"):
                verification = action_api.verify_recovery(
                    target_service=plan["target"],
                    settle_seconds=settle_seconds,
                )
                if not verification.get("verified"):
                    rollback_res = action_api.rollback_action(plan, execution)
                    verification["rollback"] = rollback_res
    else:
        print(f"\n[ESCALATION] Escalating incident {incident_id} to human operator: {plan.get('reason')}")
        action_api.log_audit("incident_escalated", {"incident_id": incident_id, "reason": plan.get("reason")})

    report = action_api.write_incident_report(
        incident_id=incident_id,
        alert=alert,
        started_at=started_at,
        diagnosis=diagnosis,
        plan=plan,
        approval=approval,
        execution=execution,
        verification=verification,
        observations=list(OBSERVATIONS),
    )
    print(f"\n[REPORT] Saved incident reports to:\n  - {report['report_files']['json']}\n  - {report['report_files']['markdown']}")
    return report


def main():
    p = argparse.ArgumentParser(description="Incident Zero: AI On-Call Engineer")
    p.add_argument(
        "alert",
        nargs="?",
        default="Automatic anomaly scan triggered: investigate current system health and error rates.",
        help="Alert description to investigate",
    )
    p.add_argument(
        "--diagnose-only",
        action="store_true",
        help="Run only investigation and print diagnosis JSON (Checkpoints 1 & 2)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Run full loop in dry-run mode (logs WOULD CALL without mutating the system)",
    )
    p.add_argument(
        "--max-steps",
        type=int,
        default=10,
        help="Maximum tool-calling iterations (default: 10)",
    )
    p.add_argument(
        "--settle-seconds",
        type=int,
        default=15,
        help="Seconds to wait after executing an action before verifying recovery (default: 15)",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress step-by-step tool logs on stderr",
    )
    args = p.parse_args()

    out = run_full_incident_loop(
        alert=args.alert,
        max_steps=args.max_steps,
        diagnose_only=args.diagnose_only,
        dry_run=args.dry_run,
        settle_seconds=args.settle_seconds,
        verbose=not args.quiet,
    )
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
