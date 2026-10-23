# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""On-call agent: alert -> tool-calling investigation -> grounded diagnosis JSON -> human approval -> Action API -> verify -> report.

  python agent.py --diagnose-only "checkout error rate elevated"   # investigation only, prints diagnosis JSON
  python agent.py --dry-run "checkout error rate elevated"         # full loop, nothing is changed
  python agent.py "checkout error rate elevated"                   # full loop, a human must type 'yes'

LLM config (oncall-agent/.env): GROQ_API_KEY (+ optional GROQ_MODEL), or an OpenAI-compatible
API_KEY / LLM_BASE_URL / LLM_MODEL. The LLM only proposes; action_api.py (deterministic code + a human) decides.
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
import detector
import ops_tools
import registry
from registry import OBSERVATIONS, OBSERVED_SERVICES, TOOL_SPECS, call_tool, grounded, missing_signal_categories, reset_session

AGENT_DIR = Path(__file__).resolve().parent
load_dotenv(AGENT_DIR / ".env")  # secrets come only from the git-ignored .env file
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

BACKING_STORES = {"valkey-cart", "astronomy-db", "kafka"}
FAULT_CLASSES = [
    "app_error", "partial_failure", "dependency_down", "container_crash_or_restart", "memory_leak",
    "cpu_saturation", "traffic_flood", "network_degradation", "resource_starvation", "unknown",
]


def _build_llm_client():
    """Groq (allowed) or any OpenAI-compatible endpoint, from environment variables."""
    groq_key = os.environ.get("GROQ_API_KEY")
    if groq_key:
        from groq import Groq

        return Groq(api_key=groq_key), os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
    api_key = os.environ.get("API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        sys.exit("No LLM key found. Put GROQ_API_KEY (or API_KEY + LLM_BASE_URL) in oncall-agent/.env")
    from openai import OpenAI

    return OpenAI(api_key=api_key, base_url=os.environ.get("LLM_BASE_URL")), os.environ.get("LLM_MODEL", "openai/gpt-oss-120b")


SYSTEM = """You are an on-call SRE agent investigating a production incident in the OpenTelemetry Astronomy Shop.
Work only from tool results; cite only values/IDs/lines that tools returned, copied exactly. Never invent evidence.
Never ask for or look at feature-flag state.

Evidence format: every tool result has an "obs" id (e.g. "obs-3"). Cite each evidence item as
"obs-N: <exact value copied from that observation>" (a trace_id, an error message, a rate, a container state).
Items that do not match the cited observation are discarded.

Mandatory method (query ALL 5 pillars before giving your final JSON)
1. METRICS & CONTAINERS: call `triage` first (RED metrics for every service AND operation + container health).
   Use `get_metrics` (error_rate / latency_p95 / request_rate / cpu / memory, optionally per service) to confirm.
   An overall service error rate can look small while ONE operation fails (e.g. cart / EmptyCart): read the per-operation rows.
2. TRACES & TOPOLOGY: call `error_hotspots` (then `trace_detail`, `attribute_skew` or `edge_latency_gap`) on the
   suspect service and on `frontend`/`checkout` to get the deepest root-cause span and an exact trace_id.
   Call `topology` for upstream/downstream dependencies. If a trace tool returns an error or no traces, say so;
   absence of traces is NOT evidence of health.
3. LOGS: call `get_logs` on the suspect service (and its caller) for exact error lines.
4. DEPLOY HISTORY: call `deploy_history`.
5. Distinguish lookalike faults:
   - checkout fails calling payment AND payment has error spans/traffic -> payment app_error.
   - checkout fails connecting to payment AND payment receives zero traffic -> payment dependency_down.
   - cart fails AND valkey-cart container is not_running -> valkey-cart container_crash_or_restart / dependency_down.
   - cart fails on EmptyCart AND valkey-cart IS running -> cart app_error.
   - product-catalog fails AND astronomy-db container is not_running -> astronomy-db dependency_down.
   - product-catalog fails only on one product ID (attribute_skew) -> product-catalog partial_failure.
   RULES OF PROOF:
   - "dependency_down" needs POSITIVE proof: the dependency appears in container_health `not_running`, or it
     receives zero traffic. Connection-error text alone is NOT proof: the same "can't connect to redis" message
     appears when the caller is faulty while valkey-cart is perfectly healthy. Check `running` in container_health.
   - A service that is absent from not_running/hot/cpu_limited is healthy. Absence from a list is never evidence of a fault.
   - `no_data` from get_metrics is a failed/empty query, NOT "zero traffic". valkey-cart, astronomy-db and kafka emit no
     span metrics at all, so never use their request_rate as evidence; use container_health for them.
   - Same error text, different cause: if cart reports "can't connect to redis" and valkey-cart is in `running`,
     the fault is in cart (app_error), not in valkey-cart.
   - `topology` is static structure, never evidence that something failed.
6. There may be more than one simultaneous fault. Keep going until every significant anomaly from triage is
   explained or dismissed as noise; report extra faults in secondary_findings. Traffic from load-generator
   (e.g. failing /prompt requests) is test-harness noise, not a finding.

Playbook (signature -> confirm with)
- app_error: one service/operation errors -> error_hotspots, trace_detail, get_logs.
- partial_failure: only some requests fail (one product/user) -> attribute_skew on the failing operation.
- dependency_down: callers show connection refused/unavailable; callee or its DB/cache/queue is down
  -> container_health (not_running), get_logs on caller, topology.
- container_crash_or_restart: restarts/OOM/exited, request rate dropped -> container_health, get_logs.
- memory_leak: latency or restarts creep up -> list_metrics("memory"), then metric_trend over 30+ min.
- cpu_saturation: container hot or cpu_limited, latency up, little erroring -> container_health, metric_trend on cpu/gc.
- traffic_flood: request-rate surge at the entry service, latency up broadly -> triage traffic_surge, get_metrics request_rate.
- network_degradation: latency on one edge, callee's own time normal -> edge_latency_gap, then get_logs for timeouts.
- resource_starvation: CPU/memory limits (cpu_limited), throttling, OOM -> container_health.
If evidence is thin, conflicting, or no hypothesis is confirmed, set confidence "low" and escalate_to_human true.

Final answer: ONLY a JSON object:
{"fault_class": one of ["app_error","partial_failure","dependency_down","container_crash_or_restart","memory_leak",
  "cpu_saturation","traffic_flood","network_degradation","resource_starvation","unknown"],
 "failing_component": str,
 "cause": str,
 "confidence": "low"|"medium"|"high",
 "evidence": ["obs-N: exact value", ...],
 "secondary_findings": [str, ...],
 "suggested_remedy": one of "restart a service", "toggle a feature flag", "throttle the load generator", "scale a service", "none/escalate",
 "escalate_to_human": bool}"""


def _parse(text):
    """Find the diagnosis object in free text: handles prose around it, code fences, trailing braces, raw newlines."""
    text = text or ""
    dec, fallback = json.JSONDecoder(strict=False), {}
    for m in re.finditer(r"\{", text):
        try:
            obj, _ = dec.raw_decode(text, m.start())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            if "fault_class" in obj:
                return obj
            fallback = fallback or obj
    return fallback


def _safe_default(cause):
    return {
        "fault_class": "unknown", "failing_component": "unknown", "cause": cause, "confidence": "low",
        "evidence": [], "dropped_ungrounded_evidence": [], "secondary_findings": [],
        "suggested_remedy": "none/escalate", "escalate_to_human": True,
    }


def finalize(text):
    """Validate the model's JSON, drop ungrounded evidence, and downgrade anything not verifiable."""
    d = _parse(text)
    if not d:
        out = _safe_default("Agent output was not valid JSON; escalating safely to a human.")
        out["raw_output"] = str(text or "")[:300]
        return out
    out = _safe_default("")
    out["fault_class"] = d.get("fault_class") if d.get("fault_class") in FAULT_CLASSES else "unknown"
    out["failing_component"] = str(d.get("failing_component") or "unknown")
    out["cause"] = str(d.get("cause") or "")
    out["confidence"] = d.get("confidence") if d.get("confidence") in ("low", "medium", "high") else "low"
    out["secondary_findings"] = [str(x) for x in (d.get("secondary_findings") or [])]
    out["suggested_remedy"] = str(d.get("suggested_remedy") or "none/escalate")
    out["escalate_to_human"] = bool(d.get("escalate_to_human", False))
    if d.get("target_flag"):
        out["target_flag"] = str(d["target_flag"])

    good, dropped = [], []
    for item in d.get("evidence") or []:
        (good if grounded(item) else dropped).append(str(item))
    out["evidence"], out["dropped_ungrounded_evidence"] = good, dropped

    if not good:  # nothing verifiable -> never claim a confident fix
        out.update(confidence="low", escalate_to_human=True, suggested_remedy="none/escalate")
    elif out["confidence"] == "high" and (len(good) < 2 or dropped or missing_signal_categories()):
        out["confidence"] = "medium"  # high needs >=2 grounded items, none dropped, all 5 pillars queried

    # A backing store can only be "down" if its container is actually not running.
    comp = out["failing_component"]
    if (out["fault_class"] == "dependency_down" and comp in BACKING_STORES
            and comp in registry.RUNNING_SERVICES and comp not in registry.DOWN_SERVICES):
        # Its container is running, so the dependency is not what is down. If exactly one of its callers is
        # implicated by the diagnosis itself, the fault is in that caller; otherwise escalate.
        text = " ".join([out["cause"], *good]).lower()
        callers = sorted({a for a, b in ops_tools.EDGES if b == comp})
        implicated = [c for c in callers if re.search(rf"(?<![\w-]){re.escape(c)}(?![\w-])", text)]
        original = out["cause"]
        if len(implicated) == 1:
            caller = implicated[0]
            out.update(
                fault_class="app_error", failing_component=caller, confidence="medium", escalate_to_human=False,
                suggested_remedy="toggle a feature flag",
                cause=f"{caller} cannot use {comp} although the {comp} container is running, so the fault is in {caller}, "
                      f"not in the dependency. Original finding: {original}",
            )
            out["secondary_findings"].append(f"Guard: reclassified from {comp} dependency_down to {caller} app_error (container state).")
            out["guard_triggered"] = "reclassified_to_caller"
        else:
            out["secondary_findings"].append(f"Guard: {comp} was claimed down but its container is running; diagnosis contradicted by container state.")
            out.update(confidence="low", escalate_to_human=True, suggested_remedy="none/escalate")
            out["guard_triggered"] = "dependency_down_contradicted_by_container_state"
    return out


def _assistant_dict(msg):
    d = {"role": "assistant", "content": msg.content or ""}
    if msg.tool_calls:
        d["tool_calls"] = [
            {"id": tc.id, "type": "function",
             "function": {"name": tc.function.name, "arguments": tc.function.arguments or "{}"}}
            for tc in msg.tool_calls
        ]
    return d


def _chat(client, model, messages, tools=None):
    """One LLM call with retry/backoff for rate limits, timeouts and malformed tool calls."""
    last = None
    for attempt in range(4):
        try:
            kw = {"model": model, "messages": messages, "temperature": 0}
            if tools:
                kw["tools"] = tools
            return client.chat.completions.create(**kw)
        except Exception as e:  # noqa: BLE001
            last = e
            text = f"{type(e).__name__} {e}".lower()
            retryable = any(k in text for k in ("ratelimit", "429", "timeout", "connection", "internalserver", "503", "tool_use_failed", "failed to call a function"))
            if not retryable or attempt == 3:
                raise
            time.sleep(2 * (2 ** attempt))
    raise last


def _finalize_with_repair(client, model, messages, content, verbose=False):
    """If the final answer is not parseable, ask once for just the JSON before giving up."""
    if _parse(content):
        return finalize(content)
    if verbose:
        print(f"[repair] final answer was not valid JSON ({str(content or '')[:120]!r}); asking again", file=sys.stderr)
    messages.append({"role": "user", "content": "Your last message was not a valid JSON object. Reply with ONLY the final JSON object "
                                                 "described in the instructions, no other text."})
    return finalize(_chat(client, model, messages).choices[0].message.content)


def investigate(alert, max_steps=12, enforce_all_pillars=True, verbose=False):
    reset_session()
    client, model = _build_llm_client()
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": f"ALERT: {alert}"}]
    nudged = False

    for step in range(1, max_steps + 1):
        if action_api.is_kill_switch_active():
            out = _safe_default("Investigation halted immediately because the kill switch is active.")
            out["kill_switch_aborted"] = True
            return out

        msg = _chat(client, model, messages, TOOL_SPECS).choices[0].message
        messages.append(_assistant_dict(msg))
        if not msg.tool_calls:
            missing = missing_signal_categories()
            if enforce_all_pillars and missing and not nudged and step < max_steps:
                nudged = True
                hints = {"metrics": "triage / get_metrics", "containers": "container_health", "traces": "error_hotspots / trace_detail",
                         "logs": "get_logs on the suspect service", "deploys": "deploy_history"}
                needed = ", ".join(f"{c} ({hints[c]})" for c in missing)
                if verbose:
                    print(f"[Step {step}] Asking the agent to cover remaining pillars: {needed}", file=sys.stderr)
                messages.append({"role": "user", "content": f"Before finalizing, query the remaining observability pillars: {needed}."})
                continue
            return _finalize_with_repair(client, model, messages, msg.content, verbose)

        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            if verbose:
                print(f"[Step {step}] {tc.function.name}({json.dumps(args)})", file=sys.stderr)
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": call_tool(tc.function.name, args)})

    messages.append({"role": "user", "content": "Step limit reached. Give your final JSON now; use low confidence if unsure."})
    return _finalize_with_repair(client, model, messages, _chat(client, model, messages).choices[0].message.content, verbose)


def run_full_incident_loop(alert, max_steps=10, diagnose_only=False, dry_run=False, settle_seconds=75, verbose=True):
    incident_id = f"inc-{int(time.time())}"
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    action_api.log_audit("incident_opened", {"incident_id": incident_id, "alert": alert})

    diagnosis = investigate(alert, max_steps=max_steps, verbose=verbose)
    action_api.log_audit("incident_diagnosed", {"incident_id": incident_id, "diagnosis": diagnosis})
    if diagnose_only:
        diagnosis["incident_id"] = incident_id
        action_api.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        (action_api.REPORTS_DIR / f"{incident_id}-diagnosis.json").write_text(json.dumps(diagnosis, indent=2, default=str) + "\n", encoding="utf-8")
        return diagnosis

    plan = action_api.build_action_plan(incident_id, diagnosis, OBSERVED_SERVICES, registry.DOWN_SERVICES)
    approval = execution = verification = None

    if plan.get("allowed"):
        approval = action_api.request_human_approval(diagnosis=diagnosis, plan=plan, dry_run=dry_run)
        if approval.get("approved"):
            execution = action_api.execute_action(plan, approval)
            if execution.get("executed") and not approval.get("dry_run"):
                verification = action_api.verify_recovery(plan["target"], settle_seconds=settle_seconds)
                if not verification.get("verified"):
                    verification["rollback"] = action_api.rollback_action(plan, execution)
    else:
        print(f"\n[ESCALATION] Incident {incident_id} escalated to a human: {plan.get('reason')}", file=sys.stderr)
        action_api.log_audit("incident_escalated", {"incident_id": incident_id, "reason": plan.get("reason")})

    report = action_api.write_incident_report(
        incident_id=incident_id, alert=alert, started_at=started_at, diagnosis=diagnosis, plan=plan,
        approval=approval, execution=execution, verification=verification, observations=list(OBSERVATIONS),
    )
    print(f"\n[REPORT] {report['report_files']['json']}\n         {report['report_files']['markdown']}", file=sys.stderr)
    return report


def _clip(text, n=190):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 3] + "..."


def render(out):
    """Human-readable summary of a diagnosis (diagnose-only) or a full incident report."""
    d = out.get("diagnosis", out)
    plan, ver, ex = out.get("action_plan"), out.get("verification"), out.get("execution")
    bar = "=" * 74
    L = [bar, f"  INCIDENT {out.get('incident_id', '')}   status: {out.get('status', 'diagnosis only')}", bar,
         f"  Diagnosis : {d.get('failing_component')} ({d.get('fault_class')})   confidence: {str(d.get('confidence')).upper()}",
         f"  Cause     : {_clip(d.get('cause'), 300)}"]
    if d.get("escalate_to_human"):
        L.append("  ESCALATE  : agent is not confident enough to act; a human should take over")
    L.append("  Evidence  :")
    L += [f"    {i}. {_clip(e)}" for i, e in enumerate(d.get("evidence", []), 1)] or ["    (none verified)"]
    if d.get("dropped_ungrounded_evidence"):
        L.append(f"  Dropped   : {len(d['dropped_ungrounded_evidence'])} claim(s) not found in tool output")
    for s in d.get("secondary_findings", []):
        L.append(f"  Also seen : {_clip(s)}")
    if plan:
        if plan.get("allowed"):
            L.append(f"  Fix       : {plan['action_type']} on {plan['target']}  {json.dumps(plan['parameters'])}")
            if plan.get("policy_note"):
                L.append(f"              ({plan['policy_note']})")
        else:
            L.append(f"  Fix       : none, escalated ({_clip(plan.get('reason'))})")
    if ex:
        L.append(f"  Outcome   : {_clip(ex.get('detail'))}")
    if ver:
        L.append(f"  Recovery  : {ver.get('status')} ({ver.get('passing_samples', 0)}/{ver.get('required_samples', 0)} clean scans)")
        if ver.get("rollback"):
            L.append(f"  Rollback  : {_clip(ver['rollback'].get('detail') or ver['rollback'].get('reason'))}")
    files = out.get("report_files")
    if files:
        L.append(f"  Report    : {files['markdown']}")
    elif out.get("incident_id"):
        L.append(f"  Saved     : {action_api.REPORTS_DIR / (out['incident_id'] + '-diagnosis.json')}")
    L.append(bar)
    return "\n".join(L)


def watch(interval=30, persist=2, cooldown=600, **loop_kw):
    """Autonomous mode: scan telemetry, open an incident when an anomaly persists, handle it, keep watching."""
    det = detector.Detector(persist=persist, cooldown_s=cooldown)
    print(f"[WATCH] scanning every {interval}s; incident opens after {persist} consecutive scans; Ctrl+C to stop", file=sys.stderr)
    while True:
        try:
            if action_api.is_kill_switch_active():
                print("[WATCH] kill switch is ON: paused", file=sys.stderr)
            else:
                found = detector.scan()
                ready = det.step(found)
                print(f"[WATCH] {time.strftime('%H:%M:%S')} anomalies={len(found)} ready={len(ready)}", file=sys.stderr)
                if ready:
                    alert = detector.describe(ready)
                    print(f"[WATCH] {alert}", file=sys.stderr)
                    out = run_full_incident_loop(alert, **loop_kw)
                    print(render(out))
                    det.mute(ready)
        except KeyboardInterrupt:
            print("\n[WATCH] stopped", file=sys.stderr)
            return
        except Exception as e:  # noqa: BLE001 - a bad scan must not kill the watcher
            print(f"[WATCH] error: {type(e).__name__}: {e}", file=sys.stderr)
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[WATCH] stopped", file=sys.stderr)
            return


def main():
    p = argparse.ArgumentParser(description="Incident Zero: AI On-Call Engineer")
    p.add_argument("alert", nargs="?", default="Automatic anomaly scan: investigate current system health and error rates.")
    p.add_argument("--diagnose-only", action="store_true", help="Investigate and print the diagnosis JSON only")
    p.add_argument("--dry-run", action="store_true", help="Full loop, but the executor only prints WOULD CALL")
    p.add_argument("--max-steps", type=int, default=10, help="Maximum tool-calling iterations")
    p.add_argument("--settle-seconds", type=int, default=75, help="Wait after acting before verifying recovery")
    p.add_argument("--quiet", action="store_true", help="Hide step-by-step tool logs on stderr")
    p.add_argument("--watch", action="store_true", help="Autonomous mode: detector opens incidents by itself")
    p.add_argument("--detect-once", action="store_true", help="Run one detector scan and print the anomalies (no LLM)")
    p.add_argument("--interval", type=int, default=30, help="Seconds between detector scans (--watch)")
    p.add_argument("--persist", type=int, default=2, help="Consecutive scans an anomaly must persist (--watch)")
    p.add_argument("--cooldown", type=int, default=600, help="Seconds to ignore a handled anomaly (--watch)")
    p.add_argument("--json", action="store_true", help="Print the full machine-readable JSON instead of the summary")
    a = p.parse_args()
    if a.detect_once:
        print(json.dumps(detector.scan(), indent=2))
        return
    if a.watch:
        watch(a.interval, a.persist, a.cooldown, max_steps=a.max_steps, diagnose_only=a.diagnose_only,
              dry_run=a.dry_run, settle_seconds=a.settle_seconds, verbose=not a.quiet)
        return
    out = run_full_incident_loop(a.alert, a.max_steps, a.diagnose_only, a.dry_run, a.settle_seconds, not a.quiet)
    print(json.dumps(out, indent=2, default=str) if a.json else render(out))


if __name__ == "__main__":
    main()
