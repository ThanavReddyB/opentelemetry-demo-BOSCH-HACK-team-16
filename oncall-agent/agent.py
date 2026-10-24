# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""On-call agent: alert -> tool-calling investigation -> grounded diagnosis JSON -> human approval -> Action API -> verify -> report.

  python agent.py --detect-and-handle                               # wait for the detector, then handle the incident
  python agent.py --watch                                           # keep watching and handle every incident
  python agent.py --diagnose-only "checkout error rate elevated"   # investigation only, prints diagnosis JSON
  python agent.py --dry-run "checkout error rate elevated"         # full loop, nothing is changed
  python agent.py "checkout error rate elevated"                   # full loop, a human must type 'yes'
  python agent.py --detect-once [--window 2]                        # one detector scan as JSON (no LLM)

Several faults at once are handled in rounds: fix the strongest, verify it, re-scan, and investigate what is still
wrong (up to --max-rounds). LLM config lives in oncall-agent/.env (see llm.py). The LLM only proposes;
action_api.py (deterministic code + a human) decides.
"""
import argparse
import json
import re
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

import action_api
import detector
import llm
import ops_tools
import registry
from registry import OBSERVATIONS, OBSERVED_SERVICES, TOOL_SPECS, call_tool, grounded, missing_signal_categories, reset_session

AGENT_DIR = Path(__file__).resolve().parent
load_dotenv(AGENT_DIR / ".env")  # secrets come only from the git-ignored .env file
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

BACKING_STORES = {"valkey-cart", "astronomy-db", "kafka"}
FAULT_CLASSES = [
    "app_error", "partial_failure", "dependency_down", "container_crash_or_restart", "memory_leak",
    "cpu_saturation", "traffic_flood", "network_degradation", "resource_starvation", "latency_regression", "unknown",
]
ALIASES = {"redis": "valkey-cart", "valkey": "valkey-cart", "postgres": "astronomy-db", "postgresql": "astronomy-db",
           "database": "astronomy-db", "envoy": "frontend-proxy", "productcatalog": "product-catalog",
           "loadgenerator": "load-generator", "locust": "load-generator", "imageprovider": "image-provider"}
KEEP_FULL_CHARS, DIGEST_CHARS = 3000, 420
_LLM = None


def _build_llm_client():
    """One router per process so quota knowledge (pacing, exhausted providers) carries across rounds."""
    global _LLM
    if _LLM is None:
        _LLM = llm.build_router(env_file=AGENT_DIR / ".env")
    return _LLM, _LLM.model


SYSTEM = """You are an on-call SRE agent investigating a live incident in the OpenTelemetry Astronomy Shop.
Services: frontend, frontend-proxy (edge), cart, checkout, payment, product-catalog, recommendation, ad, shipping,
quote, currency, email, image-provider. Stores: valkey-cart (cart cache), astronomy-db (catalog DB).
load-generator is synthetic traffic: never a root cause unless it floods the site.

How to work (every model call is expensive: batch independent tool calls into ONE turn)
- Turn 1: call triage, container_health and deploy_history together.
- Then choose from what you learned, again batching: error_hotspots on the failing service or its caller plus
  get_logs on the suspect; confirm with get_metrics / metric_trend / attribute_skew / edge_latency_gap.
- Query metrics, traces, logs, containers and deploy history before answering; aim to finish in 4-5 turns.
- Never ask about feature-flag settings; diagnose only from telemetry.
- A result with "evidence_note" (empty or failed) proves nothing. No data is not zero.

Rules of proof
- A container listed in not_running is always a real fault and the first thing to fix (restart a service).
  Slowness elsewhere on a busy machine is usually a symptom or noise; it never outranks a stopped container.
- checkout fails calling payment and payment shows its own error spans -> payment app_error.
- checkout cannot connect to payment and payment gets no traffic -> payment dependency_down.
- dependency_down needs positive proof: the dependency is in container_health not_running, or gets zero traffic.
  "can't connect to redis" also appears when cart itself is broken while valkey-cart runs: check container state.
- A service absent from not_running/hot/cpu_limited is healthy. topology is structure, not evidence.
- valkey-cart and astronomy-db have no span metrics; judge them by container_health.
- Errors only for some requests (one product id) -> attribute_skew -> partial_failure.
- Slow edge while the callee itself is fast -> network_degradation (edge_latency_gap).
- A cpu_limited container that is slow -> resource_starvation.
- Memory rising steadily (metric_trend memory, monotonic_up_share near 1) -> memory_leak.
- Slow but not failing inside one service -> latency_regression; heavy CPU or GC -> cpu_saturation.
- Request-rate surge at frontend with rising latency -> traffic_flood.
- Several independent faults can coexist: report the strongest as primary and every other one in
  secondary_findings as "<service>: <what is wrong>".
- Thin or conflicting evidence -> confidence "low" and escalate_to_human true. Escalating beats a confident wrong fix.
- A fault that returns after an earlier fix (deploy_history recent_agent_actions) is a recurrence, not doubt:
  still propose the fix, and add "recurrence: <what was done before>" to secondary_findings so the human sees it.

Evidence: cite each item as "obs-N: <text copied exactly from that observation>" (trace_id, error message, number,
container state). Items not found in the cited observation are discarded.

Final answer: ONLY this JSON object:
{"fault_class": one of ["app_error","partial_failure","dependency_down","container_crash_or_restart","memory_leak",
  "cpu_saturation","traffic_flood","network_degradation","resource_starvation","latency_regression","unknown"],
 "failing_component": "<service>", "cause": "<one or two sentences>", "confidence": "low"|"medium"|"high",
 "evidence": ["obs-N: ..."], "secondary_findings": ["<service>: ..."],
 "suggested_remedy": "restart a service"|"toggle a feature flag"|"throttle the load generator"|"scale a service"|"none/escalate",
 "escalate_to_human": true|false}"""


def _say(msg):
    print(msg, file=sys.stderr, flush=True)


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


def _norm_component(name):
    """'Cart Service', 'cartservice', 'redis' -> the compose service name the policy understands."""
    raw = str(name or "unknown").strip().lower()
    s = re.sub(r"[\s_]+", "-", raw)
    s = re.sub(r"-?service$", "", s) or raw
    if s in registry.KNOWN_SERVICES:
        return s
    flat = s.replace("-", "")
    for svc in registry.KNOWN_SERVICES:
        if svc.replace("-", "") == flat:
            return svc
    return ALIASES.get(flat, ALIASES.get(s, s))


def _downstream(service):
    """Every service reachable from `service` in the static call graph (its direct and indirect dependencies)."""
    seen, todo = set(), [service]
    while todo:
        for a, b in ops_tools.EDGES:
            if a == todo[-1] and b not in seen:
                seen.add(b)
                todo.insert(0, b)
        todo.pop()
    return seen


def finalize(text):
    """Validate the model's JSON, drop ungrounded evidence, and downgrade anything not verifiable."""
    d = _parse(text)
    if not d:
        out = _safe_default("Agent output was not valid JSON; escalating safely to a human.")
        out["raw_output"] = str(text or "")[:300]
        return out
    out = _safe_default("")
    out["fault_class"] = d.get("fault_class") if d.get("fault_class") in FAULT_CLASSES else "unknown"
    out["failing_component"] = _norm_component(d.get("failing_component"))
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

    # A caller blamed while something it depends on is actually stopped: the fix belongs to the stopped dependency.
    comp = out["failing_component"]
    down_deps = sorted(d for d in _downstream(comp) if d in registry.DOWN_SERVICES)
    if comp not in registry.DOWN_SERVICES and len(down_deps) == 1 and out["fault_class"] in (
            "dependency_down", "app_error", "container_crash_or_restart", "unknown"):
        dep, original = down_deps[0], out["cause"]
        out.update(failing_component=dep, fault_class="dependency_down", suggested_remedy="restart a service",
                   cause=f"{dep} is not running (container state), so {comp} fails when it calls it. Original finding: {original}")
        out["secondary_findings"].append(f"Guard: retargeted from {comp} to its stopped dependency {dep} (container state).")
        out["guard_triggered"] = "retargeted_to_stopped_dependency"
        comp = dep

    # "Unreachable" contradicts a running service that is receiving requests: it is failing them itself.
    if out["fault_class"] == "dependency_down" and comp not in BACKING_STORES and comp not in registry.DOWN_SERVICES:
        try:
            served = ops_tools.service_rates(3).get(comp, 0)
        except Exception:  # noqa: BLE001 - no traffic data: leave the diagnosis as it is
            served = 0
        if served > 0:
            original = out["cause"]
            out.update(fault_class="app_error", cause=f"{comp} is receiving requests ({served}/s) and failing them itself, "
                                                      f"so it is not unreachable. Original finding: {original}")
            out["secondary_findings"].append(f"Guard: {comp} reclassified from dependency_down to app_error (it is serving traffic).")
            out["guard_triggered"] = "unreachable_but_serving_traffic"

    # A stopped app container is unambiguous evidence. If the model could not settle on anything firmer, fix that first.
    down = sorted(s for s in registry.DOWN_SERVICES if s and s != comp)
    if down and (out["confidence"] == "low" or out["escalate_to_human"] or out["fault_class"] == "unknown"):
        svc = down[0]
        cite = next((f"{o['id']}: not_running service {svc} state exited" for o in reversed(OBSERVATIONS)
                     if o["tool"] in ("container_health", "triage") and svc in o.get("output_preview", "")), None)
        if cite and grounded(cite):
            hunch = f"{out['failing_component']} ({out['fault_class']}, {out['confidence']}): {out['cause']}"
            callers = {a for a, b in ops_tools.EDGES if b == svc}
            out.update(failing_component=svc, fault_class="dependency_down" if callers else "container_crash_or_restart",
                       confidence="medium", escalate_to_human=False, suggested_remedy="restart a service",
                       cause=f"The {svc} container is not running, so everything that calls it fails.", evidence=[cite] + good)
            out["secondary_findings"].append(f"Model's own hunch, kept for the human: {hunch}")
            out["secondary_findings"].append(f"Guard: stopped container {svc} takes priority over a low-confidence diagnosis.")
            out["guard_triggered"] = "stopped_container_takes_priority"
            comp = svc

    # A backing store can only be "down" if its container is actually not running.
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


def _digest(content, limit):
    content = str(content or "")
    if len(content) <= limit:
        return content
    return content[:limit] + ' ...[older output shortened; values seen earlier still count as evidence]"}'


def _compact_history(messages, keep_last=True, full=KEEP_FULL_CHARS, digest=DIGEST_CHARS):
    """Tool results the model has already read shrink to a digest, so each call stays inside small token budgets.
    Grounding keeps the full outputs, so citing a value from an older result still validates."""
    last_call = max((i for i, m in enumerate(messages) if m.get("role") == "assistant" and m.get("tool_calls")), default=-1)
    out = []
    for i, m in enumerate(messages):
        if m.get("role") == "tool":
            m = {**m, "content": _digest(m["content"], full if keep_last and i > last_call else digest)}
        out.append(m)
    return out


def _chat(client, model, messages, tools=None):
    """One LLM call on a compacted history; if the provider still says the request is too big, shrink harder once."""
    try:
        return client.chat.completions.create(model=model, messages=_compact_history(messages), tools=tools, temperature=0)
    except llm.RequestTooLarge:
        _say("[LLM] request too large for this provider; shrinking older tool output and retrying")
        return client.chat.completions.create(model=model, messages=_compact_history(messages, full=1200, digest=200),
                                              tools=tools, temperature=0)


def _finalize_with_repair(client, model, messages, content, verbose=False):
    """If the final answer is not parseable, ask once for just the JSON before giving up."""
    if _parse(content):
        return finalize(content)
    if verbose:
        _say(f"  [repair] final answer was not valid JSON ({str(content or '')[:120]!r}); asking again")
    messages.append({"role": "user", "content": "Your last message was not a valid JSON object. Reply with ONLY the final JSON object "
                                                 "described in the instructions, no other text."})
    return finalize(_chat(client, model, messages).choices[0].message.content)


def _thought(msg):
    t = getattr(msg, "reasoning", None) or ""
    t = " ".join(str(t).split())
    return t[:170] + ("..." if len(t) > 170 else "")


def investigate(alert, max_steps=12, enforce_all_pillars=True, verbose=False, context=None):
    try:
        return _investigate(alert, max_steps, enforce_all_pillars, verbose, context)
    except llm.LLMUnavailable as e:
        _say(f"[LLM] {e}")
        out = _safe_default(f"No LLM capacity left ({e}). Escalating to a human with the telemetry gathered so far.")
        out["llm_unavailable"] = True
        out["secondary_findings"] = [f"{o['tool']}: {o.get('finding', '')}" for o in OBSERVATIONS][:8]
        return out


def _investigate(alert, max_steps, enforce_all_pillars, verbose, context):
    reset_session()
    client, model = _build_llm_client()
    user = f"ALERT: {alert}" + (f"\n\nEarlier in this incident:\n{context}" if context else "")
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]
    nudged = False

    for step in range(1, max_steps + 1):
        if action_api.is_kill_switch_active():
            out = _safe_default("Investigation halted immediately because the kill switch is active.")
            out["kill_switch_aborted"] = True
            return out

        msg = _chat(client, model, messages, TOOL_SPECS).choices[0].message
        messages.append(_assistant_dict(msg))
        if verbose and _thought(msg):
            _say(f"  [think] {_thought(msg)}")
        if not msg.tool_calls:
            missing = missing_signal_categories()
            if enforce_all_pillars and missing and not nudged and step < max_steps:
                nudged = True
                hints = {"metrics": "triage / get_metrics", "containers": "container_health", "traces": "error_hotspots / trace_detail",
                         "logs": "get_logs on the suspect service", "deploys": "deploy_history"}
                needed = ", ".join(f"{c} ({hints[c]})" for c in missing)
                if verbose:
                    _say(f"  [step {step}] asking the agent to also check: {needed}")
                messages.append({"role": "user", "content": f"Before finalizing, query the remaining observability pillars: {needed}."})
                continue
            return _finalize_with_repair(client, model, messages, msg.content, verbose)

        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": call_tool(tc.function.name, args)})
            if verbose:
                o = OBSERVATIONS[-1]
                shown = ", ".join(f"{k}={v}" for k, v in args.items())
                _say(f"  [step {step}] {o['id']:>6} {tc.function.name}({shown})\n               -> {o.get('finding', '')}")

    messages.append({"role": "user", "content": "Step limit reached. Give your final JSON now; use low confidence if unsure."})
    return _finalize_with_repair(client, model, messages, _chat(client, model, messages).choices[0].message.content, verbose)


# ------------------------------------------------------------------ incident orchestration (rounds)
def _confirm_still_wrong(wait_s=45, gap_s=30):
    """Two fresh scans after the fix: what shows up in both is still wrong, one noisy sample never starts a round.
    The wait matters: a fault behind the one just fixed (payment, while the cart cache was down) only starts failing
    once traffic flows through it again."""
    time.sleep(wait_s)
    try:
        first = detector.scan(window_min=3)
        time.sleep(gap_s)
        second = detector.scan(window_min=3)
    except Exception:  # noqa: BLE001
        return []
    seen = {detector.signature(a) for a in first}
    return [a for a in second if detector.signature(a) in seen]


def _round_summary(n, r):
    d, plan, ver = r["diagnosis"], r["action_plan"] or {}, r["verification"] or {}
    act = f"{plan.get('action_type')} on {plan.get('target')}" if plan.get("allowed") else "no action (escalated)"
    return (f"Round {n}: diagnosed {d.get('failing_component')} ({d.get('fault_class')}): {d.get('cause')[:160]}. "
            f"Action: {act}. Verification: {ver.get('status', 'not run')}.")


def _overall_status(rounds, final_clean):
    statuses = [action_api._final_status(r["action_plan"], r["human_approval"], r["execution"], r["verification"]) for r in rounds]
    last = statuses[-1]
    fixed = [r for r in rounds if (r["verification"] or {}).get("verified") or (r["verification"] or {}).get("target_recovered")]
    if last in ("Halted_Kill_Switch", "Rejected", "Simulated"):
        return last if not fixed else f"Partially_Resolved_{last}"
    if fixed and final_clean:
        return "Resolved"
    if fixed:
        return "Partially_Resolved_Escalated"
    return last


def run_full_incident_loop(alert, max_steps=10, diagnose_only=False, dry_run=False, settle_seconds=75, verbose=True,
                           max_rounds=3):
    incident_id = f"inc-{int(time.time())}"
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    action_api.log_audit("incident_opened", {"incident_id": incident_id, "alert": alert})
    if verbose:
        _say(f"\n[INCIDENT {incident_id}] {alert}")

    rounds, context, current_alert, final_clean, remaining = [], None, alert, False, []
    for n in range(1, max_rounds + 1):
        if verbose:
            _say(f"\n[ROUND {n}] investigating with read-only tools...")
        diagnosis = investigate(current_alert, max_steps=max_steps, verbose=verbose, context=context)
        observations = [{**o, "round": n} for o in OBSERVATIONS]
        action_api.log_audit("incident_diagnosed", {"incident_id": incident_id, "round": n, "diagnosis": diagnosis})
        if verbose:
            _say(f"[ROUND {n}] diagnosis: {diagnosis.get('failing_component')} ({diagnosis.get('fault_class')}), "
                 f"confidence {diagnosis.get('confidence')}" + ("  -> ESCALATE" if diagnosis.get("escalate_to_human") else ""))
        if diagnose_only:
            diagnosis["incident_id"] = incident_id
            action_api.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            (action_api.REPORTS_DIR / f"{incident_id}-diagnosis.json").write_text(json.dumps(diagnosis, indent=2, default=str) + "\n", encoding="utf-8")
            return diagnosis

        plan = action_api.build_action_plan(incident_id, diagnosis, set(OBSERVED_SERVICES), set(registry.DOWN_SERVICES),
                                            set(registry.LIMITED_SERVICES), round_no=n)
        approval = execution = verification = None
        if plan.get("allowed"):
            approval = action_api.request_human_approval(diagnosis=diagnosis, plan=plan, dry_run=dry_run)
            if approval.get("approved"):
                execution = action_api.execute_action(plan, approval)
                if execution.get("executed") and not approval.get("dry_run"):
                    verification = action_api.verify_recovery(plan["target"], settle_seconds=settle_seconds)
                    if not verification.get("verified") and not verification.get("target_recovered"):
                        verification["rollback"] = action_api.rollback_action(plan, execution)
        else:
            _say(f"\n[ESCALATION] round {n}: {plan.get('reason')}")
            action_api.log_audit("incident_escalated", {"incident_id": incident_id, "round": n, "reason": plan.get("reason")})
        rounds.append({"round": n, "alert": current_alert, "diagnosis": diagnosis, "action_plan": plan,
                       "human_approval": approval, "execution": execution, "verification": verification,
                       "observations": observations})

        ver = verification or {}
        if not (ver.get("verified") or ver.get("target_recovered")):
            break  # escalated, rejected, dry run, halted or a fix that did not work: a human takes it from here
        # Always look again: a fault hidden behind the one just fixed only shows once traffic reaches it.
        remaining = _confirm_still_wrong()
        if verbose:
            _say(f"[ROUND {n}] re-scan after the fix: " + (detector.describe(remaining) if remaining else "nothing left"))
        if not remaining:
            final_clean = True
            break
        if verbose:
            _say(f"\n[ROUND {n}] {plan['target']} recovered, but other symptoms remain: {detector.describe(remaining)}")
        context = "\n".join(_round_summary(i, r) for i, r in enumerate(rounds, 1)) + \
            "\nThose faults are fixed. Find what is STILL wrong; do not re-diagnose a fixed component."
        current_alert = detector.describe(remaining)
    else:
        remaining = remaining or []

    first, last = rounds[0], rounds[-1]
    status = _overall_status(rounds, final_clean)
    extra = {"llm_usage": _LLM.stats() if _LLM else [],
             "remaining_symptoms": [f"{a['service']}: {a['detail']}" for a in remaining] if not final_clean else []}
    report = action_api.write_incident_report(
        incident_id=incident_id, alert=alert, started_at=started_at, diagnosis=first["diagnosis"], plan=last["action_plan"],
        approval=last["human_approval"], execution=last["execution"], verification=last["verification"],
        observations=[o for r in rounds for o in r["observations"]], rounds=rounds, status=status, extra=extra,
    )
    if verbose:
        _say(f"\n[REPORT] {report['report_files']['json']}\n         {report['report_files']['markdown']}")
    return report


# ------------------------------------------------------------------ presentation
def _clip(text, n=190):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 3] + "..."


def render(out):
    """Human-readable summary of a diagnosis (diagnose-only) or a full incident report."""
    bar = "=" * 78
    rounds = out.get("rounds") or [{"diagnosis": out.get("diagnosis", out), "action_plan": out.get("action_plan"),
                                    "execution": out.get("execution"), "verification": out.get("verification")}]
    L = [bar, f"  INCIDENT {out.get('incident_id', '')}   status: {out.get('status', 'diagnosis only')}", bar]
    for n, r in enumerate(rounds, 1):
        d, plan, ex, ver = r.get("diagnosis") or {}, r.get("action_plan"), r.get("execution"), r.get("verification")
        if len(rounds) > 1:
            L.append(f"  -- round {n} --")
        L += [f"  Diagnosis : {d.get('failing_component')} ({d.get('fault_class')})   confidence: {str(d.get('confidence')).upper()}",
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
    for s in out.get("remaining_symptoms") or []:
        L.append(f"  Still open: {_clip(s)}")
    files = out.get("report_files")
    if files:
        L.append(f"  Report    : {files['markdown']}")
    elif out.get("incident_id"):
        L.append(f"  Saved     : {action_api.REPORTS_DIR / (out['incident_id'] + '-diagnosis.json')}")
    L.append(bar)
    return "\n".join(L)


def _write_json(path, obj):
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(obj, indent=2, default=str) + "\n", encoding="utf-8")


def detect_and_handle(detect_timeout=420, interval=20, persist=2, report_json=None, **loop_kw):
    """Wait for the detector to open ONE incident, handle it end to end, then exit (used by the test bench)."""
    det, deadline = detector.Detector(persist=persist, cooldown_s=0), time.time() + detect_timeout
    _say(f"[DETECT] scanning every {interval}s for up to {detect_timeout}s; an incident opens after {persist} consecutive scans")
    while time.time() < deadline:
        if action_api.is_kill_switch_active():
            _say("[DETECT] kill switch is ON: not handling anything")
            out = {"status": "Halted_Kill_Switch", "rounds": []}
            _write_json(report_json, out)
            return out
        try:
            found = detector.scan()
        except Exception as e:  # noqa: BLE001
            _say(f"[DETECT] scan error: {type(e).__name__}: {e}")
            found = []
        ready = det.step(found)
        _say(f"[DETECT] {time.strftime('%H:%M:%S')} anomalies={len(found)} persisted={len(ready)}"
             + (f"  e.g. {found[0]['service']}: {found[0]['detail']}" if found else ""))
        if ready:
            out = run_full_incident_loop(detector.describe(ready), **loop_kw)
            _write_json(report_json, out)
            print(render(out))
            return out
        time.sleep(interval)
    out = {"status": "No_Incident", "rounds": [], "note": f"no anomaly persisted within {detect_timeout}s"}
    _write_json(report_json, out)
    _say("[DETECT] no incident detected")
    return out


def watch(interval=30, persist=2, cooldown=600, **loop_kw):
    """Autonomous mode: scan telemetry, open an incident when an anomaly persists, handle it, keep watching."""
    det = detector.Detector(persist=persist, cooldown_s=cooldown)
    _say(f"[WATCH] scanning every {interval}s; incident opens after {persist} consecutive scans; Ctrl+C to stop")
    while True:
        try:
            if action_api.is_kill_switch_active():
                _say("[WATCH] kill switch is ON: paused")
            else:
                found = detector.scan()
                ready = det.step(found)
                _say(f"[WATCH] {time.strftime('%H:%M:%S')} anomalies={len(found)} ready={len(ready)}")
                if ready:
                    alert = detector.describe(ready)
                    _say(f"[WATCH] {alert}")
                    out = run_full_incident_loop(alert, **loop_kw)
                    print(render(out))
                    det.mute(ready)
        except KeyboardInterrupt:
            _say("\n[WATCH] stopped")
            return
        except Exception as e:  # noqa: BLE001 - a bad scan must not kill the watcher
            _say(f"[WATCH] error: {type(e).__name__}: {e}")
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            _say("\n[WATCH] stopped")
            return


def main():
    p = argparse.ArgumentParser(description="Incident Zero: AI On-Call Engineer")
    p.add_argument("alert", nargs="?", default="Automatic anomaly scan: investigate current system health and error rates.")
    p.add_argument("--diagnose-only", action="store_true", help="Investigate and print the diagnosis JSON only")
    p.add_argument("--dry-run", action="store_true", help="Full loop, but the executor only prints WOULD CALL")
    p.add_argument("--max-steps", type=int, default=10, help="Maximum tool-calling iterations per round")
    p.add_argument("--max-rounds", type=int, default=3, help="Maximum fix rounds per incident (multiple faults)")
    p.add_argument("--settle-seconds", type=int, default=75, help="Wait after acting before verifying recovery")
    p.add_argument("--quiet", action="store_true", help="Hide step-by-step tool logs on stderr")
    p.add_argument("--watch", action="store_true", help="Autonomous mode: detector opens incidents by itself")
    p.add_argument("--detect-and-handle", action="store_true", help="Wait for one detected incident, handle it, exit")
    p.add_argument("--detect-timeout", type=int, default=420, help="Seconds to wait for an incident (--detect-and-handle)")
    p.add_argument("--report-json", help="Also write the final report JSON to this path")
    p.add_argument("--detect-once", action="store_true", help="Run one detector scan and print the anomalies (no LLM)")
    p.add_argument("--window", type=int, default=5, help="Detector window in minutes (--detect-once)")
    p.add_argument("--interval", type=int, default=20, help="Seconds between detector scans")
    p.add_argument("--persist", type=int, default=2, help="Consecutive scans an anomaly must persist")
    p.add_argument("--cooldown", type=int, default=600, help="Seconds to ignore a handled anomaly (--watch)")
    p.add_argument("--json", action="store_true", help="Print the full machine-readable JSON instead of the summary")
    a = p.parse_args()
    loop_kw = {"max_steps": a.max_steps, "diagnose_only": a.diagnose_only, "dry_run": a.dry_run,
               "settle_seconds": a.settle_seconds, "verbose": not a.quiet, "max_rounds": a.max_rounds}
    if a.detect_once:
        print(json.dumps(detector.scan(window_min=a.window), indent=2))
        return
    if a.detect_and_handle:
        detect_and_handle(a.detect_timeout, a.interval, a.persist, a.report_json, **loop_kw)
        return
    if a.watch:
        watch(a.interval, a.persist, a.cooldown, **loop_kw)
        return
    out = run_full_incident_loop(a.alert, **loop_kw)
    _write_json(a.report_json, out)
    print(json.dumps(out, indent=2, default=str) if a.json else render(out))


if __name__ == "__main__":
    main()
