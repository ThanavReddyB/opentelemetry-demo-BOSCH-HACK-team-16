# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Merged tool registry + evidence grounding + observation tracker.

Every tool result the LLM sees gets an observation id ("obs-3") injected into the JSON, is tokenised into
SEEN (all observations) and OBS_TOKENS (per observation). Cited evidence counts as grounded only if it
matches tool output collected during THIS investigation. Citing "obs-N: <value>" is checked against that
specific observation, which is much stricter than the global check.
"""
import inspect
import json
import re
import time

import jaeger_tools
import metrics
import ops_tools

TOOLS = {**jaeger_tools.TOOLS, **ops_tools.TOOLS, "get_metrics": metrics.get_metrics}
# Offered to the model: one clear tool per job keeps prompts small and choices sharp. The rest stay callable.
HIDDEN_FROM_MODEL = {"list_services", "dependencies", "list_metrics", "metric_query"}
TOOL_SPECS = [s for s in jaeger_tools.TOOL_SPECS + ops_tools.TOOL_SPECS + [metrics.TOOL_SPEC]
              if s["function"]["name"] not in HIDDEN_FROM_MODEL]

MAX_OUTPUT_CHARS = 3000

SEEN = set()
OBS_TOKENS = {}
OBSERVED_SERVICES = set()
OBSERVATIONS = []
CALLED_TOOLS = set()
RUNNING_SERVICES = set()
DOWN_SERVICES = set()
LIMITED_SERVICES = set()   # containers with an explicit CPU cap (starvation suspects)
EMPTY_OBS = set()          # observations that returned nothing usable: never valid evidence

SIGNAL_CATEGORIES = {
    "metrics": {"triage", "get_metrics", "list_metrics", "metric_query", "metric_trend"},
    "traces": {"error_hotspots", "trace_detail", "list_services", "dependencies", "attribute_skew", "edge_latency_gap"},
    "logs": {"get_logs"},
    "containers": {"triage", "container_health"},
    "deploys": {"deploy_history"},
}

KNOWN_SERVICES = {
    "ad", "accounting", "astronomy-db", "cart", "checkout", "currency", "email", "fraud-detection",
    "frontend", "frontend-proxy", "image-provider", "kafka", "load-generator", "payment",
    "product-catalog", "quote", "recommendation", "shipping", "valkey-cart",
}

_OBS_REF = re.compile(r"\bobs-(\d+)\b", re.I)


def reset_session():
    """Reset grounding state at the start of each incident investigation."""
    SEEN.clear()
    OBS_TOKENS.clear()
    OBSERVED_SERVICES.clear()
    OBSERVATIONS.clear()
    CALLED_TOOLS.clear()
    RUNNING_SERVICES.clear()
    DOWN_SERVICES.clear()
    LIMITED_SERVICES.clear()
    EMPTY_OBS.clear()
    jaeger_tools.EVIDENCE.clear()


def missing_signal_categories():
    """Return any of the 5 core observability categories not yet queried in this session."""
    return [cat for cat, names in SIGNAL_CATEGORIES.items() if not (CALLED_TOOLS & names)]


def _tok(text):
    return re.findall(r"[a-z0-9_.-]+", str(text).lower())


def _word_tok(text):
    return re.findall(r"[a-z0-9]+", str(text).lower())


def _trim(obj, max_list, max_str):
    if isinstance(obj, dict):
        return {k: _trim(v, max_list, max_str) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_trim(v, max_list, max_str) for v in obj[:max_list]]
    if isinstance(obj, str) and len(obj) > max_str:
        return obj[:max_str] + "..."
    return obj


def _compact(res, limit=MAX_OUTPUT_CHARS):
    """Serialise to JSON that is ALWAYS valid: shrink lists/strings instead of cutting mid-token."""
    out = json.dumps(res, default=str)
    if len(out) <= limit:
        return out
    for max_list, max_str in ((12, 300), (8, 200), (5, 140), (3, 100), (2, 60)):
        trimmed = _trim(res, max_list, max_str)
        if isinstance(trimmed, dict):
            trimmed["_truncated"] = True
        out = json.dumps(trimmed, default=str)
        if len(out) <= limit:
            return out
    return json.dumps({"_truncated": True, "preview": out[: limit - 80]})


def call_tool(name, args):
    obs_id = f"obs-{len(OBSERVATIONS) + 1}"
    args = args if isinstance(args, dict) else {}
    try:
        fn = TOOLS[name]
        accepted = set(inspect.signature(fn).parameters)
        clean = {k: v for k, v in args.items() if k in accepted}
        res = fn(**clean)
        if len(clean) != len(args):
            res = {"result": res, "ignored_args": sorted(set(args) - accepted)} if not isinstance(res, dict) else {
                **res, "ignored_args": sorted(set(args) - accepted)}
    except KeyError:
        res = {"tool_error": f"unknown tool {name!r}"}
    except Exception as e:  # errors go back to the model so it can adapt
        res = {"tool_error": f"{type(e).__name__}: {e}"}
    res = {"obs": obs_id, **res} if isinstance(res, dict) else {"obs": obs_id, "result": res}
    if name == "container_health" and isinstance(res.get("running"), list):
        RUNNING_SERVICES.update(res["running"])
        DOWN_SERVICES.update(c.get("service") for c in res.get("not_running", []))
    if name in ("container_health", "triage"):
        box = (res.get("containers") or {}) if name == "triage" else res
        LIMITED_SERVICES.update(c.get("service") for c in (box.get("cpu_limited") or []) if isinstance(c, dict))
        if name == "triage":
            DOWN_SERVICES.update(c.get("service") for c in (box.get("not_running") or []) if isinstance(c, dict))
    if is_empty(name, res):
        EMPTY_OBS.add(obs_id)
        res["evidence_note"] = "this result is empty or failed: it is not evidence of anything"
    out = _compact(res)

    CALLED_TOOLS.add(name)
    toks = set(_tok(out)) | set(_word_tok(out))
    SEEN.update(toks)
    OBS_TOKENS[obs_id] = toks
    OBSERVED_SERVICES.update(svc for svc in KNOWN_SERVICES if svc in toks)
    OBSERVATIONS.append({
        "id": obs_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool": name,
        "args": args,
        "finding": brief(name, res),
        "empty": obs_id in EMPTY_OBS,
        "output_preview": out[:500],
    })
    return out


def is_empty(name, res):
    """True when a tool result carries no usable signal (error, no series, no traces, no log lines)."""
    if not isinstance(res, dict) or res.get("tool_error") or res.get("status") in ("no_data", "error"):
        return True
    if "series" in res and not res["series"]:
        return True
    for key in ("traces_checked", "spans_checked", "edges", "lines"):
        if key in res and not res[key]:
            return True
    return bool(res.get("note")) and len(res) <= 3 and name not in ("triage", "container_health", "get_metrics")


def _c(text, n=90):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "..."


def brief(name, r):
    """One human line per tool result for the live console and the report timeline."""
    if not isinstance(r, dict):
        return _c(r)
    if r.get("tool_error"):
        return "tool error: " + _c(r["tool_error"])
    try:
        if name == "triage":
            a = r.get("anomalies") or []
            c = r.get("containers") or {}
            down = [d.get("service") for d in c.get("not_running", [])]
            top = "; ".join(f"{x['service']} {x.get('detail', x.get('type'))}" for x in a[:2])
            return _c(f"{len(a)} anomalies" + (f": {top}" if top else "") + (f" | DOWN: {', '.join(down)}" if down else ""), 140)
        if name == "error_hotspots":
            h = (r.get("root_error_hotspots") or [None])[0]
            root = f"root: {h.get('service')} {h.get('operation')} '{_c(h.get('message'), 60)}'" if h else "no root errors"
            return f"{r.get('errored_traces', 0)}/{r.get('traces_checked', 0)} traces errored; {root}"
        if name == "trace_detail":
            roots = r.get("root_error_spans") or []
            return _c(f"{r.get('spans')} spans, root error: " + (f"{roots[0]['service']} {roots[0]['operation']}" if roots else "none"))
        if name == "container_health":
            down = [d.get("service") for d in r.get("not_running", [])]
            hot = [f"{d.get('service')} cpu {d.get('cpu_pct')}% mem {d.get('mem_pct_of_limit')}%" for d in r.get("hot", [])]
            lim = [d.get("service") for d in r.get("cpu_limited", [])]
            parts = [f"{len(r.get('running', []))} running"] + ([f"DOWN {down}"] if down else []) + ([f"hot {hot[:2]}"] if hot else []) + ([f"cpu-capped {lim}"] if lim else [])
            return _c(", ".join(parts), 140)
        if name == "get_logs":
            p = (r.get("top_patterns") or [None])[0]
            return _c(f"{r.get('error_lines', 0)} error lines in {r.get('lines', 0)}" + (f"; top: '{p.get('example')}'" if p else ""), 140)
        if name == "get_metrics":
            row = (r.get("rows") or [None])[0]
            return _c(f"{r.get('metric')} {r.get('status')}" + (f"; top: {json.dumps(row)}" if row else ""), 140)
        if name == "metric_trend":
            s = (r.get("series") or [None])[0]
            return _c(f"first {s.get('first')} -> last {s.get('last')} (x{s.get('change_ratio')}, rising {s.get('monotonic_up_share')})" if s else r.get("note", "no series"))
        if name == "attribute_skew":
            h = (r.get("skewed_attributes") or [None])[0]
            return _c(f"{r.get('failing_spans', 0)}/{r.get('spans_checked', 0)} spans failing" + (f"; skew: {h.get('attribute')}={h.get('value')} ({h.get('error_rate_when_present_pct')}% fail)" if h else ""), 140)
        if name == "edge_latency_gap":
            e = (r.get("edges") or [None])[0]
            return _c(f"widest gap: {e.get('caller')} -> {e.get('callee')} median {e.get('median_gap_ms')}ms" if e else "no edges")
        if name == "deploy_history":
            ch = [f"{c.get('service')} {c.get('event')} {c.get('minutes_ago')}m ago" for c in (r.get("container_changes") or []) if c.get("service")]
            return _c(f"{len(ch)} recent container changes" + (f": {', '.join(ch[:3])}" if ch else ""), 140)
        if name == "topology":
            return _c(f"calls {r.get('calls')}, called by {r.get('called_by')}")
    except Exception:  # noqa: BLE001 - a summary must never break the loop
        pass
    return _c(json.dumps({k: v for k, v in r.items() if k != "obs"}, default=str))


def grounded(item):
    """Check that cited evidence is grounded in tool outputs from this session."""
    text = str(item or "")
    if not text.strip() or not SEEN:
        return False

    refs = {f"obs-{n}" for n in _OBS_REF.findall(text)}
    if refs and not refs <= set(OBS_TOKENS):
        return False  # cites an observation that does not exist
    if refs and refs <= EMPTY_OBS:
        return False  # an empty or failed query proves nothing
    pool = set().union(*(OBS_TOKENS[r] for r in refs)) if refs else SEEN
    threshold = 0.6 if refs else 0.45

    toks = _word_tok(_OBS_REF.sub(" ", text))
    if not toks:
        return False
    # An exact trace/span ID from Jaeger relaxes the threshold, but the rest of the sentence still has to match.
    if any(len(i) >= 8 and i.lower() in text.lower() for i in jaeger_tools.EVIDENCE):
        threshold = min(threshold, 0.35)
    # Any hex-looking ID (8+ chars with letters and digits) must exist in the tool output.
    long_ids = [t for t in toks if len(t) >= 8 and any(c.isdigit() for c in t) and any(c.isalpha() for c in t)]
    if long_ids and any(t not in pool for t in long_ids):
        return False
    words = [t for t in toks if len(t) >= 3]
    if not words:
        return False
    return sum(w in pool for w in words) / len(words) >= threshold
