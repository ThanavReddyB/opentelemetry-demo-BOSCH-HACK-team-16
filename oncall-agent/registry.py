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
TOOL_SPECS = jaeger_tools.TOOL_SPECS + ops_tools.TOOL_SPECS + [metrics.TOOL_SPEC]

MAX_OUTPUT_CHARS = 4000

SEEN = set()
OBS_TOKENS = {}
OBSERVED_SERVICES = set()
OBSERVATIONS = []
CALLED_TOOLS = set()
RUNNING_SERVICES = set()
DOWN_SERVICES = set()

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
        "output_preview": out[:500],
    })
    return out


def grounded(item):
    """Check that cited evidence is grounded in tool outputs from this session."""
    text = str(item or "")
    if not text.strip() or not SEEN:
        return False

    refs = {f"obs-{n}" for n in _OBS_REF.findall(text)}
    if refs and not refs <= set(OBS_TOKENS):
        return False  # cites an observation that does not exist
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
