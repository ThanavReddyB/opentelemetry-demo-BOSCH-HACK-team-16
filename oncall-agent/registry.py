# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Merged tool registry + evidence grounding + observed service tracker.

Every tool result the LLM sees is tokenised into SEEN and tracked in OBSERVATIONS.
A piece of cited evidence counts as grounded only if its trace/span IDs or key numeric/service tokens
appear in the tool outputs collected during THIS incident investigation.
"""
import json
import re
import time

import jaeger_tools
import ops_tools

TOOLS = {**jaeger_tools.TOOLS, **ops_tools.TOOLS}
TOOL_SPECS = jaeger_tools.TOOL_SPECS + ops_tools.TOOL_SPECS

SEEN = set()
OBSERVED_SERVICES = set()
OBSERVATIONS = []
CALLED_TOOLS = set()

SIGNAL_CATEGORIES = {
    "metrics": {"triage", "list_metrics", "metric_query", "metric_trend"},
    "traces": {"error_hotspots", "trace_detail", "list_services", "dependencies", "attribute_skew", "edge_latency_gap"},
    "logs": {"get_logs"},
    "containers": {"triage", "container_health"},
    "deploys": {"deploy_history"},
}

KNOWN_SERVICES = {
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


def reset_session():
    """Reset grounding state at the start of each incident investigation."""
    SEEN.clear()
    OBSERVED_SERVICES.clear()
    OBSERVATIONS.clear()
    CALLED_TOOLS.clear()
    jaeger_tools.EVIDENCE.clear()


def missing_signal_categories():
    """Return any of the 5 core observability categories not yet queried in this session."""
    return [cat for cat, names in SIGNAL_CATEGORIES.items() if not (CALLED_TOOLS & names)]


def _tok(text):
    return re.findall(r"[a-z0-9_.-]+", str(text).lower())


def _word_tok(text):
    return re.findall(r"[a-z0-9]+", str(text).lower())


def call_tool(name, args):
    try:
        res = TOOLS[name](**args)
        out = json.dumps(res)
    except Exception as e:  # errors go back to the model so it can adapt
        out = json.dumps({"tool_error": f"{type(e).__name__}: {e}"})
    out = out[:4000]
    CALLED_TOOLS.add(name)
    SEEN.update(_tok(out))
    SEEN.update(_word_tok(out))
    for svc in KNOWN_SERVICES:
        if svc in out.lower():
            OBSERVED_SERVICES.add(svc)
    OBSERVATIONS.append({
        "id": f"obs-{len(OBSERVATIONS) + 1}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool": name,
        "args": args,
        "output_preview": out[:500],
    })
    return out


def grounded(item):
    """Check that cited evidence is grounded in tool outputs from this session."""
    if not item or not SEEN:
        return False
    # Check if an exact trace ID / span ID from Jaeger is cited
    for ev_id in jaeger_tools.EVIDENCE:
        if len(ev_id) >= 8 and ev_id.lower() in str(item).lower():
            return True
    toks = _word_tok(item)
    if not toks:
        return False
    # Any hex/trace IDs (8+ chars with digits) must exist in SEEN
    long_ids = [t for t in toks if any(c.isdigit() for c in t) and any(c.isalpha() for c in t) and len(t) >= 8]
    if long_ids and any(t not in SEEN for t in long_ids):
        return False
    words = [t for t in toks if len(t) >= 3]
    if not words:
        return False
    return sum(w in SEEN for w in words) / len(words) >= 0.45
