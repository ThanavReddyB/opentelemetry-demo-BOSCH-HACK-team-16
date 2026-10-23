# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Read-only Jaeger tools for the on-call agent.

Every function returns small, JSON-able dicts (never raw traces) so the LLM
stays cheap and focused. Every trace ID / message returned is recorded in
EVIDENCE so the final diagnosis can be grounding-checked.

Config: JAEGER_API (auto-resolves http://localhost:8080/jaeger/api or http://localhost:16686/api).
Rule #6 enforcement: flagd / flagd-ui spans and feature_flag.* attributes are strictly excluded.
"""
import json
import os
import time
from collections import Counter, defaultdict

import requests

CANDIDATE_URLS = [
    os.environ.get("JAEGER_API", "").rstrip("/"),
    "http://localhost:8080/jaeger/api",
    "http://localhost:8080/jaeger/ui/api",
    "http://localhost:16686/api",
]
CANDIDATE_URLS = [u for u in CANDIDATE_URLS if u]

BLOCKED_SERVICES = {"flagd", "flagd-ui"}
SKIP_KEYS = {"error", "span.kind", "internal.span.format", "http.url", "http.target", "user_agent.original"}
SKIP_PREFIX = ("otel.", "feature_flag", "flagd", "telemetry.", "thread.", "code.")  # flag data = answer key

EVIDENCE = set()  # trace IDs, span IDs and error messages the tools have shown the LLM
_RESOLVED_BASE = None


def _resolve_base():
    global _RESOLVED_BASE
    if _RESOLVED_BASE:
        return _RESOLVED_BASE
    if os.environ.get("JAEGER_API"):
        _RESOLVED_BASE = os.environ["JAEGER_API"].rstrip("/")
        return _RESOLVED_BASE
    for url in CANDIDATE_URLS:
        try:
            r = requests.get(f"{url}/services", timeout=3)
            if r.status_code == 200 and "data" in r.json():
                _RESOLVED_BASE = url
                return _RESOLVED_BASE
        except Exception:
            continue
    return CANDIDATE_URLS[0]


def _get(path, **params):
    base = _resolve_base()
    r = requests.get(f"{base}{path}", params=params, timeout=15)
    r.raise_for_status()
    return r.json()


def _us(minutes_ago=0):
    return int((time.time() - minutes_ago * 60) * 1_000_000)


def _tags(span):
    return {
        t["key"]: t["value"]
        for t in span.get("tags", [])
        if not str(t.get("key", "")).startswith(("feature_flag", "flagd"))
    }


def _is_error(span):
    t = _tags(span)
    if str(t.get("error", "")).lower() == "true" or t.get("otel.status_code") == "ERROR":
        return True
    http = t.get("http.status_code") or t.get("http.response.status_code")
    if http and str(http).isdigit() and int(http) >= 500:
        return True
    grpc = t.get("rpc.grpc.status_code")
    return grpc is not None and str(grpc).isdigit() and int(grpc) != 0


def _message(span):
    t = _tags(span)
    msg = t.get("otel.status_description") or t.get("exception.message") or ""
    for log in span.get("logs", []):
        f = {
            x["key"]: x["value"]
            for x in log.get("fields", [])
            if not str(x.get("key", "")).startswith(("feature_flag", "flagd"))
        }
        msg = msg or f.get("exception.message") or f.get("message") or ""
    return str(msg)[:200]


def summarize_trace(trace):
    """Find the deepest erroring spans: errors with no erroring descendant.

    Errors propagate upward (frontend <- checkout <- cart), so these are the
    best root-cause candidates, not the loud spans near the top.
    """
    procs = {
        k: v["serviceName"]
        for k, v in trace.get("processes", {}).items()
        if v.get("serviceName") not in BLOCKED_SERVICES
    }
    spans = {
        s["spanID"]: s
        for s in trace.get("spans", [])
        if s.get("processID") in procs
        and not any(b in str(s.get("operationName", "")).lower() for b in ("flagd", "feature_flag"))
    }
    children = defaultdict(list)
    for s in spans.values():
        for ref in s.get("references", []):
            if ref["spanID"] in spans:
                children[ref["spanID"]].append(s["spanID"])
    err = {sid for sid, s in spans.items() if _is_error(s)}

    def has_err_descendant(sid):
        stack = list(children[sid])
        while stack:
            c = stack.pop()
            if c in err:
                return True
            stack.extend(children[c])
        return False

    roots = []
    for sid in err:
        if not has_err_descendant(sid):
            s = spans[sid]
            roots.append({
                "service": procs.get(s["processID"], "?"),
                "operation": s["operationName"],
                "span_id": sid,
                "message": _message(s),
                "duration_ms": round(s["duration"] / 1000, 1),
            })
    slowest = sorted(spans.values(), key=lambda s: -s["duration"])[:3]
    out = {
        "trace_id": trace["traceID"],
        "spans": len(spans),
        "error_spans": len(err),
        "root_error_spans": roots,
        "slowest_spans": [
            {
                "service": procs.get(s["processID"], "?"),
                "operation": s["operationName"],
                "duration_ms": round(s["duration"] / 1000, 1),
            }
            for s in slowest
        ],
    }
    EVIDENCE.add(trace["traceID"])
    for r in roots:
        EVIDENCE.add(r["span_id"])
        if r["message"]:
            EVIDENCE.add(r["message"])
    return out


def list_services():
    svcs = [s for s in (_get("/services").get("data") or []) if s not in BLOCKED_SERVICES]
    return {"services": sorted(svcs)}


def error_hotspots(service, minutes=15, limit=20):
    """Aggregate root-cause error spans across recent errored traces touching `service`."""
    if service in BLOCKED_SERVICES:
        return {"note": "flag service traces are excluded by fair-play rules"}
    traces = _get(
        "/traces",
        service=service,
        limit=limit,
        start=_us(minutes),
        end=_us(),
        tags=json.dumps({"error": "true"}),
    ).get("data") or []
    counts, examples = Counter(), defaultdict(list)
    for tr in traces:
        for r in summarize_trace(tr)["root_error_spans"]:
            key = (r["service"], r["operation"], r["message"])
            counts[key] += 1
            if len(examples[key]) < 2:
                examples[key].append(tr["traceID"])
    return {
        "service_queried": service,
        "window_min": minutes,
        "errored_traces": len(traces),
        "root_error_hotspots": [
            {
                "service": k[0],
                "operation": k[1],
                "message": k[2],
                "count": n,
                "example_traces": examples[k],
            }
            for k, n in counts.most_common(5)
        ],
    }


def trace_detail(trace_id):
    data = _get(f"/traces/{trace_id}").get("data") or []
    return summarize_trace(data[0]) if data else {"error": "trace not found"}


def dependencies(minutes=60):
    data = _get("/dependencies", endTs=int(time.time() * 1000), lookback=minutes * 60 * 1000).get("data") or []
    filtered = [
        d for d in data
        if d.get("parent") not in BLOCKED_SERVICES and d.get("child") not in BLOCKED_SERVICES
    ]
    top = sorted(filtered, key=lambda d: -d.get("callCount", 0))[:30]
    return {"edges": [{"caller": d["parent"], "callee": d["child"], "calls": d["callCount"]} for d in top]}


def attribute_skew(service, operation=None, minutes=15, limit=100):
    """Which span attribute values are over-represented among FAILING spans?
    Catches 'fails only for product X / user Y' style faults without hard-coding them."""
    if service in BLOCKED_SERVICES:
        return {"note": "flag service traces are excluded by fair-play rules"}
    traces = _get("/traces", service=service, limit=limit, start=_us(minutes), end=_us()).get("data") or []
    rows = []
    for tr in traces:
        procs = {k: v["serviceName"] for k, v in tr.get("processes", {}).items()}
        for s in tr.get("spans", []):
            if procs.get(s["processID"]) == service and (not operation or s["operationName"] == operation):
                rows.append((_is_error(s), _tags(s)))
    n, n_err = len(rows), sum(e for e, _ in rows)
    if not n_err:
        return {"spans_checked": n, "note": "no failing spans in window"}
    overall = n_err / n
    with_attr, err_with = Counter(), Counter()
    for is_err, tags in rows:
        for k, v in tags.items():
            if k in SKIP_KEYS or k.startswith(SKIP_PREFIX):
                continue
            kv = (k, str(v)[:60])
            with_attr[kv] += 1
            err_with[kv] += is_err
    hits = []
    for kv, e in err_with.items():
        rate = e / with_attr[kv]
        if e >= 2 and e / n_err >= 0.6 and rate >= max(1.5 * overall, 0.3):
            hits.append({
                "attribute": kv[0],
                "value": kv[1],
                "failing_spans": e,
                "spans_with_value": with_attr[kv],
                "error_rate_when_present_pct": round(rate * 100, 1),
                "share_of_all_failures_pct": round(e / n_err * 100, 1),
            })
    hits.sort(key=lambda h: -h["error_rate_when_present_pct"])
    return {
        "spans_checked": n,
        "failing_spans": n_err,
        "overall_error_rate_pct": round(overall * 100, 1),
        "skewed_attributes": hits[:5],
    }


def edge_latency_gap(minutes=10, entry_service="frontend", limit=50):
    """Per caller->callee edge: client-span time minus server-span time. A big gap while the callee's own
    time is normal points at the network (latency, packet loss, queueing), not at the callee."""
    traces = _get("/traces", service=entry_service, limit=limit, start=_us(minutes), end=_us()).get("data") or []
    gaps = defaultdict(list)
    for tr in traces:
        procs = {
            k: v["serviceName"]
            for k, v in tr.get("processes", {}).items()
            if v.get("serviceName") not in BLOCKED_SERVICES
        }
        spans = {s["spanID"]: s for s in tr.get("spans", []) if s.get("processID") in procs}
        for s in spans.values():
            if _tags(s).get("span.kind") != "server":
                continue
            for ref in s.get("references", []):
                p = spans.get(ref["spanID"])
                if p and ref.get("refType") == "CHILD_OF" and procs[p["processID"]] != procs[s["processID"]]:
                    gaps[(procs[p["processID"]], procs[s["processID"]])].append((p["duration"] - s["duration"]) / 1000)
    rows = []
    for (a, b), g in gaps.items():
        if len(g) >= 3:
            g.sort()
            rows.append({
                "caller": a,
                "callee": b,
                "samples": len(g),
                "median_gap_ms": round(g[len(g) // 2], 1),
                "p95_gap_ms": round(g[min(len(g) - 1, int(len(g) * 0.95))], 1),
            })
    rows.sort(key=lambda r: -r["median_gap_ms"])
    return {"window_min": minutes, "edges": rows[:6]}


TOOLS = {
    "list_services": list_services,
    "error_hotspots": error_hotspots,
    "trace_detail": trace_detail,
    "dependencies": dependencies,
    "attribute_skew": attribute_skew,
    "edge_latency_gap": edge_latency_gap,
}

TOOL_SPECS = [
    {
        "type": "function",
        "function": {
            "name": "list_services",
            "description": "List services seen by Jaeger.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "error_hotspots",
            "description": (
                "Aggregate the deepest (root-cause) erroring spans across recent errored traces "
                "that touch a service. Start here with the alerting service or the frontend."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {"type": "string"},
                    "minutes": {"type": "integer", "default": 15},
                },
                "required": ["service"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "trace_detail",
            "description": "Summarise one trace: root error spans and slowest spans.",
            "parameters": {
                "type": "object",
                "properties": {"trace_id": {"type": "string"}},
                "required": ["trace_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dependencies",
            "description": "Service call graph (caller -> callee) from recent traces.",
            "parameters": {
                "type": "object",
                "properties": {"minutes": {"type": "integer", "default": 60}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "attribute_skew",
            "description": (
                "Find span attribute values over-represented among failing spans of a service "
                "(e.g. fails only for one product id). Use when only SOME requests fail."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {"type": "string"},
                    "operation": {"type": "string"},
                    "minutes": {"type": "integer", "default": 15},
                },
                "required": ["service"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "edge_latency_gap",
            "description": (
                "Per caller->callee edge, time spent between client and server spans. A large gap with "
                "a healthy callee suggests network latency or packet loss."
            ),
            "parameters": {
                "type": "object",
                "properties": {"minutes": {"type": "integer", "default": 10}},
            },
        },
    },
]
