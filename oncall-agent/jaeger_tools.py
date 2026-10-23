# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Read-only Jaeger tools for the on-call agent.

Supports BOTH Jaeger APIs and normalises them to one internal trace shape:
  * v3 (OTLP JSON)  e.g. http://localhost:8080/jaeger/ui/api/v3   <- verified to answer on this stack
  * v1 (classic UI) e.g. http://localhost:16686/api               <- fallback

Every function returns small JSON-able dicts (never raw traces) so the LLM stays cheap and focused.
Every trace ID / span ID / error message shown to the LLM is recorded in EVIDENCE for grounding.

Config (env): JAEGER_API   explicit base URL (mode is inferred from a trailing /v3)
              JAEGER_FETCH_LIMIT  traces fetched per query (default 100)

Self-test on the real stack (prints what Jaeger returns so API-shape surprises are visible):
    python jaeger_tools.py
    python jaeger_tools.py --raw        # also dump the first 800 chars of a raw trace search

Fair play: flag service spans and feature_flag.* attributes are dropped at normalisation time (fairplay.py).
"""
import base64
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict

import requests

import fairplay

FETCH_LIMIT = int(os.environ.get("JAEGER_FETCH_LIMIT", "100"))
CANDIDATE_BASES = [
    b.rstrip("/")
    for b in (
        os.environ.get("JAEGER_API", ""),
        "http://localhost:8080/jaeger/ui/api/v3",   # verified on this stack
        "http://localhost:16686/api/v3",
        "http://localhost:8080/jaeger/ui/api",
        "http://localhost:16686/api",
    )
    if b
]

SKIP_KEYS = {"error", "span.kind", "internal.span.format", "http.url", "http.target", "user_agent.original"}
SKIP_PREFIX = ("otel.", "telemetry.", "thread.", "code.")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_KIND = {1: "internal", 2: "server", 3: "client", 4: "producer", 5: "consumer"}

EVIDENCE = set()  # trace IDs, span IDs and error messages shown to the LLM
_RESOLVED = None  # (base, mode)


# ------------------------------------------------------------------ HTTP / base resolution
def _resolve():
    global _RESOLVED
    if _RESOLVED:
        return _RESOLVED
    tried = []
    for base in CANDIDATE_BASES:
        try:
            r = requests.get(f"{base}/services", timeout=3)
            tried.append(f"{base} -> HTTP {r.status_code}")
            if r.status_code != 200:
                continue
            body = r.json()
            if isinstance(body, dict) and "services" in body:
                _RESOLVED = (base, "v3")
                return _RESOLVED
            if isinstance(body, dict) and "data" in body:
                _RESOLVED = (base, "v1")
                return _RESOLVED
        except Exception as e:  # noqa: BLE001 - try next candidate
            tried.append(f"{base} -> {type(e).__name__}")
    raise RuntimeError("Jaeger query API not reachable. Tried: " + "; ".join(tried) + ". Set JAEGER_API.")


def _get_text(path, params=None, timeout=20):
    base, _ = _resolve()
    r = requests.get(f"{base}{path}", params=params, timeout=timeout)
    r.raise_for_status()
    return r.text


def _rfc3339(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _us(minutes_ago=0):
    return int((time.time() - minutes_ago * 60) * 1_000_000)


# ------------------------------------------------------------------ normalisation
def _norm_id(raw):
    """Jaeger v3 normally returns hex IDs; accept base64 too."""
    s = str(raw or "")
    if not s or _HEX.match(s):
        return s.lower()
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4)).hex()
    except Exception:  # noqa: BLE001
        return s


def _otlp_value(v):
    if not isinstance(v, dict):
        return v
    for k in ("stringValue", "boolValue", "doubleValue"):
        if k in v:
            return v[k]
    if "intValue" in v:
        try:
            return int(v["intValue"])
        except (TypeError, ValueError):
            return v["intValue"]
    if "arrayValue" in v:
        return [_otlp_value(x) for x in v["arrayValue"].get("values", [])]
    return str(v)


def _otlp_attrs(lst):
    return {a["key"]: _otlp_value(a.get("value")) for a in (lst or []) if "key" in a}


def _is_error(status_code, message, attrs):
    if str(status_code) in ("2", "STATUS_CODE_ERROR", "ERROR"):
        return True
    if str(attrs.get("error", "")).lower() == "true" or attrs.get("otel.status_code") == "ERROR":
        return True
    http = attrs.get("http.status_code") or attrs.get("http.response.status_code")
    if http is not None and str(http).isdigit() and int(http) >= 500:
        return True
    grpc = attrs.get("rpc.grpc.status_code")
    return grpc is not None and str(grpc).isdigit() and int(grpc) != 0


def _clean_attrs(attrs):
    return {k: v for k, v in attrs.items() if not fairplay.is_blocked_attr(k)}


def _parse_stream(text):
    """Jaeger v3 may stream several concatenated JSON objects; accept one or many."""
    dec, i, out, text = json.JSONDecoder(), 0, [], text.strip()
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        obj, i = dec.raw_decode(text, i)
        out.append(obj)
    return out


def _group_otlp(chunks):
    """OTLP JSON chunks -> list of normalised traces (spans of flag services/ops removed)."""
    traces, order = {}, []
    for chunk in chunks:
        body = chunk.get("result", chunk) if isinstance(chunk, dict) else {}
        for rs in body.get("resourceSpans", []) or []:
            rattrs = _otlp_attrs((rs.get("resource") or {}).get("attributes"))
            service = str(rattrs.get("service.name", "?"))
            if fairplay.is_blocked_service(service):
                continue
            scopes = rs.get("scopeSpans") or rs.get("instrumentationLibrarySpans") or []
            for sc in scopes:
                for sp in sc.get("spans", []) or []:
                    name = str(sp.get("name", ""))
                    if fairplay.is_blocked_text(name):
                        continue
                    attrs = _clean_attrs(_otlp_attrs(sp.get("attributes")))
                    status = sp.get("status") or {}
                    msg = str(status.get("message") or attrs.get("exception.message") or "")
                    for ev in sp.get("events", []) or []:
                        ea = _clean_attrs(_otlp_attrs(ev.get("attributes")))
                        msg = msg or str(ea.get("exception.message") or "")
                    kind = sp.get("kind")
                    kind = _KIND.get(kind) if isinstance(kind, int) else str(kind or "").replace("SPAN_KIND_", "").lower()
                    start, end = int(sp.get("startTimeUnixNano", 0) or 0), int(sp.get("endTimeUnixNano", 0) or 0)
                    tid = _norm_id(sp.get("traceId"))
                    if tid not in traces:
                        traces[tid] = []
                        order.append(tid)
                    traces[tid].append({
                        "span_id": _norm_id(sp.get("spanId")),
                        "parent_id": _norm_id(sp.get("parentSpanId")),
                        "service": service,
                        "name": name,
                        "kind": kind,
                        "dur_us": max(0, (end - start) // 1000),
                        "error": _is_error(status.get("code"), msg, attrs),
                        "message": msg[:200],
                        "attrs": attrs,
                    })
    return [{"trace_id": t, "spans": traces[t]} for t in order]


def _norm_v1(trace):
    procs = {k: v.get("serviceName", "?") for k, v in trace.get("processes", {}).items()}
    spans = []
    for s in trace.get("spans", []):
        service = procs.get(s.get("processID"), "?")
        if fairplay.is_blocked_service(service) or fairplay.is_blocked_text(s.get("operationName", "")):
            continue
        attrs = _clean_attrs({t["key"]: t["value"] for t in s.get("tags", [])})
        msg = str(attrs.get("otel.status_description") or attrs.get("exception.message") or "")
        for log in s.get("logs", []):
            f = _clean_attrs({x["key"]: x["value"] for x in log.get("fields", [])})
            msg = msg or str(f.get("exception.message") or f.get("message") or "")
        parent = next((r["spanID"] for r in s.get("references", []) if r.get("refType") == "CHILD_OF"), "")
        spans.append({
            "span_id": s["spanID"],
            "parent_id": parent,
            "service": service,
            "name": s.get("operationName", ""),
            "kind": str(attrs.get("span.kind", "")).lower(),
            "dur_us": int(s.get("duration", 0)),
            "error": _is_error(None, msg, attrs),
            "message": msg[:200],
            "attrs": attrs,
        })
    return {"trace_id": trace["traceID"], "spans": spans}


# ------------------------------------------------------------------ fetching
def find_traces(service, minutes=15, limit=None):
    limit = int(limit or FETCH_LIMIT)
    minutes = max(1, min(int(minutes), 120))
    _, mode = _resolve()
    if mode == "v3":
        text = _get_text("/traces", {
            "query.service_name": service,
            "query.start_time_min": _rfc3339(time.time() - minutes * 60),
            "query.start_time_max": _rfc3339(time.time()),
            "query.num_traces": limit,
        })
        return _group_otlp(_parse_stream(text))
    data = json.loads(_get_text("/traces", {
        "service": service, "limit": limit, "start": _us(minutes), "end": _us(),
    })).get("data") or []
    return [_norm_v1(t) for t in data]


def fetch_trace(trace_id):
    if not re.fullmatch(r"[0-9a-fA-F]{16,32}", str(trace_id)):
        raise ValueError("trace_id must be 16-32 hex characters, copied from error_hotspots")
    _, mode = _resolve()
    text = _get_text(f"/traces/{trace_id}")
    if mode == "v3":
        traces = _group_otlp(_parse_stream(text))
        return traces[0] if traces else None
    data = json.loads(text).get("data") or []
    return _norm_v1(data[0]) if data else None


# ------------------------------------------------------------------ analysis
def summarize_trace(tr):
    """Deepest erroring spans (errors with no erroring descendant): the best root-cause candidates."""
    spans = {s["span_id"]: s for s in tr["spans"]}
    children = defaultdict(list)
    for s in spans.values():
        if s["parent_id"] in spans:
            children[s["parent_id"]].append(s["span_id"])
    err = {sid for sid, s in spans.items() if s["error"]}

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
                "service": s["service"], "operation": s["name"], "span_id": sid,
                "message": s["message"], "duration_ms": round(s["dur_us"] / 1000, 1),
            })
    slowest = sorted(spans.values(), key=lambda s: -s["dur_us"])[:3]
    out = {
        "trace_id": tr["trace_id"],
        "spans": len(spans),
        "error_spans": len(err),
        "root_error_spans": roots,
        "slowest_spans": [
            {"service": s["service"], "operation": s["name"], "duration_ms": round(s["dur_us"] / 1000, 1)}
            for s in slowest
        ],
    }
    EVIDENCE.add(tr["trace_id"])
    for r in roots:
        EVIDENCE.add(r["span_id"])
        if r["message"]:
            EVIDENCE.add(r["message"])
    return out


def list_services():
    _, mode = _resolve()
    body = json.loads(_get_text("/services"))
    svcs = body.get("services" if mode == "v3" else "data") or []
    return {"services": sorted(s for s in svcs if not fairplay.is_blocked_service(s)), "api": mode}


def error_hotspots(service, minutes=15):
    """Aggregate root-cause error spans across recent errored traces touching `service`."""
    if fairplay.is_blocked_service(service):
        return {"note": "flag service traces are excluded by fair-play rules"}
    traces = find_traces(service, minutes)
    counts, examples, errored = Counter(), defaultdict(list), 0
    for tr in traces:
        if not any(s["error"] for s in tr["spans"]):
            continue
        errored += 1
        for r in summarize_trace(tr)["root_error_spans"]:
            key = (r["service"], r["operation"], r["message"])
            counts[key] += 1
            if len(examples[key]) < 2:
                examples[key].append(tr["trace_id"])
    return {
        "service_queried": service,
        "window_min": minutes,
        "traces_checked": len(traces),
        "errored_traces": errored,
        "root_error_hotspots": [
            {"service": k[0], "operation": k[1], "message": k[2], "count": n, "example_traces": examples[k]}
            for k, n in counts.most_common(5)
        ],
        **({"note": "no traces returned for this service/window; this is NOT proof of health"} if not traces else {}),
    }


def trace_detail(trace_id):
    tr = fetch_trace(trace_id)
    return summarize_trace(tr) if tr else {"error": "trace not found"}


def dependencies(minutes=30):
    """Caller->callee edges derived from parent/child spans of recent traces (no dependency API needed)."""
    edges = Counter()
    for entry in ("frontend", "checkout"):
        try:
            traces = find_traces(entry, minutes, 60)
        except Exception:  # noqa: BLE001
            continue
        for tr in traces:
            spans = {s["span_id"]: s for s in tr["spans"]}
            for s in spans.values():
                p = spans.get(s["parent_id"])
                if p and p["service"] != s["service"]:
                    edges[(p["service"], s["service"])] += 1
    top = edges.most_common(30)
    return {"edges": [{"caller": a, "callee": b, "calls": n} for (a, b), n in top]}


def attribute_skew(service, operation=None, minutes=15):
    """Which span attribute values are over-represented among FAILING spans? Catches 'fails only for
    product X / user Y' faults without hard-coding them."""
    if fairplay.is_blocked_service(service):
        return {"note": "flag service traces are excluded by fair-play rules"}
    rows = []
    for tr in find_traces(service, minutes):
        for s in tr["spans"]:
            if s["service"] == service and (not operation or s["name"] == operation):
                rows.append((s["error"], s["attrs"]))
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
                "attribute": kv[0], "value": kv[1], "failing_spans": e,
                "spans_with_value": with_attr[kv],
                "error_rate_when_present_pct": round(rate * 100, 1),
                "share_of_all_failures_pct": round(e / n_err * 100, 1),
            })
    hits.sort(key=lambda h: -h["error_rate_when_present_pct"])
    return {
        "spans_checked": n, "failing_spans": n_err,
        "overall_error_rate_pct": round(overall * 100, 1),
        "skewed_attributes": hits[:5],
    }


def edge_latency_gap(minutes=10, entry_service="frontend"):
    """Per caller->callee edge: client-span time minus server-span time. A big gap while the callee's own
    time is normal points at the network, not at the callee."""
    gaps = defaultdict(list)
    for tr in find_traces(entry_service, minutes, 50):
        spans = {s["span_id"]: s for s in tr["spans"]}
        for s in spans.values():
            p = spans.get(s["parent_id"])
            if s["kind"] == "server" and p and p["service"] != s["service"]:
                gaps[(p["service"], s["service"])].append((p["dur_us"] - s["dur_us"]) / 1000)
    rows = []
    for (a, b), g in gaps.items():
        if len(g) >= 3:
            g.sort()
            rows.append({
                "caller": a, "callee": b, "samples": len(g),
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


def _spec(name, desc, props=None, required=None):
    return {"type": "function", "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object", "properties": props or {}, "required": required or []},
    }}


TOOL_SPECS = [
    _spec("list_services", "List services seen by Jaeger."),
    _spec(
        "error_hotspots",
        "Aggregate the deepest (root-cause) erroring spans across recent errored traces that touch a service, "
        "with example trace_ids. Start with the alerting service, 'frontend' or 'checkout'.",
        {"service": {"type": "string"}, "minutes": {"type": "integer", "default": 15}},
        ["service"],
    ),
    _spec(
        "trace_detail", "Summarise one trace by trace_id: root error spans and slowest spans.",
        {"trace_id": {"type": "string"}}, ["trace_id"],
    ),
    _spec("dependencies", "Service call graph (caller -> callee) from recent traces.", {"minutes": {"type": "integer", "default": 30}}),
    _spec(
        "attribute_skew",
        "Find span attribute values over-represented among failing spans of a service "
        "(e.g. fails only for one product id). Use when only SOME requests fail.",
        {"service": {"type": "string"}, "operation": {"type": "string"}, "minutes": {"type": "integer", "default": 15}},
        ["service"],
    ),
    _spec(
        "edge_latency_gap",
        "Per caller->callee edge, time between client and server spans. A large gap with a healthy callee "
        "suggests network latency or packet loss.",
        {"minutes": {"type": "integer", "default": 10}},
    ),
]


def _selftest(raw=False):
    base, mode = _resolve()
    print(f"Jaeger base={base} mode={mode}")
    print("services:", json.dumps(list_services()))
    if raw:
        if mode == "v3":
            text = _get_text("/traces", {
                "query.service_name": "frontend",
                "query.start_time_min": _rfc3339(time.time() - 600),
                "query.start_time_max": _rfc3339(time.time()),
                "query.num_traces": 2,
            })
        else:
            text = _get_text("/traces", {"service": "frontend", "limit": 2})
        print("RAW (first 800 chars):", text[:800])
    print("error_hotspots(frontend):", json.dumps(error_hotspots("frontend", 15), indent=2)[:2500])


if __name__ == "__main__":
    _selftest(raw="--raw" in sys.argv)
