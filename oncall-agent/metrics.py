#!/usr/bin/env python3
"""metrics.py - read-only Prometheus tool for the on-call agent.

Backend: Prometheus HTTP API (default http://localhost:9090, override with PROM_URL).
Data: span-derived metrics from the OpenTelemetry collector
  traces_span_metrics_calls_total                (labels: service_name, span_name, span_kind, status_code)
  traces_span_metrics_duration_milliseconds_*    (histogram)
plus container CPU / memory gauges.

Rules this module enforces:
  * read-only: it only issues instant queries.
  * flag-mirroring telemetry is never returned (see fairplay.py),
    so the agent cannot read the answer key through metrics.
  * every argument that reaches PromQL is validated (the LLM supplies them).
  * never raises into the agent loop: failures come back as status="error",
    and "no series at all" is reported as status="no_data", not as zero errors.

Quick test:
  python metrics.py error_rate --window 5m
  python metrics.py latency_p95 --service checkout
  python metrics.py request_rate
  python metrics.py cpu
"""
import argparse
import json
import math
import os
import re
import sys
import urllib.parse
import urllib.request

import fairplay

PROM_URL = os.getenv("PROM_URL", "http://localhost:9090")
TIMEOUT_S = 10
MIN_ERR_RATE = 1e-6          # errors/second below this counts as zero

# Never show telemetry that mirrors feature-flag state.
EXCLUDED_SERVICES = tuple(sorted(fairplay.BLOCKED_SERVICES))
EXCLUDED_SPAN_RE = fairplay.BLOCKED_SPAN_REGEX
BASE_FILTER = f'service_name!~"{"|".join(EXCLUDED_SERVICES)}",span_name!~"{EXCLUDED_SPAN_RE}"'

# Traffic sources are not diagnosis targets; rows from them are annotated.
TRAFFIC_SOURCES = ("load-generator",)

# UNVERIFIED: label that identifies the service on container_* metrics.
# Check with:  (Invoke-RestMethod "http://localhost:9090/api/v1/query?query=container_cpu_utilization_ratio").data.result[0].metric
CONTAINER_LABEL = os.getenv("CONTAINER_LABEL", "service_name")

_WINDOW_RE = re.compile(r"^\d{1,3}[smh]$")
_SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,62}$")


class ToolError(Exception):
    pass


def _check_args(service, window, top):
    if not _WINDOW_RE.match(window or ""):
        raise ToolError(f"invalid window {window!r}; use forms like 5m, 30s, 1h")
    if service is not None:
        if not _SERVICE_RE.match(service):
            raise ToolError(f"invalid service name {service!r}")
        if service in EXCLUDED_SERVICES:
            raise ToolError(f"service {service!r} is not available to this tool")
    if not isinstance(top, int) or not 1 <= top <= 25:
        raise ToolError("top must be an integer between 1 and 25")


def _query(promql):
    url = f"{PROM_URL}/api/v1/query?" + urllib.parse.urlencode({"query": promql})
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_S) as resp:
            body = json.load(resp)
    except Exception as exc:  # network, timeout, bad JSON
        raise ToolError(f"prometheus unreachable: {exc}") from exc
    if body.get("status") != "success":
        raise ToolError(f"prometheus error: {body.get('error', body)}")
    return body["data"]["result"]


def _num(sample):
    try:
        v = float(sample["value"][1])
    except (KeyError, IndexError, ValueError, TypeError):
        return None
    return None if math.isnan(v) or math.isinf(v) else v


def _selector(service):
    sel = BASE_FILTER
    if service:
        sel += f',service_name="{service}"'
    return sel


def _r(x, n=4):
    return None if x is None else round(x, n)


def _result(metric, window, status, rows=None, note=None, queries=None):
    out = {"tool": "get_metrics", "metric": metric, "window": window,
           "status": status, "rows": rows or [], "queries": queries or []}
    if note:
        out["note"] = note
    return out


def error_rate(service=None, window="5m", top=8):
    sel = _selector(service)
    q_calls = f'sum by (service_name, span_name) (rate(traces_span_metrics_calls_total{{{sel}}}[{window}]))'
    q_errs = (f'sum by (service_name, span_name) '
              f'(rate(traces_span_metrics_calls_total{{{sel},status_code="STATUS_CODE_ERROR"}}[{window}]))')
    calls = {(r["metric"].get("service_name"), r["metric"].get("span_name")): _num(r) for r in _query(q_calls)}
    if not calls:
        return _result("error_rate", window, "no_data",
                       note="no span-metric series returned; treat as a failed query, not zero errors",
                       queries=[q_calls])
    rows = []
    for r in _query(q_errs):
        key = (r["metric"].get("service_name"), r["metric"].get("span_name"))
        e = _num(r)
        if e is None or e <= MIN_ERR_RATE:
            continue
        t = calls.get(key)
        row = {"service": key[0], "operation": key[1],
               "errors_per_s": _r(e), "calls_per_s": _r(t),
               "error_pct": _r(100 * e / t, 2) if t else None}
        if key[0] in TRAFFIC_SOURCES:
            row["note"] = "traffic source, not a diagnosis target"
        rows.append(row)
    rows.sort(key=lambda x: x["errors_per_s"], reverse=True)
    note = None if rows else "series exist but no errors in this window (zero errors)"
    return _result("error_rate", window, "ok", rows[:top], note, [q_calls, q_errs])


def latency_p95(service=None, window="5m", top=8):
    sel = _selector(service)
    q = (f'histogram_quantile(0.95, sum by (le, service_name, span_name) '
         f'(rate(traces_span_metrics_duration_milliseconds_bucket{{{sel}}}[{window}])))')
    rows = []
    for r in _query(q):
        v = _num(r)
        if v is None:
            continue
        row = {"service": r["metric"].get("service_name"),
               "operation": r["metric"].get("span_name"), "p95_ms": _r(v, 2)}
        if row["service"] in TRAFFIC_SOURCES:
            row["note"] = "whole user flow, not a service latency"
        rows.append(row)
    if not rows:
        return _result("latency_p95", window, "no_data", note="no latency series returned", queries=[q])
    rows.sort(key=lambda x: x["p95_ms"], reverse=True)
    return _result("latency_p95", window, "ok", rows[:top], queries=[q])


def request_rate(service=None, window="5m", top=8):
    sel = _selector(service)
    q = f'sum by (service_name) (rate(traces_span_metrics_calls_total{{{sel}}}[{window}]))'
    rows = [{"service": r["metric"].get("service_name"), "calls_per_s": _r(_num(r), 3)}
            for r in _query(q) if _num(r) is not None]
    if not rows:
        return _result("request_rate", window, "no_data", note="no series returned", queries=[q])
    rows.sort(key=lambda x: x["calls_per_s"], reverse=True)
    return _result("request_rate", window, "ok", rows[:top], queries=[q])


def _resource(metric_name, label_name, service, window, top):
    L = CONTAINER_LABEL
    flt = f'{L}="{service}"' if service else f'{L}!~"{"|".join(EXCLUDED_SERVICES)}"'
    q = f'max by ({L}) (avg_over_time({label_name}{{{flt}}}[{window}]))'
    rows = [{"service": r["metric"].get(L), "value": _r(_num(r), 4)}
            for r in _query(q) if _num(r) is not None]
    if not rows:
        return _result(metric_name, window, "no_data",
                       note=f"no series; check CONTAINER_LABEL (currently {L!r})", queries=[q])
    rows.sort(key=lambda x: x["value"], reverse=True)
    return _result(metric_name, window, "ok", rows[:top], queries=[q])


def cpu(service=None, window="5m", top=8):
    return _resource("cpu", "container_cpu_utilization_ratio", service, window, top)


def memory(service=None, window="5m", top=8):
    return _resource("memory", "container_memory_percent_ratio", service, window, top)


METRICS = {"error_rate": error_rate, "latency_p95": latency_p95,
           "request_rate": request_rate, "cpu": cpu, "memory": memory}


def get_metrics(metric, service=None, window="5m", top=8):
    """Query Prometheus for one metric view. Never raises; returns a dict with status
    "ok", "no_data" (treat as a failed query) or "error"."""
    try:
        if metric not in METRICS:
            raise ToolError(f"unknown metric {metric!r}; choose from {sorted(METRICS)}")
        _check_args(service, window, top)
        return METRICS[metric](service, window, top)
    except ToolError as exc:
        return {"tool": "get_metrics", "metric": metric, "window": window,
                "status": "error", "error": str(exc), "rows": [], "queries": []}


# Definition handed to the LLM (OpenAI-compatible function-calling format).
TOOL_SPEC = {
    "type": "function",
    "function": {
        "name": "get_metrics",
        "description": (
            "Read-only metrics from Prometheus. error_rate: failing operations with errors/s and error %, "
            "worst first (only operations with errors are listed). latency_p95: slowest operations. "
            "request_rate: calls/s per service. cpu / memory: container utilisation ratio per service. "
            "Optionally restrict to one service. status 'no_data' means the query failed, not that the value is zero."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "metric": {"type": "string", "enum": sorted(METRICS)},
                "service": {"type": "string", "description": "service name, e.g. checkout (optional)"},
                "window": {"type": "string", "description": "lookback like 5m, 15m, 1h (default 5m)"},
            },
            "required": ["metric"],
        },
    },
}


def main():
    p = argparse.ArgumentParser(description="Query the metrics tool by hand")
    p.add_argument("metric", choices=sorted(METRICS))
    p.add_argument("--service")
    p.add_argument("--window", default="5m")
    p.add_argument("--top", type=int, default=8)
    a = p.parse_args()
    print(json.dumps(get_metrics(a.metric, a.service, a.window, a.top), indent=2))


if __name__ == "__main__":
    sys.exit(main())
