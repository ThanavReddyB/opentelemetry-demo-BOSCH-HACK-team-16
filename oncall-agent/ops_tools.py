# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Metrics, container, log, topology and triage tools (all read-only).

Config (env): PROM_URL, SPAN_CALLS_METRIC, SPAN_DURATION_METRIC, DEMO_DIR, COMPOSE_ARGS,
DEPLOY_HISTORY_URL.
Verified in this repo's Grafana dashboards (spanmetrics-dashboard.json):
  - SPAN_CALLS_METRIC = traces_span_metrics_calls_total
  - SPAN_DURATION_METRIC = traces_span_metrics_duration_milliseconds_bucket

Fair play: flag-mirroring telemetry (flag service, flag spans/metrics/logs) is filtered out via fairplay.py.
"""
import json
import os
import re
import shlex
import subprocess
import time
from collections import Counter
from pathlib import Path

import requests

import fairplay

REPO_ROOT = Path(__file__).resolve().parent.parent
PROM = os.environ.get("PROM_URL", "http://localhost:9090").rstrip("/")
CALLS = os.environ.get("SPAN_CALLS_METRIC", "traces_span_metrics_calls_total")
DUR = os.environ.get("SPAN_DURATION_METRIC", "traces_span_metrics_duration_milliseconds_bucket")
DEMO_DIR = Path(os.environ.get("DEMO_DIR", str(REPO_ROOT))).expanduser().resolve()
COMPOSE = ["docker", "compose"] + shlex.split(os.environ.get("COMPOSE_ARGS", ""))
BLOCKED_SERVICES = fairplay.BLOCKED_SERVICES
SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
BAD = ("NaN", "+Inf", "-Inf")

# Static call graph from the demo architecture (flag-service edges deliberately omitted).
# Confirmed service names in compose.yaml (PostgreSQL service is 'astronomy-db').
EDGES = [
    ("load-generator", "frontend-proxy"),
    ("frontend-proxy", "frontend"),
    ("frontend-proxy", "image-provider"),
    ("frontend", "ad"),
    ("frontend", "cart"),
    ("frontend", "currency"),
    ("frontend", "checkout"),
    ("frontend", "shipping"),
    ("frontend", "product-catalog"),
    ("frontend", "recommendation"),
    ("checkout", "currency"),
    ("checkout", "cart"),
    ("checkout", "payment"),
    ("checkout", "email"),
    ("checkout", "kafka"),
    ("checkout", "product-catalog"),
    ("checkout", "shipping"),
    ("cart", "valkey-cart"),
    ("shipping", "quote"),
    ("product-catalog", "astronomy-db"),
    ("recommendation", "product-catalog"),
    ("accounting", "astronomy-db"),
    ("kafka", "accounting"),
    ("kafka", "fraud-detection"),
]


# ---------- helpers ----------
def _run(cmd, timeout=25):
    p = subprocess.run(cmd, cwd=str(DEMO_DIR), capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout).strip()[:200])
    return p.stdout


def _prom(path, **params):
    r = requests.get(f"{PROM}/api/v1/{path}", params=params, timeout=20)
    r.raise_for_status()
    return r.json()["data"]


def _is_blocked_query_or_metric(text):
    return fairplay.is_blocked_text(text)


def _clamp(value, lo, hi, default):
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def _by_service(query):
    out = {}
    for r in _prom("query", query=query)["result"]:
        svc = r["metric"].get("service_name", "?")
        if svc in BLOCKED_SERVICES:
            continue
        if r["value"][1] not in BAD:
            out[svc] = float(r["value"][1])
    return out


def _by_service_and_op(query):
    out = {}
    for r in _prom("query", query=query)["result"]:
        svc = r["metric"].get("service_name", "?")
        op = r["metric"].get("span_name", "?")
        if svc in BLOCKED_SERVICES or _is_blocked_query_or_metric(op):
            continue
        if r["value"][1] not in BAD:
            out[(svc, op)] = float(r["value"][1])
    return out


def _labels(metric):
    return {
        k: v
        for k, v in metric.items()
        if k not in ("__name__", "job", "instance") and not _is_blocked_query_or_metric(k)
    }


# ---------- metrics ----------
def list_metrics(match="", limit=40):
    names = [
        n
        for n in _prom("label/__name__/values")
        if match.lower() in n.lower() and not _is_blocked_query_or_metric(n)
    ]
    return {"match": match, "count": len(names), "metrics": names[:limit]}


def metric_query(promql):
    promql = str(promql).strip()
    if len(promql) > 500:
        return {"note": "query too long (max 500 chars)"}
    if _is_blocked_query_or_metric(promql):
        return {"note": "feature-flag metrics are excluded by fair-play rules"}
    res = [
        r
        for r in _prom("query", query=promql)["result"]
        if r["metric"].get("service_name") not in BLOCKED_SERVICES
    ][:10]
    return {
        "query": promql,
        "series": [{"labels": _labels(r["metric"]), "value": r["value"][1]} for r in res],
    }


def metric_trend(promql, minutes=30):
    """Summarise a range query: first/last/min/max and how monotonic the rise is (leak signature)."""
    promql, minutes = str(promql).strip()[:500], _clamp(minutes, 5, 180, 30)
    if _is_blocked_query_or_metric(promql):
        return {"note": "feature-flag metrics are excluded by fair-play rules"}
    end = time.time()
    res = _prom(
        "query_range",
        query=promql,
        start=end - minutes * 60,
        end=end,
        step=max(15, minutes),
    )["result"]
    rows = []
    for r in res:
        if r["metric"].get("service_name") in BLOCKED_SERVICES:
            continue
        v = [float(x[1]) for x in r["values"] if x[1] not in BAD]
        if len(v) < 3:
            continue
        rows.append({
            "series": _labels(r["metric"]),
            "first": round(v[0], 3),
            "last": round(v[-1], 3),
            "min": round(min(v), 3),
            "max": round(max(v), 3),
            "change_ratio": round(v[-1] / v[0], 2) if v[0] else None,
            "monotonic_up_share": round(sum(b >= a for a, b in zip(v, v[1:])) / (len(v) - 1), 2),
        })
    rows.sort(key=lambda d: -abs(d["last"] - d["first"]) / (abs(d["first"]) + 1e-9))
    return {"query": promql, "window_min": minutes, "series": rows[:5]}


# ---------- containers and logs ----------
def container_health():
    ids = _run(COMPOSE + ["ps", "-a", "-q"]).split()
    if not ids:
        return {"note": "no containers found; check DEMO_DIR / COMPOSE_ARGS"}
    info = json.loads(_run(["docker", "inspect", *ids]))
    stats = {}
    try:
        for line in _run(["docker", "stats", "--no-stream", "--format", "{{json .}}", *ids], 40).splitlines():
            d = json.loads(line)
            stats[d["ID"][:12]] = d
    except Exception:
        pass

    def pct(s):
        s = (s or "").strip("%")
        return float(s) if s.replace(".", "", 1).isdigit() else 0.0

    out = {"total": 0, "running": [], "not_running": [], "restarts_or_oom": [], "hot": [], "cpu_limited": []}
    for c in info:
        st, hc = c["State"], c["HostConfig"]
        svc = c["Config"]["Labels"].get("com.docker.compose.service", c["Name"].strip("/"))
        if svc in BLOCKED_SERVICES:
            continue
        out["total"] += 1
        s = stats.get(c["Id"][:12], {})
        cpu, mem = pct(s.get("CPUPerc")), pct(s.get("MemPerc"))
        if st["Status"] == "running":
            out["running"].append(svc)
        if st["Status"] != "running":
            out["not_running"].append({
                "service": svc,
                "state": st["Status"],
                "exit_code": st.get("ExitCode"),
                "oom_killed": st.get("OOMKilled"),
            })
        if c.get("RestartCount") or st.get("OOMKilled"):
            out["restarts_or_oom"].append({
                "service": svc,
                "restarts": c.get("RestartCount"),
                "oom_killed": st.get("OOMKilled"),
            })
        if cpu > 70 or mem > 70:
            out["hot"].append({"service": svc, "cpu_pct": cpu, "mem_pct_of_limit": mem})
        if hc.get("NanoCpus"):
            out["cpu_limited"].append({
                "service": svc,
                "cpus": round(hc["NanoCpus"] / 1e9, 2),
                "memory_limit_mb": round(hc["Memory"] / (1024 * 1024), 1) if hc.get("Memory") else None,
            })
    out["running"].sort()
    out["note"] = ("'running' lists every healthy-state container. A service missing from not_running/hot/cpu_limited "
                   "is simply fine; only an entry in not_running means it is down.")
    return out


ERR_RE = re.compile(
    r"error|exception|fail|refused|timeout|timed out|unavailable|oom|out of memory|"
    r"panic|fatal|deadline|reset by peer|unreachable|traceback",
    re.I,
)


def get_logs(service, minutes=10, limit=6):
    """Recent error-looking log lines for a service, grouped into patterns with counts."""
    if service in BLOCKED_SERVICES:
        return {"note": "flag service logs are not available to the agent"}
    if not SERVICE_RE.match(str(service)):
        return {"note": f"invalid service name {service!r}"}
    minutes, limit = _clamp(minutes, 1, 60, 10), _clamp(limit, 1, 10, 6)
    raw = _run(COMPOSE + ["logs", "--no-color", "--since", f"{minutes}m", service], 40).splitlines()
    pats, ex, n_err = Counter(), {}, 0
    for line in raw:
        line = line.split("|", 1)[-1].strip()
        if _is_blocked_query_or_metric(line):
            continue
        if ERR_RE.search(line):
            n_err += 1
            key = re.sub(r"[0-9a-f]{8,}|\d+", "#", line)[:120]
            pats[key] += 1
            ex.setdefault(key, line[:160])
    return {
        "service": service,
        "window_min": minutes,
        "lines": len(raw),
        "error_lines": n_err,
        "top_patterns": [{"count": n, "example": ex[k]} for k, n in pats.most_common(limit)],
    }


# ---------- topology / deploys ----------
def topology(service):
    return {
        "service": service,
        "calls": sorted({b for a, b in EDGES if a == service}),
        "called_by": sorted({a for a, b in EDGES if b == service}),
    }


def deploy_history(minutes=120):
    minutes = _clamp(minutes, 1, 1440, 120)
    url = os.environ.get("DEPLOY_HISTORY_URL")
    if url:
        return requests.get(url, params={"minutes": minutes}, timeout=10).json()
    commits = []
    try:
        git_out = _run(["git", "log", f"--since={minutes} minutes ago", "-n", "10", "--oneline"])
        commits = [
            line for line in git_out.splitlines()
            if not fairplay.is_blocked_text(line)
        ]
    except Exception:
        pass
    audit_file = Path(__file__).resolve().parent / "logs" / "audit.jsonl"
    recent_actions = []
    if audit_file.exists():
        try:
            for line in audit_file.read_text(encoding="utf-8").splitlines()[-10:]:
                entry = json.loads(line)
                if entry.get("event") in ("action_executed", "action_rolled_back"):
                    recent_actions.append(entry)
        except Exception:
            pass
    return {"window_min": minutes, "recent_git_commits": commits, "recent_agent_actions": recent_actions}


# ---------- triage: one cheap scan across ALL signals and ALL services ----------
def triage(window_min=5, baseline_offset_min=30):
    """Compare the last window against an earlier baseline for every service and operation."""
    window_min = _clamp(window_min, 1, 30, 5)
    baseline_offset_min = _clamp(baseline_offset_min, 5, 240, 30)
    w, off = f"{window_min}m", f"{baseline_offset_min}m"
    srv = '{span_kind="SPAN_KIND_SERVER"'
    notes, anomalies = [], []

    def rate(extra, offset=""):
        return f'sum by (service_name)(rate({CALLS}{srv}{extra}}}[{w}] {("offset " + off) if offset else ""}))'

    def op_rate(extra, offset=""):
        return f'sum by (service_name, span_name)(rate({CALLS}{{{extra}}}[{w}] {("offset " + off) if offset else ""}))'

    def op_count(extra):
        return f'sum by (service_name, span_name)(increase({CALLS}{{{extra}}}[{w}]))'

    def p95(offset=""):
        return (
            f"histogram_quantile(0.95, sum by (le, service_name)(rate({DUR}{srv}}}[{w}] "
            f'{("offset " + off) if offset else ""})))'
        )

    try:
        r_now, r_base = _by_service(rate("")), _by_service(rate("", 1))
        e_now = _by_service(rate(',status_code="STATUS_CODE_ERROR"'))
        e_base = _by_service(rate(',status_code="STATUS_CODE_ERROR"', 1))
        l_now, l_base = _by_service(p95()), _by_service(p95(1))
        if not r_base:
            notes.append("no baseline data (incident may predate the baseline window); using absolute thresholds")
        for svc in set(r_now) | set(r_base):
            if svc in ("load-generator", "?"):
                continue
            rn, rb = r_now.get(svc, 0.0), r_base.get(svc, 0.0)
            en = e_now.get(svc, 0.0) / rn if rn else 0.0
            eb = e_base.get(svc, 0.0) / rb if rb else 0.0
            if rn and en > 0.02 and (not r_base or en - eb > 0.02):
                anomalies.append({
                    "type": "error_rate",
                    "service": svc,
                    "score": round(min(100, en * 100), 1),
                    "detail": f"error rate {en * 100:.1f}% (baseline {eb * 100:.1f}%)",
                })
            ln, lb = l_now.get(svc), l_base.get(svc)
            if ln and ln > 50 and ln > (2 * lb if lb else 300):
                ratio = ln / lb if lb else 10
                anomalies.append({
                    "type": "latency",
                    "service": svc,
                    "score": round(min(100, ratio * 10), 1),
                    "detail": f"p95 {ln:.0f}ms (baseline {lb:.0f}ms)" if lb else f"p95 {ln:.0f}ms",
                })
            if rb > 0.05 and rn < 0.2 * rb:
                anomalies.append({
                    "type": "traffic_drop_or_service_gone",
                    "service": svc,
                    "score": 90.0,
                    "detail": f"request rate {rn:.2f}/s (baseline {rb:.2f}/s)",
                })
            if rb > 0.05 and rn > 3 * rb:
                anomalies.append({
                    "type": "traffic_surge",
                    "service": svc,
                    "score": round(min(100, rn / rb * 10), 1),
                    "detail": f"request rate {rn:.2f}/s (baseline {rb:.2f}/s)",
                })

        # Also check per-operation error rates (catches single-operation failures like CartService/EmptyCart)
        # Counts, not rates: a rarely-called operation (EmptyCart runs only when an order is placed) can fail 100%
        # of the time at well under 0.01 calls/s and must still be detected.
        op_tot = _by_service_and_op(op_count('span_kind="SPAN_KIND_SERVER"'))
        op_err = _by_service_and_op(op_count('span_kind="SPAN_KIND_SERVER",status_code="STATUS_CODE_ERROR"'))
        for (svc, op), err_val in op_err.items():
            if svc in ("load-generator", "?"):
                continue
            tot_val = op_tot.get((svc, op), 0.0)
            if err_val >= 2 and tot_val > 0 and err_val / tot_val >= 0.10:
                op_er = err_val / tot_val
                anomalies.append({
                    "type": "operation_error_rate",
                    "service": svc,
                    "operation": op,
                    "score": round(min(95, op_er * 100), 1),
                    "detail": f"operation {op} error rate {op_er * 100:.1f}%",
                })
    except Exception as e:
        notes.append(
            f"prometheus scan failed: {type(e).__name__}: {e}. Check PROM_URL and span metric names (list_metrics)."
        )

    try:
        c = container_health()
        containers = {k: c[k] for k in ("not_running", "restarts_or_oom", "hot", "cpu_limited") if c.get(k)}
        containers["running_count"] = len(c.get("running", []))
        containers["note"] = "only problem containers are listed; every other container is running"
    except Exception as e:
        containers = {}
        notes.append(f"container scan failed: {e}")
    anomalies.sort(key=lambda a: -a["score"])
    return {"window_min": window_min, "anomalies": anomalies[:12], "containers": containers, "notes": notes}


TOOLS = {
    "triage": triage,
    "container_health": container_health,
    "get_logs": get_logs,
    "list_metrics": list_metrics,
    "metric_query": metric_query,
    "metric_trend": metric_trend,
    "topology": topology,
    "deploy_history": deploy_history,
}


def _spec(name, desc, props=None, required=None):
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": desc,
            "parameters": {
                "type": "object",
                "properties": props or {},
                "required": required or [],
            },
        },
    }


TOOL_SPECS = [
    _spec(
        "triage",
        "FIRST CALL. Scans every service and operation for error-rate, latency and traffic changes versus "
        "a baseline, plus container state (down, restarting, OOM, hot, CPU-limited).",
        {"window_min": {"type": "integer", "default": 5}},
    ),
    _spec("container_health", "Container state, restarts, OOM kills, CPU/memory pressure, CPU limits."),
    _spec(
        "get_logs",
        "Error-looking log lines for one service, grouped into patterns with counts.",
        {"service": {"type": "string"}, "minutes": {"type": "integer", "default": 10}},
        ["service"],
    ),
    _spec(
        "list_metrics",
        "Discover Prometheus metric names containing a substring (e.g. memory, cpu, gc, span_metrics).",
        {"match": {"type": "string"}},
    ),
    _spec("metric_query", "Instant PromQL query (max 10 series).", {"promql": {"type": "string"}}, ["promql"]),
    _spec(
        "metric_trend",
        "Range PromQL summary: first/last/min/max, change ratio and monotonic_up_share "
        "(near 1.0 and a large change_ratio on memory suggests a leak). Use 30+ minutes for leaks.",
        {"promql": {"type": "string"}, "minutes": {"type": "integer", "default": 30}},
        ["promql"],
    ),
    _spec(
        "topology",
        "Static call graph: what a service calls and who calls it.",
        {"service": {"type": "string"}},
        ["service"],
    ),
    _spec(
        "deploy_history",
        "Recent deploys/changes and agent remediation history.",
        {"minutes": {"type": "integer", "default": 120}},
    ),
]
