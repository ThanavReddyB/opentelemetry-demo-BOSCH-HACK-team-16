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
import shutil
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

import fairplay


def _docker_bin():
    """docker on PATH, or Docker Desktop's default location when a shell hides it from Python."""
    found = os.environ.get("DOCKER_BIN") or shutil.which("docker")
    default = Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe")
    return found or (str(default) if default.exists() else "docker")


DOCKER = _docker_bin()

REPO_ROOT = Path(__file__).resolve().parent.parent
PROM = os.environ.get("PROM_URL", "http://localhost:9090").rstrip("/")
CALLS = os.environ.get("SPAN_CALLS_METRIC", "traces_span_metrics_calls_total")
DUR = os.environ.get("SPAN_DURATION_METRIC", "traces_span_metrics_duration_milliseconds_bucket")
DEMO_DIR = Path(os.environ.get("DEMO_DIR", str(REPO_ROOT))).expanduser().resolve()
COMPOSE = [DOCKER, "compose"] + shlex.split(os.environ.get("COMPOSE_ARGS", ""))
BLOCKED_SERVICES = fairplay.BLOCKED_SERVICES
RECENT_RESTART_S = int(os.environ.get("RECENT_RESTART_S", "900"))
# Optional tooling we deliberately do not run on small laptops; their absence is not an incident.
IGNORED_CONTAINERS = set(filter(None, os.environ.get("IGNORED_CONTAINERS", "opensearch,grafana,telemetry-docs").split(",")))
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
    r = requests.get(f"{PROM}/api/v1/{path}", params=params, timeout=30)
    r.raise_for_status()
    return r.json()["data"]


_QCACHE = {}


def _prefetch(queries):
    """Run independent instant queries in parallel; the parsers below pick the results up from the cache."""
    def one(q):
        try:
            return q, _prom("query", query=q)
        except Exception as e:  # noqa: BLE001 - re-raised when the result is read
            return q, e
    with ThreadPoolExecutor(max_workers=6) as ex:
        for q, res in ex.map(one, dict.fromkeys(queries)):
            _QCACHE[q] = res


def _query_result(query):
    res = _QCACHE.pop(query, None)
    if isinstance(res, Exception):
        raise res
    return (res if res is not None else _prom("query", query=query))["result"]


def _is_blocked_query_or_metric(text):
    return fairplay.is_blocked_text(text)


def _clamp(value, lo, hi, default):
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def _by_service(query):
    out = {}
    for r in _query_result(query):
        svc = r["metric"].get("service_name", "?")
        if svc in BLOCKED_SERVICES:
            continue
        if r["value"][1] not in BAD:
            out[svc] = float(r["value"][1])
    return out


def _by_service_and_op(query):
    out = {}
    for r in _query_result(query):
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


CONTAINER_LABEL = os.environ.get("CONTAINER_LABEL", "container_name")


def _trend_query(metric, service):
    """Named trend views, so the model never has to guess metric names or labels."""
    s = str(service or "")
    if not SERVICE_RE.match(s) or s in BLOCKED_SERVICES:
        raise ValueError(f"invalid service {service!r}")
    srv = f'service_name="{s}",span_kind="SPAN_KIND_SERVER"'
    queries = {
        "memory": f'max by ({CONTAINER_LABEL})(container_memory_percent_ratio{{{CONTAINER_LABEL}="{s}"}})',
        "cpu": f'max by ({CONTAINER_LABEL})(container_cpu_utilization_ratio{{{CONTAINER_LABEL}="{s}"}})',
        "request_rate": f"sum(rate({CALLS}{{{srv}}}[1m]))",
        "error_rate": f'sum(rate({CALLS}{{{srv},status_code="STATUS_CODE_ERROR"}}[1m])) / sum(rate({CALLS}{{{srv}}}[1m]))',
        "latency_p95": f"histogram_quantile(0.95, sum by (le)(rate({DUR}{{{srv}}}[1m])))",
    }
    if metric not in queries:
        raise ValueError(f"metric must be one of {sorted(queries)}")
    return queries[metric]


def metric_trend(metric=None, service=None, minutes=30, promql=None):
    """Summarise a range query: first/last/min/max and how monotonic the rise is (leak signature)."""
    try:
        promql = _trend_query(metric, service) if metric else str(promql or "").strip()[:500]
    except ValueError as e:
        return {"note": str(e)}
    if not promql:
        return {"note": "give metric+service (preferred) or promql"}
    minutes = _clamp(minutes, 5, 180, 30)
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
    info = json.loads(_run([DOCKER, "inspect", *ids]))
    stats = _container_stats_from_prometheus()
    if not stats:  # slow path: docker stats takes ~25 s on a loaded laptop
        try:
            for line in _run([DOCKER, "stats", "--no-stream", "--format", "{{json .}}", *ids], 40).splitlines():
                d = json.loads(line)
                stats[d["Name"]] = d
        except Exception:  # noqa: BLE001
            pass

    def pct(s):
        s = (s or "").strip("%")
        return float(s) if s.replace(".", "", 1).isdigit() else 0.0

    out = {"total": 0, "running": [], "not_running": [], "restarts_or_oom": [], "hot": [], "cpu_limited": []}
    for c in info:
        st, hc = c["State"], c["HostConfig"]
        svc = c["Config"]["Labels"].get("com.docker.compose.service", c["Name"].strip("/"))
        if svc in BLOCKED_SERVICES or svc in IGNORED_CONTAINERS:
            continue
        out["total"] += 1
        s = stats.get(c["Name"].strip("/"), {})
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
        # Docker's restart counter never resets, so only a restart in the last 15 minutes is news.
        started = _epoch(st.get("StartedAt"))
        recent = started is not None and time.time() - started <= RECENT_RESTART_S
        if (c.get("RestartCount") and recent) or st.get("OOMKilled"):
            out["restarts_or_oom"].append({
                "service": svc,
                "restarts": c.get("RestartCount"),
                "oom_killed": st.get("OOMKilled"),
                "last_start_min_ago": round((time.time() - started) / 60, 1) if started else None,
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


def _container_stats_from_prometheus():
    """Per-container CPU % (per core, like docker stats) and memory % of limit from the docker_stats receiver."""
    try:
        cpu = {r["metric"].get(CONTAINER_LABEL): r["value"][1] for r in
               _prom("query", query=f"max by ({CONTAINER_LABEL})(container_cpu_utilization_ratio)")["result"]}
        mem = {r["metric"].get(CONTAINER_LABEL): r["value"][1] for r in
               _prom("query", query=f"max by ({CONTAINER_LABEL})(container_memory_percent_ratio)")["result"]}
    except Exception:  # noqa: BLE001
        return {}
    return {n: {"CPUPerc": f"{float(cpu.get(n, 0)):.2f}%", "MemPerc": f"{float(mem.get(n, 0)):.2f}%"} for n in set(cpu) | set(mem) if n}


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


def _epoch(iso):
    """Docker timestamps ('2026-10-23T12:02:03.123456789Z') -> epoch seconds, or None."""
    try:
        return time.mktime(time.strptime(str(iso)[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
    except (ValueError, OverflowError):
        return None


def deploy_history(minutes=120):
    """What changed recently: containers created, (re)started or stopped in the window, plus remediation the agent
    itself executed (action type and target only; never switch names or values)."""
    minutes = _clamp(minutes, 1, 1440, 120)
    url = os.environ.get("DEPLOY_HISTORY_URL")
    if url:
        return requests.get(url, params={"minutes": minutes}, timeout=10).json()
    now, cutoff, changes = time.time(), time.time() - minutes * 60, []
    try:
        ids = _run(COMPOSE + ["ps", "-a", "-q"]).split()
        for c in json.loads(_run([DOCKER, "inspect", *ids])) if ids else []:
            svc = c["Config"]["Labels"].get("com.docker.compose.service", c["Name"].strip("/"))
            if svc in BLOCKED_SERVICES or svc in IGNORED_CONTAINERS:
                continue
            st = c["State"]
            for event, ts in (("created", c.get("Created")), ("started", st.get("StartedAt")),
                              ("stopped", st.get("FinishedAt") if st.get("Status") != "running" else None)):
                t = _epoch(ts)
                if t and t >= cutoff:
                    changes.append({"service": svc, "event": event, "minutes_ago": round((now - t) / 60, 1),
                                    "image": c["Config"].get("Image", "").split("/")[-1][:60]})
    except Exception as e:  # noqa: BLE001
        changes.append({"note": f"container history unavailable: {e}"[:160]})
    audit_file = Path(__file__).resolve().parent / "logs" / "audit.jsonl"
    actions = []
    if audit_file.exists():
        try:
            for line in audit_file.read_text(encoding="utf-8").splitlines()[-200:]:
                e = json.loads(line)
                t = e.get("ts_epoch", 0)
                if e.get("event") in ("action_executed", "action_rolled_back") and t >= cutoff:
                    actions.append({"event": e["event"], "action_type": e.get("action_type"), "target": e.get("target"),
                                    "status": e.get("status"), "minutes_ago": round((now - t) / 60, 1)})
        except Exception:  # noqa: BLE001
            pass
    changes.sort(key=lambda d: d.get("minutes_ago", 1e9))
    return {"window_min": minutes, "container_changes": changes[:15], "recent_agent_actions": actions[-5:],
            "note": "a change shortly before the symptoms began is a suspect; no change is normal"}


def service_rates(window_min=3):
    """Requests/s each service served recently. 3 minutes: a 1-minute rate() often has too few points to exist."""
    w = _clamp(window_min, 2, 30, 3)
    return {svc: round(v, 4) for svc, v in
            _by_service(f'sum by (service_name)(rate({CALLS}{{span_kind="SPAN_KIND_SERVER"}}[{w}m]))').items()}


# ---------- triage: one cheap scan across ALL signals and ALL services ----------
def triage(window_min=5, baseline_offset_min=30):
    """Compare the last window against an earlier baseline for every service and operation."""
    window_min = _clamp(window_min, 1, 30, 5)
    baseline_offset_min = _clamp(baseline_offset_min, 10, 240, 30)
    # Two baseline windows; the healthiest one wins, so one earlier incident cannot poison the comparison.
    offsets = sorted({max(window_min + 5, baseline_offset_min // 2), baseline_offset_min + 15})
    w = f"{window_min}m"
    srv = '{span_kind="SPAN_KIND_SERVER"'
    err = ',status_code="STATUS_CODE_ERROR"'
    notes, anomalies, r_now = [], [], {}

    def rate(extra, offset=0):
        return f'sum by (service_name)(rate({CALLS}{srv}{extra}}}[{w}]{f" offset {offset}m" if offset else ""}))'

    def op_count(extra, offset=0):
        return f'sum by (service_name, span_name)(increase({CALLS}{{{extra}}}[{w}]{f" offset {offset}m" if offset else ""}))'

    def p95(offset=0):
        return (f"histogram_quantile(0.95, sum by (le, service_name)(rate({DUR}{srv}}}[{w}]"
                f'{f" offset {offset}m" if offset else ""})))')

    tot_sel, err_sel = 'span_kind="SPAN_KIND_SERVER"', 'span_kind="SPAN_KIND_SERVER",status_code="STATUS_CODE_ERROR"'
    _prefetch([q for o in [0, *offsets] for q in (rate("", o), rate(err, o), p95(o), op_count(tot_sel, o), op_count(err_sel, o))])
    try:
        r_now, e_now, l_now = _by_service(rate("")), _by_service(rate(err)), _by_service(p95())
        r_bases, e_bases, l_bases = {}, {}, {}
        for o in offsets:
            rb, eb, lb = _by_service(rate("", o)), _by_service(rate(err, o)), _by_service(p95(o))
            for svc, v in rb.items():
                r_bases.setdefault(svc, []).append(v)
                e_bases.setdefault(svc, []).append(eb.get(svc, 0.0) / v if v else 0.0)
            for svc, v in lb.items():
                l_bases.setdefault(svc, []).append(v)
        if not r_bases:
            notes.append("no baseline data (stack younger than the baseline windows); using absolute thresholds")
        for svc in set(r_now) | set(r_bases):
            if svc in ("load-generator", "?"):
                continue
            rbs = sorted(r_bases.get(svc, []))
            rn, rb = r_now.get(svc, 0.0), (rbs[len(rbs) // 2] if rbs else 0.0)
            en = e_now.get(svc, 0.0) / rn if rn else 0.0
            eb = min(e_bases.get(svc, [0.0]))
            if rn and en > 0.02 and (not r_bases or en - eb > 0.02):
                anomalies.append({
                    "type": "error_rate",
                    "service": svc,
                    "score": round(min(100, en * 100), 1),
                    "detail": f"error rate {en * 100:.1f}% (baseline {eb * 100:.1f}%)",
                })
            ln, lb = l_now.get(svc), min(l_bases.get(svc) or [0.0]) or None
            enough = rn * 60 * window_min >= 5   # a p95 over two or three requests is noise, not a signal
            if enough and ln and ln > 50 and ln > (max(2 * lb, lb + 100) if lb else 1000):
                ratio = ln / lb if lb else 10
                anomalies.append({
                    "type": "latency",
                    "service": svc,
                    "score": round(min(100, ratio * 10), 1),
                    "detail": f"p95 {ln:.0f}ms (baseline {lb:.0f}ms)" if lb else f"p95 {ln:.0f}ms",
                })
            if rb > 0.05 and rb * 60 * window_min >= 20 and rn < 0.2 * rb:  # enough expected calls to notice silence
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
        op_tot, op_err = _by_service_and_op(op_count(tot_sel)), _by_service_and_op(op_count(err_sel))
        op_base = {}  # (svc, op) -> healthiest earlier error ratio, so chronic failures are not new incidents
        for o in offsets:
            bt, be = _by_service_and_op(op_count(tot_sel, o)), _by_service_and_op(op_count(err_sel, o))
            for key, t in bt.items():
                if t >= 2:
                    op_base[key] = min(op_base.get(key, 1.0), be.get(key, 0.0) / t)
        for (svc, op), err_val in op_err.items():
            if svc in ("load-generator", "?"):
                continue
            tot_val = op_tot.get((svc, op), 0.0)
            if err_val >= 2 and tot_val > 0 and err_val / tot_val - op_base.get((svc, op), 0.0) >= 0.10:
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
    _QCACHE.clear()
    anomalies.sort(key=lambda a: -a["score"])
    rates = {svc: round(v, 4) for svc, v in r_now.items() if svc != "?"}
    return {"window_min": window_min, "baseline_offsets_min": offsets, "anomalies": anomalies[:12], "service_rates": rates,
            "containers": containers, "notes": notes}


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
        "metric_trend",
        "How one service's metric moved over time: first/last/min/max, change_ratio and monotonic_up_share "
        "(memory with monotonic_up_share near 1.0 and a rising last value = leak). Use 30+ minutes for leaks.",
        {"metric": {"type": "string", "enum": ["memory", "cpu", "request_rate", "error_rate", "latency_p95"]},
         "service": {"type": "string"}, "minutes": {"type": "integer", "default": 30}},
        ["metric", "service"],
    ),
    _spec(
        "topology",
        "Static call graph: what a service calls and who calls it.",
        {"service": {"type": "string"}},
        ["service"],
    ),
    _spec(
        "deploy_history",
        "Recent changes: containers created, restarted or stopped, and remediation the agent already ran.",
        {"minutes": {"type": "integer", "default": 60}},
    ),
]
