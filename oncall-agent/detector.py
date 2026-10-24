# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Deterministic incident detector (no LLM): decides WHEN an incident exists and what the alert says.

It reuses ops_tools.triage (per-service AND per-operation error rate, latency, traffic change vs a baseline,
plus container state) and adds the three things a raw scan lacks:
  * persistence  - an anomaly must be seen in `persist` consecutive scans before an incident opens
                   (one noisy scrape never pages anyone)
  * cooldown     - after an incident for a signature, the same signature is ignored for `cooldown_s`
                   (a fault we just handled, or are waiting on, does not reopen endlessly)
  * grouping     - everything that persists is bundled into ONE incident with one alert text

The alert names symptoms it measured (service, operation, number), never a cause.

    python detector.py            # one scan, prints what it sees
"""
import json
import time

import ops_tools

MIN_SCORE = 40.0                       # ignore weak anomalies
SKIP_SERVICES = {"load-generator", "?"}  # traffic source, not a diagnosis target
INFRA_SERVICES = {"grafana", "prometheus", "jaeger", "otel-collector", "opamp-server", "telemetry-docs"}  # observability stack


def signature(a):
    return (a["type"], a["service"], a.get("operation", ""))


def scan(window_min=5):
    """One pass over telemetry. Returns a list of anomaly dicts (type, service, operation?, score, detail)."""
    t = ops_tools.triage(window_min=window_min)  # 5 min still catches rarely-called operations by error count
    ignore = SKIP_SERVICES | INFRA_SERVICES | ops_tools.IGNORED_CONTAINERS
    found = [a for a in t.get("anomalies", []) if a["service"] not in ignore and a.get("score", 0) >= MIN_SCORE]
    c = t.get("containers", {})
    for d in c.get("not_running", []):
        found.append({"type": "container_down", "service": d["service"], "score": 100.0,
                      "detail": f"container {d['service']} is {d.get('state')} (exit code {d.get('exit_code')})"})
    for d in c.get("restarts_or_oom", []):
        found.append({"type": "container_restart", "service": d["service"], "score": 70.0,
                      "detail": f"container {d['service']} restarted {d.get('restarts')}x (OOM killed: {d.get('oom_killed')})"})
    caps = {d["service"]: d.get("cpus") for d in c.get("cpu_limited", [])}
    for d in c.get("hot", []):
        if d["service"] in ignore:
            continue
        # docker stats CPU is per core (a busy service can show 200%), so CPU alone only counts against an explicit cap.
        capped_hot = d["service"] in caps and caps[d["service"]] and d.get("cpu_pct", 0) >= 85 * caps[d["service"]]
        if capped_hot or d.get("mem_pct_of_limit", 0) >= 92:
            found.append({"type": "container_pressure", "service": d["service"], "score": 60.0,
                          "detail": f"container {d['service']} under pressure: cpu {d.get('cpu_pct')}%"
                                    + (f" of a {caps[d['service']]} CPU cap" if capped_hot else "")
                                    + f", memory {d.get('mem_pct_of_limit')}% of limit"})
    blind = [n for n in t.get("notes", []) if "failed" in n]
    if blind and not found:
        found.append({"type": "telemetry_blind", "service": "observability", "score": 60.0, "detail": blind[0][:160]})
    return found


class Detector:
    def __init__(self, persist=2, cooldown_s=600):
        self.persist, self.cooldown_s = persist, cooldown_s
        self.streak = {}
        self.muted_until = {}

    def step(self, found, now=None):
        """Feed one scan. Returns the anomalies that have now persisted long enough (empty list = no incident)."""
        now = time.time() if now is None else now
        seen = {signature(a): a for a in found}
        self.streak = {s: self.streak.get(s, 0) + 1 for s in seen}   # a signature that vanished loses its streak
        ready = [seen[s] for s, n in self.streak.items() if n >= self.persist and self.muted_until.get(s, 0) <= now]
        return rank(ready)

    def mute(self, anomalies, now=None):
        now = time.time() if now is None else now
        for a in anomalies:
            self.muted_until[signature(a)] = now + self.cooldown_s
            self.streak.pop(signature(a), None)


# What hurts users most comes first: a dead container or failing requests outrank slowness and resource pressure.
TYPE_PRIORITY = {"container_down": 0, "operation_error_rate": 1, "error_rate": 1, "traffic_drop_or_service_gone": 2,
                 "container_restart": 3, "traffic_surge": 4, "latency": 5, "container_pressure": 6, "telemetry_blind": 7}


def rank(anomalies):
    return sorted(anomalies, key=lambda a: (TYPE_PRIORITY.get(a["type"], 9), -a.get("score", 0)))


def describe(anomalies, limit=5):
    """Alert text: measured symptoms only, most user-visible first."""
    anomalies = rank(anomalies)
    parts = [f"{a['service']}: {a['detail']}" for a in anomalies[:limit]]
    more = f" (+{len(anomalies) - limit} more)" if len(anomalies) > limit else ""
    return "Detector opened an incident. Symptoms: " + "; ".join(parts) + more


if __name__ == "__main__":
    print(json.dumps(scan(), indent=2))
