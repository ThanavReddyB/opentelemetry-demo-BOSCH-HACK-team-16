"""HTTP API + web UI for the on-call agent.  Run:  python oncall-agent/server.py   ->  http://localhost:5050

Page 1 (/):        Run agent, stop/kill switch, live progress, human approval gate -> redirects to /reports when done.
Page 2 (/reports): Clean, uncluttered dashboard showing the latest report + all previous reports.
"""
import json
import os
import re
import sys
import threading
import time
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from flask import Flask, jsonify, request, send_from_directory

import action_api
import agent  # loads .env
import detector

LOCK = threading.Lock()
S = {"status": "idle", "scan": None, "alert": None, "dry_run": False, "started": 0.0, "pending": None, "report": None,
     "error": None, "watching": False, "feed": [], "incident_id": None}
DECISION = {"event": threading.Event(), "choice": None}


def web_approval(diagnosis, plan, dry_run=False):
    """Same contract as action_api.request_human_approval, but the human answers through /api/approve."""
    if action_api.is_kill_switch_active():
        action_api.log_audit("approval_blocked_by_kill_switch", {"incident_id": plan.get("incident_id")})
        return {"approved": False, "status": "kill_switch_active", "reason": "Kill switch is ON"}
    action_api.log_audit("approval_requested", {"incident_id": plan["incident_id"], "plan": plan, "dry_run": dry_run})
    DECISION["event"].clear()
    DECISION["choice"] = None
    with LOCK:
        S["status"] = "awaiting_approval"
        S["pending"] = {"diagnosis": diagnosis, "plan": plan, "asked_at": time.time(), "ttl": action_api.APPROVAL_TTL_S}
    DECISION["event"].wait(action_api.APPROVAL_TTL_S)
    choice = DECISION["choice"] or "no"
    if choice == "dry-run":
        dry_run, choice = True, "yes"
    decision = {"approved": choice == "yes", "dry_run": dry_run, "decided_at": action_api._now(),
                "decided_epoch": time.time(), "approval_digest": plan["approval_digest"], "consumed": False,
                "operator_input": choice, "approver": os.environ.get("ONCALL_APPROVER") or "ui-operator"}
    action_api.log_audit("approval_decision", {"incident_id": plan["incident_id"], **decision})
    with LOCK:
        S["status"], S["pending"] = "running", None
    return decision


action_api.request_human_approval = web_approval

_orig_say = agent._say
TOOL_RE = re.compile(r"\[step \d+\]\s+(obs-\d+)\s+(\w+)\((.*?)\)\s*->\s*(.*)", re.S)


def _narrate(msg):
    _orig_say(msg)
    m = str(msg).strip()
    if not m:
        return
    ev = {"t": time.strftime("%H:%M:%S"), "kind": "note", "text": m}
    tool = TOOL_RE.match(m)
    if m.startswith("[think]"):
        ev.update(kind="think", text=m[7:].strip())
    elif tool:
        ev.update(kind="tool", id=tool[1], tool=tool[2], args=tool[3], text=tool[4].strip())
    elif m.startswith("[INCIDENT"):
        idm = re.match(r"\[INCIDENT (\S+?)\]", m)
        S["incident_id"] = idm[1] if idm else None
        ev["kind"] = "incident"
    elif m.startswith("[ROUND"):
        ev.update(kind="round", text=re.sub(r"^\[ROUND (\d+)\]\s*", r"Round \1: ", m))
    elif m.startswith("[ESCALATION]"):
        ev["kind"] = "escalate"
    elif m.startswith("[REPORT]"):
        ev["kind"] = "report"
    with LOCK:
        S["feed"].append(ev)


def _long_thought(msg):
    t = " ".join(str(getattr(msg, "reasoning", None) or "").split())
    return t[:700] + ("..." if len(t) > 700 else "")


agent._say, agent._thought = _narrate, _long_thought


def _pipeline(alert, dry_run):
    try:
        while not action_api.is_kill_switch_active():
            agent._LLM = None
            cur_alert = alert
            alert = None
            if cur_alert is None:
                with LOCK:
                    if S["status"] != "healthy":
                        S["status"] = "scanning"
                found = detector.scan()
                scan = {"at": time.strftime("%H:%M:%S"), "alert": detector.describe(found) if found else None,
                        "anomalies": [{k: a.get(k) for k in ("service", "type", "operation", "detail", "score")} for a in found]}
                with LOCK:
                    S["scan"] = scan
                    if not found:
                        S["status"] = "healthy"
                        S["feed"] = []
                        S["alert"] = None
                        S["pending"] = None
                        S["started"] = time.time()
                if not found:
                    for _ in range(10):
                        if action_api.is_kill_switch_active():
                            break
                        time.sleep(1)
                    continue
                cur_alert = scan["alert"]
            if action_api.is_kill_switch_active():
                break
            with LOCK:
                S["status"], S["alert"], S["feed"], S["pending"], S["error"], S["started"] = "running", cur_alert, [], None, None, time.time()
            out = agent.run_full_incident_loop(cur_alert, dry_run=dry_run, verbose=True)
            with LOCK:
                S["report"] = json.loads(json.dumps(out, default=str))
                S["status"] = "healthy"
                S["feed"] = []
                S["alert"] = None
                S["pending"] = None
                S["started"] = time.time()
                S["scan"] = {"at": time.strftime("%H:%M:%S"), "alert": None, "anomalies": []}
            for _ in range(15):
                if action_api.is_kill_switch_active():
                    break
                time.sleep(1)
        with LOCK:
            S["status"], S["pending"] = "idle", None
    except Exception as e:  # noqa: BLE001
        with LOCK:
            S["error"], S["status"] = f"{type(e).__name__}: {e}", "error"


def _start(alert, dry_run):
    with LOCK:
        if S["status"] not in ("idle", "done", "error", "healthy"):
            return False
        S.update(status="scanning" if alert is None else "running", alert=alert, dry_run=dry_run, started=time.time(), scan=None,
                 report=None, error=None, pending=None, feed=[], incident_id=None)
    threading.Thread(target=_pipeline, args=(alert, dry_run), daemon=True).start()
    return True


def _watch_loop():
    det = detector.Detector(persist=2, cooldown_s=600)
    while S["watching"]:
        try:
            if S["status"] in ("idle", "done", "error", "healthy") and not action_api.is_kill_switch_active():
                ready = det.step(detector.scan())
                if ready and _start(detector.describe(ready), S["dry_run"]):
                    det.mute(ready)
        except Exception:  # noqa: BLE001
            pass
        time.sleep(20)


def _audit_since(t0):
    if not action_api.AUDIT_LOG_FILE.exists():
        return [], None
    rows, diag = [], None
    for line in action_api.AUDIT_LOG_FILE.read_text(encoding="utf-8").splitlines()[-300:]:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("ts_epoch", 0) < t0:
            continue
        if e.get("event") == "incident_diagnosed":
            diag = e.get("diagnosis")
        rows.append({"t": e.get("timestamp"), "event": e.get("event"), "status": e.get("status"), "choice": e.get("operator_input"),
                     "approver": e.get("approver"), "detail": e.get("detail") or e.get("reason") or e.get("target")})
    return rows, diag


def _load_all_reports():
    reports_dir = action_api.REPORTS_DIR
    if not reports_dir.exists():
        return []
    items = []
    for p in sorted(reports_dir.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
        try:
            r = json.loads(p.read_text(encoding="utf-8"))
            if "diagnosis" not in r and "fault_class" in r:
                r = {
                    "incident_id": r.get("incident_id", p.stem),
                    "status": "Diagnosed_Only",
                    "alert": r.get("alert", ""),
                    "timeline": {"detected_at": "", "completed_at": "", "tool_calls_count": 0, "rounds": 1},
                    "diagnosis": r,
                    "rounds": [{"round": 1, "diagnosis": r, "observations": []}],
                    "prevention_recommendation": [],
                }
            items.append(r)
        except Exception:  # noqa: BLE001
            continue
    return items


app = Flask(__name__)


@app.get("/")
def index():
    return send_from_directory(AGENT_DIR / "ui", "index.html")


@app.get("/reports")
def reports_page():
    return send_from_directory(AGENT_DIR / "ui", "reports.html")


@app.get("/styles.css")
def styles():
    return send_from_directory(AGENT_DIR / "ui", "styles.css")


@app.get("/api/state")
def state():
    with LOCK:
        s = {**S, "feed": list(S["feed"])}
    rows, diag = _audit_since(s["started"]) if s["started"] else ([], None)
    return jsonify({**s, "audit": rows, "diagnosis": diag, "kill_switch": action_api.is_kill_switch_active()})


@app.get("/api/reports")
def api_reports():
    all_reports = _load_all_reports()
    counts = {
        "total": len(all_reports),
        "resolved": sum(1 for r in all_reports if r.get("status") == "Resolved"),
        "simulated": sum(1 for r in all_reports if r.get("status") == "Simulated"),
        "escalated": sum(1 for r in all_reports if r.get("status") not in ("Resolved", "Simulated")),
    }
    return jsonify({"counts": counts, "reports": all_reports})


@app.post("/api/incident")
def incident():
    b = request.get_json(silent=True) or {}
    alert = (b.get("alert") or "").strip() or None
    return (jsonify(ok=True), 202) if _start(alert, bool(b.get("dry_run"))) else (jsonify(ok=False, error="an incident is already running"), 409)


@app.post("/api/approve")
def approve():
    b = request.get_json(silent=True) or {}
    with LOCK:
        pend = S["pending"]
    if not pend:
        return jsonify(ok=False, error="nothing awaiting approval"), 409
    if b.get("digest") != pend["plan"]["approval_digest"] or b.get("choice") not in ("yes", "no", "dry-run"):
        return jsonify(ok=False, error="digest mismatch or bad choice"), 400
    DECISION["choice"] = b["choice"]
    DECISION["event"].set()
    return jsonify(ok=True)


@app.post("/api/kill")
def kill():
    on = bool((request.get_json(silent=True) or {}).get("active"))
    out = action_api.set_kill_switch(on, "UI kill switch" if on else "UI release")
    if on:
        DECISION["choice"] = "no"
        DECISION["event"].set()
    return jsonify(out)


@app.post("/api/watch")
def watch():
    b = request.get_json(silent=True) or {}
    on = bool(b.get("on"))
    with LOCK:
        was, S["watching"], S["dry_run"] = S["watching"], on, bool(b.get("dry_run"))
    if on and not was:
        threading.Thread(target=_watch_loop, daemon=True).start()
    return jsonify(watching=on)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("UI_PORT", "5050")), threaded=True)
