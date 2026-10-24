#!/usr/bin/env python3
"""Test bench for the on-call agent: inject a known fault, let the agent handle it, grade its report.

    python testbench/run.py list
    python testbench/run.py run cart-fail                      # you type the approvals (default)
    python testbench/run.py run smoke --operator yes           # the bench types 'yes' for you
    python testbench/run.py run payment-fail+cache-down        # several faults at once
    python testbench/run.py inject net-delay                   # inject only, explore by hand
    python testbench/run.py status | reset
    python testbench/run.py grade path/to/report.json cart-fail

Faults go in through the team injector (faultctl.py, always a subprocess, never imported), a throwaway
netem sidecar for network delay or loss, and a detached killer loop for crash loops. Everything lives outside the agent package, so the agent never sees it.
Results: testbench/results/<run_ts>/ (NN-<scenario>.log and .report.json per scenario, scoreboard.md/.json).
"""
import argparse
import codecs
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from scenarios import SCENARIOS, SUITES, combo_id, describe, expand, expected_text, parse_combo

ROOT = Path(__file__).resolve().parent.parent
RESULTS = Path(__file__).resolve().parent / "results"
NET_STATE = RESULTS / ".net_state.json"
CRASH_STATE = RESULTS / ".crash_state.json"
CRASHLOOP_MAX_S = 45 * 60  # a forgotten crash loop stops by itself
FAULTCTL_STATE = ROOT / ".faultctl_state.json"
PY = sys.executable
FAULTCTL = [PY, "faultctl.py"]
AGENT = [PY, "oncall-agent/agent.py"]
COMPOSE_ARGS = "--env-file .env --env-file .env.override -f compose.yaml -f compose.observability.yaml -f compose.extras.yaml"
NET_IMAGE = os.environ.get("TESTBENCH_NET_IMAGE", "nicolaka/netshoot")
NET_DEV = os.environ.get("TESTBENCH_NET_DEV", "eth0")
NET_GONE = ("cannot delete qdisc", "handle of zero", "no such file or directory", "no such container", "non running container")
YES_LINES = 6
CONFIDENT = {"medium", "high"}
ACCEPTABLE = {"PASS", "ESCALATED_OK"}
VERDICTS = ["PASS", "ESCALATED_OK", "PARTIAL", "FAIL", "WRONG_FIX", "NOT_DETECTED", "AGENT_CRASHED", "INJECT_FAILED", "INTERRUPTED"]
ALIASES = {"redis": "valkeycart", "valkey": "valkeycart", "postgres": "astronomydb", "postgresql": "astronomydb",
           "envoy": "frontendproxy", "locust": "loadgenerator"}
OPERATOR_BANNER = "TEST OPERATOR MODE: approvals are typed by the test bench"


# ------------------------------------------------------------------ console + log file
class Tee:
    """Writes to the console and, while a scenario runs, to its log file."""

    def __init__(self):
        self.file = None

    def open(self, path):
        self.close()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.file = open(path, "a", encoding="utf-8")

    def close(self):
        if self.file:
            self.file.close()
        self.file = None

    def raw(self, text):
        sys.stdout.write(text)
        sys.stdout.flush()
        if self.file:
            self.file.write(text)
            self.file.flush()

    def say(self, msg):
        self.raw(f"[testbench {time.strftime('%H:%M:%S')}] {msg}\n")


LOG = Tee()
say = LOG.say


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def show(cmd):
    return " ".join("python" if c == PY else (f'"{c}"' if " " in c else c) for c in map(str, cmd))


def _env(**extra):
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    env.setdefault("FAULTCTL_COMPOSE_ARGS", COMPOSE_ARGS)  # faultctl's compose calls must see the same stack
    # Back-to-back scenarios would trip the agent's 3-actions-per-hour circuit breaker; real runs keep the default.
    env.setdefault("MAX_ACTIONS_PER_HOUR", "30")
    env.update(extra)
    return env


def run_cmd(cmd, timeout=300, echo=True):
    """Run a short command from the repo root. Returns (returncode, stdout, stderr); never raises."""
    if echo:
        say("$ " + show(cmd))
    try:
        p = subprocess.run(cmd, cwd=ROOT, env=_env(), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        rc, out, err = p.returncode, p.stdout or "", p.stderr or ""
    except (OSError, subprocess.TimeoutExpired) as e:
        rc, out, err = -1, "", f"{type(e).__name__}: {e}"
    if echo:
        for line in (out + err).strip().splitlines():
            LOG.raw(f"    {line}\n")
    return rc, out, err


# ------------------------------------------------------------------ fault injection
def net_cmd(container, op, delay=None, jitter=None, loss=None):
    """netem on a container's own network namespace via a throwaway sidecar (op: replace | del)."""
    cmd = ["docker", "run", "--rm", "--net", f"container:{container}", "--cap-add", "NET_ADMIN", NET_IMAGE,
           "tc", "qdisc", op, "dev", NET_DEV, "root"]
    if op == "del":
        return cmd
    return cmd + ["netem"] + (["delay", delay] + ([jitter] if jitter else []) if delay else []) + (["loss", loss] if loss else [])


def fault_cmd(spec, restart_flagd=True):
    k = spec["kind"]
    if k == "flag":
        return FAULTCTL + ["inject", "--flag", spec["flag"], "--variant", spec["variant"]] + (["--restart-flagd"] if restart_flagd else [])
    if k == "stop":
        return FAULTCTL + ["inject", "--stop", spec["service"]]
    if k == "starve":
        return FAULTCTL + ["inject", "--starve", spec["service"], "--cpus", str(spec["cpus"])] + (["--memory", spec["memory"]] if spec.get("memory") else [])
    if k == "net":
        return net_cmd(spec["service"], "replace", spec.get("delay"), spec.get("jitter"), spec.get("loss"))
    if k == "crashloop":
        return [PY, "testbench/run.py", "_crashloop", spec["service"], str(spec["every_s"])]
    raise ValueError(f"unknown inject kind {k!r}")


# ------------------------------------------------------------------ crash loop (an external killer + the restart policy)
def load_crash():
    try:
        return json.loads(CRASH_STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_crash(state):
    CRASH_STATE.parent.mkdir(parents=True, exist_ok=True)
    if state:
        CRASH_STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    else:
        CRASH_STATE.unlink(missing_ok=True)


def start_crashloop(spec):
    """Start the killer loop as a detached process and remember its PID. Returns (cmd, rc)."""
    cmd = fault_cmd(spec)
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    try:
        proc = subprocess.Popen(cmd, cwd=ROOT, env=_env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                creationflags=flags)
    except OSError as e:
        say(f"crash loop failed to start: {e}")
        return cmd, -1
    save_crash({**load_crash(), spec["service"]: {**spec, "pid": proc.pid, "injected_at": now_iso()}})
    return cmd, 0


def crashloop(service, every_s):
    """Kill the service's main process from the host PID namespace, so Docker sees a crash and restarts it."""
    end = time.time() + CRASHLOOP_MAX_S
    while time.time() < end:
        out = subprocess.run(["docker", "inspect", "-f", "{{.State.Pid}}", service], capture_output=True, text=True).stdout.strip()
        if out.isdigit() and int(out) > 0:
            subprocess.run(["docker", "run", "--rm", "--pid=host", NET_IMAGE, "kill", "-9", out], capture_output=True)
        time.sleep(every_s)
    return 0


def clear_crash():
    """Stop every killer loop and make sure its service is running again. True if all are gone."""
    state = load_crash()
    for svc, spec in list(state.items()):
        pid = spec.get("pid")
        if pid:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
            else:
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
        run_cmd(["docker", "start", svc], timeout=120)
        state.pop(svc)
    save_crash(state)
    return not state


def load_net():
    try:
        return json.loads(NET_STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_net(state):
    NET_STATE.parent.mkdir(parents=True, exist_ok=True)
    if state:
        NET_STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    else:
        NET_STATE.unlink(missing_ok=True)


def inject(ids):
    """Inject every fault of a run. Returns (steps, ok)."""
    specs = [SCENARIOS[i]["inject"] for i in ids]
    steps = []
    for n, (sid, spec) in enumerate(zip(ids, specs)):
        if spec["kind"] == "net":  # recorded first, so a crash mid-inject is still cleaned up by reset
            save_net({**load_net(), spec["service"]: {**spec, "injected_at": now_iso()}})
        # The flag service watches its file (fileinfo sync), so no restart: a restart makes every service log
        # connection-refused errors for a few seconds, which looks like a second, fake incident.
        at = now_iso()
        if spec["kind"] == "crashloop":
            cmd, rc = start_crashloop(spec)
        else:
            cmd = fault_cmd(spec, restart_flagd=False)
            rc, _, _ = run_cmd(cmd)
        steps.append({"scenario": sid, "fault": describe(spec), "cmd": show(cmd), "at": at, "rc": rc})
        if rc != 0:
            say(f"injection failed for {sid} (exit {rc})")
            return steps, False
    say("injected: " + "; ".join(s["fault"] for s in steps))
    return steps, True


def clear_net():
    """Remove every netem delay this bench added; state survives crashes. True if all are gone."""
    state = load_net()
    for svc in list(state):
        rc, out, err = run_cmd(net_cmd(svc, "del"), timeout=120)
        if rc == 0 or any(s in (out + err).lower() for s in NET_GONE):  # a recreated container has no qdisc left
            state.pop(svc)
    save_net(state)
    if state:
        say(f"network faults NOT removed (still in {NET_STATE}): {', '.join(state)}")
    return not state


def reset_all():
    """faultctl reset + network cleanup. True if both succeeded."""
    say("reset: restoring flags/services and removing network faults")
    crash_ok = clear_crash()  # first, so nothing kills a service while it is being restored
    rc, _, _ = run_cmd(FAULTCTL + ["reset"])
    return clear_net() and crash_ok and rc == 0


def stale_faults():
    return FAULTCTL_STATE.exists() or bool(load_net()) or bool(load_crash())


# ------------------------------------------------------------------ precheck
def parse_anomalies(text):
    """The JSON list printed by --detect-once; tolerates log lines around it. None if there is none."""
    text = text or ""
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, list) else None
    except ValueError:
        pass
    dec = json.JSONDecoder()
    for m in re.finditer(r"^\s*\[", text, re.M):  # a line that opens a JSON list
        try:
            obj, _ = dec.raw_decode(text, m.end() - 1)
        except ValueError:
            continue
        if isinstance(obj, list):
            return obj
    return None


def wait_clean(timeout=360, every=20):
    """Poll the detector until it reports no anomalies, at most `timeout` seconds."""
    cmd = AGENT + ["--detect-once", "--window", "2"]
    say(f"precheck: waiting for a clean detector scan (max {timeout}s): {show(cmd)}")
    t0 = time.time()
    while True:
        rc, out, err = run_cmd(cmd, timeout=180, echo=False)
        found = parse_anomalies(out) if rc == 0 else None
        waited = round(time.time() - t0)
        if found is None:
            tail = ((err or out).strip().splitlines() or ["no output"])[-1][:200]
            say(f"precheck: detector scan failed (exit {rc}): {tail}; skipping precheck")
            return {"status": "precheck_error", "clean": False, "waited_s": waited, "error": tail}
        if not found:
            say(f"precheck: clean after {waited}s")
            return {"status": "clean", "clean": True, "waited_s": waited}
        seen = ", ".join(f"{a.get('service')}:{a.get('type')}" for a in found[:4] if isinstance(a, dict))
        if waited >= timeout:
            say(f"precheck: still {len(found)} anomalies after {waited}s ({seen}) -> dirty start")
            return {"status": "dirty_start", "clean": False, "waited_s": waited, "anomalies": found}
        say(f"precheck: {len(found)} anomalies ({seen}); waited {waited}/{timeout}s")
        time.sleep(every)


# ------------------------------------------------------------------ agent run
def _stream(pipe):
    """Copy the agent's output to console + log as it arrives (chunks, not lines: input() prompts have no newline)."""
    dec = codecs.getincrementaldecoder("utf-8")("replace")
    while True:
        chunk = pipe.read1(4096)
        if not chunk:
            break
        LOG.raw(dec.decode(chunk))
    LOG.raw(dec.decode(b"", final=True))


def _stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()


def run_agent(report_path, operator="interactive", detect_timeout=420, cap=None):
    """Run the agent once in detect-and-handle mode; returns exit code, duration and the command."""
    cmd = AGENT + ["--detect-and-handle", "--detect-timeout", str(detect_timeout), "--report-json", str(report_path)]
    env, yes = _env(), operator == "yes"
    if yes:
        say("=" * 70)
        say(OPERATOR_BANNER)
        say("=" * 70)
        env["ONCALL_APPROVER"] = "testbench"
    cap = cap or detect_timeout + 1800
    say(f"$ {show(cmd)}   (operator: {operator}, hard cap {cap}s)")
    t0, killed = time.time(), []
    proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdin=subprocess.PIPE if yes else None,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if yes:
        try:
            proc.stdin.write(b"yes\n" * YES_LINES)
            proc.stdin.close()
        except OSError:
            pass
    timer = threading.Timer(cap, lambda: (killed.append(True), proc.kill()))
    timer.daemon = True
    timer.start()
    try:
        _stream(proc.stdout)
        rc = proc.wait()
    except KeyboardInterrupt:
        _stop(proc)
        raise
    finally:
        timer.cancel()
    took = round(time.time() - t0, 1)
    say(f"agent exited with code {rc} after {took}s" + (" (killed: hard cap reached)" if killed else ""))
    return {"cmd": show(cmd), "rc": rc, "duration_s": took, "timed_out": bool(killed), "operator": operator}


def load_report(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


# ------------------------------------------------------------------ grading
def canon(name):
    """Comparable component key: 'Product Catalog Service', 'productcatalogservice', 'product-catalog' -> 'productcatalog'."""
    key = re.sub(r"[^a-z0-9]", "", str(name or "").lower())
    if key.endswith("service") and len(key) > len("service"):
        key = key[: -len("service")]
    return ALIASES.get(key, key)


def same_component(name, accepted):
    """True if a failing_component / target names one of the accepted components."""
    keys = {canon(a) for a in accepted}
    head = re.split(r"[\s(/,:;]", str(name or "").strip(), maxsplit=1)[0]  # 'cart (EmptyCart)' -> 'cart'
    return bool(name) and (canon(name) in keys or canon(head) in keys)


def mentions(text, component):
    """True if free text names the component ('product-catalog', 'product catalog', 'ProductCatalogService')."""
    names = [component] + [a for a, c in ALIASES.items() if c == canon(component)]
    for n in names:
        body = r"[-_ ]?".join(map(re.escape, n.split("-")))
        # whole word, optional 'service' suffix; '-' counts as a word char so 'cart' never matches 'valkey-cart'
        if re.search(rf"(?<![\w-]){body}(?:[-_ ]?service)?(?![\w-])", str(text or ""), re.I):
            return True
    return False


def rounds_of(report):
    """Remediation rounds; a single-round report (no `rounds`) is treated as one round."""
    rounds = report.get("rounds")
    if isinstance(rounds, list) and rounds:
        return [r for r in rounds if isinstance(r, dict)]
    if isinstance(report.get("diagnosis"), dict) and report["diagnosis"]:
        return [{k: report.get(k) for k in ("diagnosis", "action_plan", "execution", "verification")}]
    return []


def round_view(r):
    d, plan, ver = r.get("diagnosis") or {}, r.get("action_plan") or {}, r.get("verification") or {}
    return {
        "component": d.get("failing_component"), "fault_class": d.get("fault_class"),
        "confidence": str(d.get("confidence") or "").lower(),
        "escalate": bool(d.get("escalate_to_human")) or not plan.get("allowed"),
        "action": plan.get("action_type") if plan.get("allowed") else None, "target": plan.get("target"),
        "verified": ver.get("verified") is True,
        "secondary": " ".join(str(s) for s in d.get("secondary_findings") or []),
    }


def tool_calls(report):
    if isinstance(report.get("observations"), list):
        return len(report["observations"])
    per_round = [len(r["observations"]) for r in report.get("rounds") or []
                 if isinstance(r, dict) and isinstance(r.get("observations"), list)]
    return sum(per_round) if per_round else (report.get("timeline") or {}).get("tool_calls_count")


def grade(report, ids):
    """Grade one report against the faults of a run. `report` None means the agent wrote nothing."""
    faults = [SCENARIOS[i] for i in ids]
    g = {"scenario": combo_id(ids), "expected": expected_text(ids), "verdict": "AGENT_CRASHED", "faults": [],
         "rounds": [], "final_status": None, "n_rounds": 0, "tool_calls": None, "notes": []}
    if report is None:
        g["notes"].append("no readable report JSON was written")
        return g
    rounds = [round_view(r) for r in rounds_of(report)]
    status = str(report.get("status") or "")
    escalated_status = "escalat" in status.lower()
    accepted = [c for f in faults for c in f["expect"]["components"]]

    def on_target(r):
        return same_component(r["component"], accepted) or same_component(r["target"], accepted)

    for f in faults:
        exp = f["expect"]
        hits = [(n, r) for n, r in enumerate(rounds, 1) if same_component(r["component"], exp["components"])]
        row = {"id": f["id"], "state": "missed", "round": None, "component": None, "fault_class": None,
               "class_ok": False, "fixed": False, "escalated": False, "outcome_ok": False}
        if hits:
            n, r = max(hits, key=lambda h: (h[1]["verified"], h[1]["fault_class"] in exp["classes"]))
            esc = r["escalate"] or escalated_status
            row.update(state="diagnosed", round=n, component=r["component"], fault_class=r["fault_class"],
                       class_ok=r["fault_class"] in exp["classes"], fixed=r["verified"], escalated=esc,
                       outcome_ok=r["verified"] if exp["outcome"] == "resolve" else (r["verified"] or esc))
            if not row["class_ok"]:
                g["notes"].append(f"{f['id']}: class {r['fault_class']} not in {exp['classes']}")
        elif any(mentions(r["secondary"], c) for r in rounds for c in exp["components"]):
            row["state"] = "mentioned"
        if row["state"] != "diagnosed" or not row["outcome_ok"]:
            g["notes"].append(f"{f['id']}: {row['state']}" + (", not fixed" if row["state"] == "diagnosed" else ""))
        g["faults"].append(row)

    wrong = [(n, r) for n, r in enumerate(rounds, 1) if r["action"] and r["confidence"] in CONFIDENT and not on_target(r)]
    for n, r in wrong:
        g["notes"].append(f"R{n}: {r['action']} on {r['target']} ({r['component']}, {r['confidence']}) is outside {sorted(set(accepted))}")
    if not any(r["component"] for r in rounds):
        verdict = "NOT_DETECTED"
    elif wrong:
        verdict = "WRONG_FIX"
    elif all(f["state"] == "diagnosed" and f["outcome_ok"] for f in g["faults"]):
        verdict = "PASS"
    elif any(f["state"] == "diagnosed" for f in g["faults"]):
        verdict = "PARTIAL"
    elif (escalated_status or any(r["escalate"] for r in rounds)) and not any(
            r["confidence"] in CONFIDENT and not on_target(r) for r in rounds):
        verdict = "ESCALATED_OK"
    else:
        verdict = "FAIL"
    g.update(verdict=verdict, rounds=[{k: v for k, v in r.items() if k != "secondary"} for r in rounds],
             final_status=status or None, n_rounds=len(rounds), tool_calls=tool_calls(report))
    return g


def _epoch(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------ scoreboard
def rounds_text(row):
    parts = []
    for n, r in enumerate(row.get("rounds") or [], 1):
        act = f"{r['action']}({r['target']})" if r.get("action") else "escalate"
        parts.append(f"R{n} {r.get('component')}/{r.get('fault_class')}/{r.get('confidence') or '?'} -> {act}"
                     + (" verified" if r.get("verified") else ""))
    return "; ".join(parts) or "-"


def _cell(v):
    return "-" if v is None or v == "" else str(v).replace("|", "/")


def scoreboard_md(rows, meta):
    lines = [f"# Test bench scoreboard {meta['run_ts']}", "",
             f"Operator: `{meta['operator']}`  Targets: `{' '.join(meta['targets'])}`", "",
             "| # | Scenario | Expected | Verdict | Diagnosis per round | Final status | Duration (s) | Rounds | Tool calls | TTD (s) | Notes |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for n, r in enumerate(rows, 1):
        lines.append("| " + " | ".join(_cell(v) for v in (
            n, r["scenario"], r.get("expected"), r.get("verdict"), rounds_text(r), r.get("final_status"),
            r.get("duration_s"), r.get("n_rounds"), r.get("tool_calls"), r.get("ttd_s"), "; ".join(r.get("notes") or []))) + " |")
    lines += ["", totals_text(rows), ""]
    return "\n".join(lines)


def totals_text(rows):
    counts = {v: sum(r.get("verdict") == v for r in rows) for v in VERDICTS}
    ok = sum(r.get("verdict") in ACCEPTABLE for r in rows)
    return ("Totals: " + ", ".join(f"{v} {c}" for v, c in counts.items() if c)
            + f" | acceptable (PASS + ESCALATED_OK): {ok}/{len(rows)}")


def write_scoreboard(out_dir, rows, meta):
    (out_dir / "scoreboard.json").write_text(json.dumps({**meta, "totals": totals_text(rows), "scenarios": rows},
                                                        indent=2, default=str) + "\n", encoding="utf-8")
    (out_dir / "scoreboard.md").write_text(scoreboard_md(rows, meta), encoding="utf-8")


# ------------------------------------------------------------------ commands
def run_one(row, ids, out_dir, a):
    """precheck -> inject -> settle -> agent -> grade -> reset, filling `row` as it goes."""
    sid = combo_id(ids)
    stem = f"{row['n']:02d}-{sid}"  # numbered, so repeating a scenario in one run never reuses a report
    report_path = out_dir / f"{stem}.report.json"
    row.update(log=str(out_dir / f"{stem}.log"), report=str(report_path))
    LOG.open(row["log"])
    touched = False
    try:
        say(f"=== {sid}: {' + '.join(SCENARIOS[i]['title'] for i in ids)}  (expect {row['expected']})")
        if not a.no_precheck:
            row["precheck"] = wait_clean(a.precheck_timeout)
            if row["precheck"]["status"] != "clean":
                row["notes"].append(row["precheck"]["status"].replace("_", " "))
        touched = True
        row["injections"], ok = inject(ids)
        if not ok:
            row["verdict"] = "INJECT_FAILED"
            return row
        injected_at = time.time()
        if a.settle > 0:
            say(f"settling {a.settle}s before starting the agent")
            time.sleep(a.settle)
        row["agent"] = run_agent(report_path, a.operator, a.detect_timeout, a.agent_timeout)
        report = load_report(report_path)
        notes = row["notes"]
        row.update(grade(report, ids), duration_s=row["agent"]["duration_s"])
        row["notes"] = notes + row["notes"] + (["agent killed at hard cap"] if row["agent"]["timed_out"] else [])
        timeline = (report or {}).get("timeline") or {}
        for key, field in (("ttd_s", "detected_at"), ("ttr_s", "completed_at")):
            t = _epoch(timeline.get(field))
            row[key] = round(t - injected_at) if t else None
        say(f"verdict {row['verdict']}: {rounds_text(row)}  status={row['final_status']}")
        return row
    finally:
        if touched and not a.keep:
            row["reset_ok"] = reset_all()
        LOG.close()


def cmd_run(a):
    runs = expand(a.targets)
    run_ts = time.strftime("%Y%m%d-%H%M%S")
    out_dir = RESULTS / run_ts
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = {"run_ts": run_ts, "operator": a.operator, "targets": a.targets, "settle": a.settle,
            "detect_timeout": a.detect_timeout, "keep": a.keep}
    say(f"{len(runs)} scenario(s): {', '.join(combo_id(r) for r in runs)}  -> {out_dir}")
    if a.operator == "yes":
        say(OPERATOR_BANNER)
    if a.keep and len(runs) > 1:
        say("warning: --keep with several scenarios: faults stack up between scenarios")
    if stale_faults() and not a.keep:
        say("faults from an earlier run are still active; resetting first")
        reset_all()
    rows, code = [], 0
    try:
        for n, ids in enumerate(runs, 1):
            row = {"n": n, "scenario": combo_id(ids), "expected": expected_text(ids), "verdict": None, "notes": []}
            rows.append(row)
            say(f"--- scenario {n}/{len(runs)}")
            run_one(row, ids, out_dir, a)
            write_scoreboard(out_dir, rows, meta)
    except KeyboardInterrupt:
        say("interrupted by Ctrl+C")
        if rows and not rows[-1].get("verdict"):
            rows[-1]["verdict"] = "INTERRUPTED"
        code = 130
    finally:
        LOG.close()
        write_scoreboard(out_dir, rows, meta)
    print("\n" + scoreboard_md(rows, meta))
    print(f"scoreboard: {out_dir / 'scoreboard.md'}")
    return code


def cmd_list(_a):
    print("Single scenarios (expect: components | classes | outcome):")
    for sid, s in SCENARIOS.items():
        e = s["expect"]
        print(f"  {sid:20} {describe(s['inject']):42} {', '.join(e['components'])} | {', '.join(e['classes'])} | {e['outcome']}")
    print("\nSuites:")
    for name, items in SUITES.items():
        print(f"  {name:8} ({len(items)}) {', '.join(items)}")
    print("\nAny '+'-joined list of single ids is a valid target too, e.g. payment-fail+cache-down")
    return 0


def cmd_inject(a):
    runs = expand(a.target)
    if len(runs) != 1:
        sys.exit("inject takes one scenario id or one a+b combo, not a suite")
    _, ok = inject(runs[0])
    print("\nWhen done: python testbench/run.py reset")
    return 0 if ok else 1


def cmd_status(_a):
    run_cmd(FAULTCTL + ["status"])
    net = load_net()
    print("network faults:", json.dumps(net, indent=2) if net else "none")
    crash = load_crash()
    print("crash loops:", json.dumps(crash, indent=2) if crash else "none")
    return 0


def cmd_reset(_a):
    return 0 if reset_all() else 1


def cmd_grade(a):
    g = grade(load_report(a.report), parse_combo(a.scenario))
    if a.json:
        print(json.dumps(g, indent=2, default=str))
    else:
        print(f"{g['scenario']}: {g['verdict']}   expected {g['expected']}   final status {g['final_status']}")
        print(f"  rounds: {rounds_text(g)}")
        for f in g["faults"]:
            print(f"  {f['id']:20} {f['state']:10} round={f['round']} class_ok={f['class_ok']} fixed={f['fixed']} escalated={f['escalated']}")
        for note in g["notes"]:
            print(f"  note: {note}")
    return 0


def build_parser():
    p = argparse.ArgumentParser(description="On-call agent test bench (fault injection + grading)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="show scenarios and suites")
    r = sub.add_parser("run", help="run scenarios end to end")
    r.add_argument("targets", nargs="+", help="scenario id, a+b combo, or suite (smoke, core, combos, all)")
    r.add_argument("--operator", choices=["interactive", "yes"], default="interactive",
                   help="interactive: you type approvals; yes: the bench types 'yes' to every prompt")
    r.add_argument("--settle", type=int, default=60, help="seconds to wait after injecting before starting the agent")
    r.add_argument("--detect-timeout", type=int, default=420, help="passed to the agent: max seconds to wait for an incident")
    r.add_argument("--agent-timeout", type=int, default=None, help="hard cap on one agent run (default: detect-timeout + 1800)")
    r.add_argument("--precheck-timeout", type=int, default=360, help="max seconds to wait for a clean detector scan")
    r.add_argument("--no-precheck", action="store_true", help="skip waiting for a clean detector scan")
    r.add_argument("--keep", action="store_true", help="leave faults in place afterwards (no reset)")
    i = sub.add_parser("inject", help="inject a scenario only (no agent), for manual exploration")
    i.add_argument("target")
    sub.add_parser("status", help="show active faults")
    sub.add_parser("reset", help="undo every fault (faultctl reset + network faults)")
    c = sub.add_parser("_crashloop", help=argparse.SUPPRESS)
    c.add_argument("service")
    c.add_argument("every_s", type=int)
    g = sub.add_parser("grade", help="grade an existing report JSON")
    g.add_argument("report")
    g.add_argument("scenario", help="scenario id or a+b combo the report belongs to")
    g.add_argument("--json", action="store_true", help="print the full grading JSON")
    return p


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    a = build_parser().parse_args(argv)
    try:
        if a.cmd == "_crashloop":
            return crashloop(a.service, a.every_s)
        return {"list": cmd_list, "run": cmd_run, "inject": cmd_inject, "status": cmd_status,
                "reset": cmd_reset, "grade": cmd_grade}[a.cmd](a)
    except ValueError as e:
        print(f"testbench: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
