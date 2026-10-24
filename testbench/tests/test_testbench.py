"""Offline tests for the test bench: no Docker, agent, LLM or live stack. subprocess is always faked.

    python -m unittest discover -s testbench/tests -v
"""
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BENCH = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BENCH))

import run  # noqa: E402
import scenarios  # noqa: E402
from scenarios import COMBOS, SCENARIOS, SUITES  # noqa: E402

REQUIRED = ["payment-fail", "payment-unreachable", "cart-fail", "product-fail", "ad-fail", "ad-cpu", "ad-gc",
            "reco-leak", "email-leak", "traffic-flood", "shipping-slow", "image-slow", "catalog-lock",
            "cache-down", "db-down", "svc-down", "starve", "net-delay"]


def rnd(component, cls="app_error", conf="high", action="toggle_feature_flag", target=None, verified=True,
        escalate=False, secondary=()):
    """One report round in the agent's format."""
    allowed = action is not None
    return {
        "diagnosis": {"failing_component": component, "fault_class": cls, "confidence": conf, "evidence": ["obs-1: x"],
                      "secondary_findings": list(secondary), "escalate_to_human": escalate},
        "action_plan": {"allowed": allowed, "action_type": action, "target": target or component, "parameters": {}},
        "execution": {"executed": allowed},
        "verification": {"verified": verified, "status": "Resolved" if verified else "Failed_Verification_Escalated"} if allowed else None,
    }


def report(*rounds, status="Resolved", observations=3):
    return {"status": status, "rounds": list(rounds), "diagnosis": rounds[0]["diagnosis"] if rounds else None,
            "timeline": {"detected_at": "2026-10-23T10:00:00Z", "completed_at": "2026-10-23T10:05:00Z"},
            "observations": [{"id": f"obs-{i}"} for i in range(observations)]}


# ------------------------------------------------------------------ catalogue
class ScenarioTests(unittest.TestCase):
    def test_required_scenarios_are_well_formed(self):
        for sid in REQUIRED:
            self.assertIn(sid, SCENARIOS)
        for sid, s in SCENARIOS.items():
            self.assertEqual(s["id"], sid)
            self.assertIn(s["inject"]["kind"], scenarios.INJECT_KINDS, sid)
            self.assertTrue(s["expect"]["components"], sid)
            self.assertTrue(set(s["expect"]["classes"]) <= set(scenarios.FAULT_CLASSES), sid)
            self.assertIn(s["expect"]["outcome"], scenarios.OUTCOMES, sid)
        self.assertEqual(SCENARIOS["net-delay"]["expect"]["outcome"], "escalate")

    def test_flags_and_variants_exist_in_the_demo_flag_file(self):
        path = BENCH.parent / "src" / "flagd" / "demo.flagd.json"
        if not path.exists():
            self.skipTest("demo flag file not found")
        flags = json.loads(path.read_text(encoding="utf-8"))["flags"]
        for sid, s in SCENARIOS.items():
            spec = s["inject"]
            if spec["kind"] == "flag":
                self.assertIn(spec["flag"], flags, sid)
                self.assertIn(spec["variant"], flags[spec["flag"]]["variants"], sid)

    def test_suites(self):
        self.assertEqual(SUITES["smoke"], ["cart-fail", "payment-fail", "svc-down"])
        self.assertEqual(SUITES["all"], list(SCENARIOS) + COMBOS)
        for name, items in SUITES.items():
            for item in items:
                scenarios.parse_combo(item)  # raises on a bad id

    def test_parse_combo(self):
        self.assertEqual(scenarios.parse_combo("cart-fail"), ["cart-fail"])
        self.assertEqual(scenarios.parse_combo(" payment-fail + cache-down "), ["payment-fail", "cache-down"])
        for bad in ("nope", "cart-fail+nope", "cart-fail+cart-fail", "", "cart-fail+", "+"):
            with self.assertRaises(ValueError, msg=bad):
                scenarios.parse_combo(bad)

    def test_expand(self):
        self.assertEqual(scenarios.expand("smoke"), [["cart-fail"], ["payment-fail"], ["svc-down"]])
        self.assertEqual(scenarios.expand(["ad-fail+svc-down", "cart-fail"]), [["ad-fail", "svc-down"], ["cart-fail"]])
        self.assertEqual(len(scenarios.expand("all")), len(SCENARIOS) + len(COMBOS))
        with self.assertRaises(ValueError):
            scenarios.expand(["smoke", "bogus"])

    def test_describe_and_expected_text(self):
        self.assertEqual(scenarios.describe(SCENARIOS["payment-fail"]["inject"]), "flag paymentFailure=100%")
        self.assertEqual(scenarios.describe(SCENARIOS["starve"]["inject"]), "starve recommendation cpus=0.05")
        self.assertEqual(scenarios.expected_text(["payment-fail", "net-delay"]), "payment/resolve + cart/escalate")


# ------------------------------------------------------------------ grading
class GradeTests(unittest.TestCase):
    def test_component_matching(self):
        self.assertTrue(run.same_component("productcatalogservice", ["product-catalog"]))
        self.assertTrue(run.same_component("Product Catalog", ["product-catalog"]))
        self.assertTrue(run.same_component("cart (EmptyCart)", ["cart"]))
        self.assertTrue(run.same_component("redis", ["valkey-cart"]))
        self.assertFalse(run.same_component("valkey-cart", ["cart"]))
        self.assertFalse(run.same_component("cart", ["valkey-cart"]))
        self.assertFalse(run.same_component(None, ["cart"]))
        self.assertTrue(run.mentions("checkout errors are caused by ProductCatalogService", "product-catalog"))
        self.assertTrue(run.mentions("the valkey-cart container is not running", "valkey-cart"))
        self.assertFalse(run.mentions("the valkey-cart container is not running", "cart"))

    def test_single_fault_pass(self):
        g = run.grade(report(rnd("payment")), ["payment-fail"])
        self.assertEqual(g["verdict"], "PASS")
        self.assertEqual((g["n_rounds"], g["tool_calls"], g["final_status"]), (1, 3, "Resolved"))
        self.assertEqual(g["faults"][0]["round"], 1)
        self.assertTrue(g["faults"][0]["class_ok"])

    def test_pass_with_wrong_class_is_noted(self):
        g = run.grade(report(rnd("payment", cls="dependency_down")), ["payment-fail"])
        self.assertEqual(g["verdict"], "PASS")
        self.assertFalse(g["faults"][0]["class_ok"])
        self.assertTrue(any("class dependency_down" in n for n in g["notes"]))

    def test_legacy_single_round_report(self):
        r = rnd("cart")
        legacy = {"status": "Resolved", **r, "timeline": {"tool_calls_count": 7}}
        g = run.grade(legacy, ["cart-fail"])
        self.assertEqual((g["verdict"], g["n_rounds"], g["tool_calls"]), ("PASS", 1, 7))

    def test_diagnosed_but_not_fixed_is_partial(self):
        g = run.grade(report(rnd("cart", verified=False), status="Rejected"), ["cart-fail"])
        self.assertEqual(g["verdict"], "PARTIAL")

    def test_confident_wrong_fix(self):
        g = run.grade(report(rnd("frontend", conf="medium", action="restart_service")), ["cart-fail"])
        self.assertEqual(g["verdict"], "WRONG_FIX")
        self.assertTrue(any("restart_service on frontend" in n for n in g["notes"]))

    def test_wrong_extra_fix_beats_pass(self):
        g = run.grade(report(rnd("cart"), rnd("checkout", action="restart_service")), ["cart-fail"])
        self.assertEqual(g["verdict"], "WRONG_FIX")

    def test_low_confidence_escalation_is_ok(self):
        r = rnd("unknown", cls="unknown", conf="low", action=None, escalate=True)
        g = run.grade(report(r, status="Escalated"), ["cart-fail"])
        self.assertEqual(g["verdict"], "ESCALATED_OK")

    def test_confident_wrong_escalation_fails(self):
        r = rnd("frontend", conf="high", action=None, escalate=True)
        self.assertEqual(run.grade(report(r, status="Escalated"), ["cart-fail"])["verdict"], "FAIL")

    def test_escalate_scenario_passes_when_escalated_with_right_component(self):
        r = rnd("cart", cls="network_degradation", conf="medium", action=None, escalate=True)
        g = run.grade(report(r, status="Escalated"), ["net-delay"])
        self.assertEqual(g["verdict"], "PASS")
        self.assertTrue(g["faults"][0]["escalated"])

    def test_escalate_scenario_also_passes_when_fixed(self):
        g = run.grade(report(rnd("cart", cls="network_degradation", action="restart_service")), ["net-delay"])
        self.assertEqual(g["verdict"], "PASS")

    def test_combo_pass_and_partial(self):
        ids = ["payment-fail", "cache-down"]
        both = report(rnd("valkey-cart", cls="dependency_down", action="restart_service"), rnd("payment"))
        g = run.grade(both, ids)
        self.assertEqual(g["verdict"], "PASS")
        self.assertEqual([f["round"] for f in g["faults"]], [2, 1])

        one = report(rnd("payment", secondary=["valkey-cart container is not running"]), status="Partially_Resolved")
        g = run.grade(one, ids)
        self.assertEqual(g["verdict"], "PARTIAL")
        self.assertEqual([f["state"] for f in g["faults"]], ["diagnosed", "mentioned"])

    def test_best_round_is_used(self):
        g = run.grade(report(rnd("cart", verified=False), rnd("cart")), ["cart-fail"])
        self.assertEqual((g["verdict"], g["faults"][0]["round"]), ("PASS", 2))

    def test_missing_report_and_no_incident(self):
        self.assertEqual(run.grade(None, ["cart-fail"])["verdict"], "AGENT_CRASHED")
        self.assertEqual(run.grade({"status": "No_Incident"}, ["cart-fail"])["verdict"], "NOT_DETECTED")

    def test_defensive_against_odd_shapes(self):
        odd = {"status": None, "rounds": [{"diagnosis": None, "action_plan": None}, "junk"], "observations": "x"}
        self.assertIn(run.grade(odd, ["cart-fail"])["verdict"], run.VERDICTS)

    def test_parse_anomalies(self):
        self.assertEqual(run.parse_anomalies("[]\n"), [])
        self.assertEqual(run.parse_anomalies('[WATCH] hi\n[\n {"type": "x"}\n]\n'), [{"type": "x"}])
        self.assertIsNone(run.parse_anomalies("usage: agent.py ...\nerror: unrecognized arguments"))

    def test_scoreboard(self):
        row = {**run.grade(report(rnd("payment")), ["payment-fail"]), "duration_s": 12.5, "ttd_s": 40}
        md = run.scoreboard_md([row], {"run_ts": "t", "operator": "yes", "targets": ["payment-fail"]})
        self.assertIn("| 1 | payment-fail | payment/resolve | PASS | R1 payment/app_error/high -> toggle_feature_flag(payment) verified |", md)
        self.assertIn("acceptable (PASS + ESCALATED_OK): 1/1", md)


# ------------------------------------------------------------------ runner (subprocess faked)
class FakeStdin:
    def __init__(self):
        self.data = b""

    def write(self, b):
        self.data += b

    def close(self):
        pass


class FakePopen:
    """Stands in for the agent process: writes a report to --report-json and prints an approval prompt."""
    instances = []
    report = None

    def __init__(self, cmd, **kw):
        self.cmd, self.kw, self.returncode = cmd, kw, 0
        self.stdin = FakeStdin() if kw.get("stdin") == subprocess.PIPE else None
        self.stdout = io.BytesIO("investigating…\nApprove execution? Type 'yes', 'dry-run' or 'no': ".encode())
        if FakePopen.report is not None:
            Path(cmd[cmd.index("--report-json") + 1]).write_text(json.dumps(FakePopen.report), encoding="utf-8")
        FakePopen.instances.append(self)

    def wait(self, timeout=None):
        return 0

    def poll(self):
        return 0

    def kill(self):
        pass

    terminate = kill


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        tmp = Path(self.tmp.name)
        self.calls, self.outputs = [], {}
        FakePopen.instances, FakePopen.report = [], None
        patches = [
            mock.patch.object(run.subprocess, "run", side_effect=self.fake_run),
            mock.patch.object(run.subprocess, "Popen", FakePopen),
            mock.patch.object(run.time, "sleep"),
            mock.patch.object(run, "RESULTS", tmp / "results"),
            mock.patch.object(run, "NET_STATE", tmp / "results" / ".net_state.json"),
            mock.patch.object(run, "FAULTCTL_STATE", tmp / ".faultctl_state.json"),
            contextlib.redirect_stdout(io.StringIO()),
        ]
        for p in patches:
            p.__enter__()
            self.addCleanup(p.__exit__, None, None, None)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(run.LOG.close)

    def fake_run(self, cmd, **kw):
        self.calls.append([str(c) for c in cmd])
        self.assertEqual(Path(kw["cwd"]), run.ROOT)
        self.assertIn("FAULTCTL_COMPOSE_ARGS", kw["env"])
        for key, (rc, out) in self.outputs.items():
            if key in cmd:
                return subprocess.CompletedProcess(cmd, rc, out, "")
        return subprocess.CompletedProcess(cmd, 0, "[]" if "--detect-once" in cmd else "ok\n", "")

    def tail(self, cmd):
        """Command without the interpreter path, for readable assertions."""
        return cmd[1:] if cmd[0] == run.PY else cmd

    def test_inject_commands_never_restart_flagd(self):
        steps, ok = run.inject(["payment-fail", "ad-fail", "cache-down", "starve"])
        self.assertTrue(ok)
        self.assertEqual([self.tail(c) for c in self.calls], [
            ["faultctl.py", "inject", "--flag", "paymentFailure", "--variant", "100%"],
            ["faultctl.py", "inject", "--flag", "adFailure", "--variant", "on"],
            ["faultctl.py", "inject", "--stop", "valkey-cart"],
            ["faultctl.py", "inject", "--starve", "recommendation", "--cpus", "0.05"],
        ])
        self.assertEqual(steps[0]["cmd"], "python faultctl.py inject --flag paymentFailure --variant 100%")

    def test_net_fault_is_tracked_and_removed(self):
        run.inject(["net-delay"])
        self.assertEqual(self.calls[0], ["docker", "run", "--rm", "--net", "container:cart", "--cap-add", "NET_ADMIN",
                                         run.NET_IMAGE, "tc", "qdisc", "replace", "dev", "eth0", "root",
                                         "netem", "delay", "400ms", "50ms"])
        self.assertIn("cart", run.load_net())
        self.assertTrue(run.reset_all())
        self.assertEqual(self.tail(self.calls[1]), ["faultctl.py", "reset"])
        self.assertEqual(self.calls[2][-6:], ["tc", "qdisc", "del", "dev", "eth0", "root"])
        self.assertEqual(run.load_net(), {})

    def test_net_cleanup_keeps_state_on_unknown_error(self):
        run.save_net({"cart": {"delay": "400ms"}, "shipping": {"delay": "400ms"}})
        self.outputs = {"container:cart": (1, "Error: Cannot delete qdisc with handle of zero."),
                        "container:shipping": (1, "error during connect: docker daemon is not running")}
        self.assertFalse(run.clear_net())
        self.assertEqual(list(run.load_net()), ["shipping"])

    def test_failed_injection_stops_early(self):
        self.outputs = {"--stop": (1, "boom")}
        steps, ok = run.inject(["cache-down", "payment-fail"])
        self.assertFalse(ok)
        self.assertEqual(len(steps), 1)

    def test_precheck_waits_until_clean(self):
        scans = iter([(0, '[{"type": "error_rate", "service": "cart"}]'), (0, "[]")])
        self.fake_run = lambda cmd, **kw: subprocess.CompletedProcess(cmd, *next(scans), "")
        run.subprocess.run.side_effect = self.fake_run
        self.assertEqual(run.wait_clean(360)["status"], "clean")
        self.assertEqual(run.time.sleep.call_count, 1)

    def test_precheck_dirty_start_and_error(self):
        self.outputs = {"--detect-once": (0, '[{"type": "error_rate", "service": "cart"}]')}
        self.assertEqual(run.wait_clean(0)["status"], "dirty_start")
        self.outputs = {"--detect-once": (2, "error: unrecognized arguments: --window")}
        self.assertEqual(run.wait_clean(360)["status"], "precheck_error")

    def test_agent_operator_yes(self):
        res = run.run_agent(Path(self.tmp.name) / "r.json", operator="yes", detect_timeout=420)
        proc = FakePopen.instances[0]
        self.assertEqual(self.tail(proc.cmd), ["oncall-agent/agent.py", "--detect-and-handle", "--detect-timeout", "420",
                                               "--report-json", str(Path(self.tmp.name) / "r.json")])
        self.assertEqual(proc.kw["env"]["ONCALL_APPROVER"], "testbench")
        self.assertEqual(proc.stdin.data, b"yes\n" * run.YES_LINES)
        self.assertEqual(res["rc"], 0)
        out = sys.stdout.getvalue()
        self.assertIn(run.OPERATOR_BANNER, out)
        self.assertIn("Approve execution?", out)  # prompt without newline is still streamed

    def test_agent_interactive_inherits_stdin(self):
        run.run_agent(Path(self.tmp.name) / "r.json")
        proc = FakePopen.instances[0]
        self.assertIsNone(proc.kw["stdin"])
        self.assertNotIn("ONCALL_APPROVER", proc.kw["env"])

    def test_run_combo_end_to_end(self):
        FakePopen.report = report(rnd("valkey-cart", cls="dependency_down", action="restart_service"), rnd("payment"))
        code = run.main(["run", "payment-fail+cache-down", "--operator", "yes", "--settle", "0"])
        self.assertEqual(code, 0)
        out_dir = next((Path(self.tmp.name) / "results").iterdir())
        board = json.loads((out_dir / "scoreboard.json").read_text(encoding="utf-8"))
        row = board["scenarios"][0]
        self.assertEqual((row["verdict"], row["n_rounds"], row["tool_calls"]), ("PASS", 2, 3))
        self.assertTrue((out_dir / "scoreboard.md").exists())
        log = (out_dir / "01-payment-fail+cache-down.log").read_text(encoding="utf-8")
        self.assertIn("Approve execution?", log)
        self.assertIn("faultctl.py inject --stop valkey-cart", log)
        cmds = [" ".join(self.tail(c)) for c in self.calls]
        self.assertEqual(cmds[-1], "faultctl.py reset")  # reset after the scenario
        self.assertTrue(row["reset_ok"])
        self.assertTrue((out_dir / "01-payment-fail+cache-down.report.json").exists())

    def test_repeated_scenario_gets_its_own_files(self):
        FakePopen.report = report(rnd("cart"))
        run.main(["run", "cart-fail", "cart-fail", "--settle", "0", "--no-precheck"])
        out_dir = next((Path(self.tmp.name) / "results").iterdir())
        self.assertTrue((out_dir / "01-cart-fail.log").exists() and (out_dir / "02-cart-fail.log").exists())

    def test_missing_report_is_agent_crashed(self):
        run.main(["run", "cart-fail", "--settle", "0", "--no-precheck"])
        out_dir = next((Path(self.tmp.name) / "results").iterdir())
        row = json.loads((out_dir / "scoreboard.json").read_text(encoding="utf-8"))["scenarios"][0]
        self.assertEqual(row["verdict"], "AGENT_CRASHED")
        self.assertFalse(any("--detect-once" in c for c in self.calls))

    def test_ctrl_c_still_resets_and_writes_scoreboard(self):
        with mock.patch.object(run, "run_agent", side_effect=KeyboardInterrupt):
            code = run.main(["run", "cart-fail", "--settle", "0"])
        self.assertEqual(code, 130)
        self.assertEqual(" ".join(self.tail(self.calls[-1])), "faultctl.py reset")
        out_dir = next((Path(self.tmp.name) / "results").iterdir())
        row = json.loads((out_dir / "scoreboard.json").read_text(encoding="utf-8"))["scenarios"][0]
        self.assertEqual(row["verdict"], "INTERRUPTED")

    def test_keep_skips_reset(self):
        FakePopen.report = report(rnd("cart"))
        run.main(["run", "cart-fail", "--settle", "0", "--keep"])
        self.assertFalse(any("reset" in c for c in self.calls))

    def test_stale_faults_are_reset_before_running(self):
        run.FAULTCTL_STATE.write_text("{}", encoding="utf-8")
        FakePopen.report = report(rnd("cart"))
        run.main(["run", "cart-fail", "--settle", "0", "--no-precheck"])
        self.assertEqual(" ".join(self.tail(self.calls[0])), "faultctl.py reset")

    def test_grade_cli_and_bad_target(self):
        path = Path(self.tmp.name) / "r.json"
        path.write_text(json.dumps(report(rnd("cart"))), encoding="utf-8")
        self.assertEqual(run.main(["grade", str(path), "cart-fail"]), 0)
        self.assertIn("cart-fail: PASS", sys.stdout.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(run.main(["grade", str(path), "smoke"]), 2)
            self.assertEqual(run.main(["run", "nope"]), 2)
        self.assertEqual(self.calls, [])


class InfraFaultTests(unittest.TestCase):
    def test_packet_loss_and_delay_commands(self):
        loss = run.fault_cmd(scenarios.SCENARIOS["net-loss"]["inject"])
        self.assertEqual(loss[-4:], ["root", "netem", "loss", "30%"])
        delay = run.fault_cmd(scenarios.SCENARIOS["net-delay"]["inject"])
        self.assertEqual(delay[-4:], ["netem", "delay", "400ms", "50ms"])
        self.assertNotIn("loss", delay)

    def test_crash_loop_is_detached_tracked_and_cleared(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(run, "CRASH_STATE", Path(tmp) / ".crash_state.json"), \
                mock.patch.object(run.subprocess, "Popen", return_value=mock.Mock(pid=4242)) as popen, \
                mock.patch.object(run, "run_cmd", return_value=(0, "", "")) as rc, \
                mock.patch.object(run.subprocess, "run") as sprun:
            cmd, code = run.start_crashloop(scenarios.SCENARIOS["crash-loop"]["inject"])
            self.assertEqual((code, cmd[-3:]), (0, ["_crashloop", "currency", "45"]))
            self.assertEqual(run.load_crash()["currency"]["pid"], 4242)
            self.assertTrue(run.stale_faults())  # a live crash loop counts as a leftover fault
            self.assertTrue(run.clear_crash())
            self.assertEqual(run.load_crash(), {})
            rc.assert_called_with(["docker", "start", "currency"], timeout=120)
            self.assertTrue(sprun.called)  # the killer process was terminated
            popen.assert_called_once()


if __name__ == "__main__":
    unittest.main()
