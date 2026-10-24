"""Offline tests: no Docker, Prometheus, Jaeger or LLM key needed.

    cd oncall-agent && python -m unittest discover -s tests -v
"""
import builtins
import json
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import action_api  # noqa: E402
import detector  # noqa: E402
import agent  # noqa: E402
import jaeger_tools  # noqa: E402
import ops_tools  # noqa: E402
import registry  # noqa: E402
import remediation_adapters as adapters  # noqa: E402

REAL_SET_FLAG = adapters.set_flag  # keep the real function; ActionApiTests patches the module attribute


# ------------------------------------------------------------------ fair-play guard
class GuardTests(unittest.TestCase):
    EXEMPT = {"fairplay.py", "remediation_adapters.py"}
    INVESTIGATION = ["registry.py", "ops_tools.py", "jaeger_tools.py", "metrics.py", "fairplay.py", "detector.py"]

    def test_no_flag_state_access_outside_allowed_modules(self):
        pat = re.compile(r"flagd|faultctl", re.I)
        for f in ROOT.glob("*.py"):
            if f.name in self.EXEMPT:
                continue
            self.assertIsNone(pat.search(f.read_text(encoding="utf-8")), f"{f.name} mentions flag-service internals")

    def test_investigation_modules_never_import_the_action_layer(self):
        for name in self.INVESTIGATION:
            src = (ROOT / name).read_text(encoding="utf-8")
            self.assertNotIn("remediation_adapters", src, name)
            self.assertNotIn("import action_api", src, name)

    def test_no_auto_approval_and_no_example_env_secrets(self):
        agent_src = (ROOT / "agent.py").read_text(encoding="utf-8")
        api_src = (ROOT / "action_api.py").read_text(encoding="utf-8")
        self.assertNotIn(".env.example", agent_src)
        self.assertNotIn("auto_mode", agent_src + api_src)

    def test_fairplay_filters(self):
        import fairplay
        self.assertTrue(fairplay.is_blocked_service("flagd"))
        self.assertTrue(fairplay.is_blocked_text("flagd.evaluation"))
        self.assertTrue(fairplay.is_blocked_attr("feature_flag.key"))
        self.assertFalse(fairplay.is_blocked_text("CartService/EmptyCart"))
        # connection noise to the flag service (e.g. while it restarts) is plumbing, not a caller fault
        self.assertTrue(fairplay.is_flag_plumbing("connect ECONNREFUSED 172.20.0.5:8013"))
        self.assertTrue(fairplay.is_flag_plumbing("", {"server.port": 8016}))
        self.assertFalse(fairplay.is_flag_plumbing("connect ECONNREFUSED 172.20.0.9:6379", {"server.port": 6379}))
        self.assertFalse(fairplay.is_flag_plumbing("timeout after 80130ms"))


# ------------------------------------------------------------------ jaeger
def otlp_trace():
    def attr(k, v):
        return {"key": k, "value": {"stringValue": v}}
    return {"result": {"resourceSpans": [
        {"resource": {"attributes": [attr("service.name", "frontend")]},
         "scopeSpans": [{"spans": [
             {"traceId": "aa" * 16, "spanId": "01" * 8, "parentSpanId": "", "name": "POST /api/checkout", "kind": 2,
              "startTimeUnixNano": "1000000000", "endTimeUnixNano": "1900000000",
              "status": {"code": 2, "message": "13 INTERNAL"}},
         ]}]},
        {"resource": {"attributes": [attr("service.name", "checkout")]},
         "scopeSpans": [{"spans": [
             {"traceId": "aa" * 16, "spanId": "02" * 8, "parentSpanId": "01" * 8, "name": "PlaceOrder", "kind": "SPAN_KIND_SERVER",
              "startTimeUnixNano": "1100000000", "endTimeUnixNano": "1800000000",
              "status": {"code": "STATUS_CODE_ERROR", "message": "cart failure"}},
         ]}]},
        {"resource": {"attributes": [attr("service.name", "cart")]},
         "scopeSpans": [{"spans": [
             {"traceId": "aa" * 16, "spanId": "03" * 8, "parentSpanId": "02" * 8, "name": "CartService/EmptyCart", "kind": 2,
              "startTimeUnixNano": "1200000000", "endTimeUnixNano": "1300000000",
              "status": {"code": 2, "message": "Can't access cart storage"},
              "attributes": [attr("feature_flag.key", "cartFailure"), attr("app.user.id", "u1")]},
         ]}]},
        {"resource": {"attributes": [attr("service.name", "flagd")]},
         "scopeSpans": [{"spans": [
             {"traceId": "aa" * 16, "spanId": "04" * 8, "parentSpanId": "03" * 8, "name": "flagd.evaluation", "kind": 3,
              "startTimeUnixNano": "1210000000", "endTimeUnixNano": "1220000000", "status": {"code": 0}},
         ]}]},
    ]}}


class JaegerTests(unittest.TestCase):
    def setUp(self):
        jaeger_tools._RESOLVED = None
        jaeger_tools.EVIDENCE.clear()
        p = mock.patch.object(jaeger_tools, "_direct_base", return_value=None)  # no Docker in offline tests
        p.start()
        self.addCleanup(p.stop)

    def test_v3_base_is_resolved_and_v1_paths_are_skipped(self):
        def fake_get(url, **kw):
            ok = url.endswith("/jaeger/ui/api/v3/services")
            return SimpleNamespace(status_code=200 if ok else 404, json=lambda: {"services": ["cart"]})
        with mock.patch.object(jaeger_tools.requests, "get", fake_get):
            base, mode = jaeger_tools._resolve()
        self.assertEqual(mode, "v3")
        self.assertTrue(base.endswith("/jaeger/ui/api/v3"))

    def test_stream_parsing_and_flag_filtering(self):
        text = json.dumps(otlp_trace()) + "\n" + json.dumps({"result": {"resourceSpans": []}})
        traces = jaeger_tools._group_otlp(jaeger_tools._parse_stream(text))
        self.assertEqual(len(traces), 1)
        names = {s["service"] for s in traces[0]["spans"]}
        self.assertEqual(names, {"frontend", "checkout", "cart"})  # flagd dropped
        cart = next(s for s in traces[0]["spans"] if s["service"] == "cart")
        self.assertNotIn("feature_flag.key", cart["attrs"])
        self.assertEqual(cart["attrs"]["app.user.id"], "u1")

    def test_root_cause_is_deepest_error(self):
        tr = jaeger_tools._group_otlp([otlp_trace()])[0]
        s = jaeger_tools.summarize_trace(tr)
        self.assertEqual(s["error_spans"], 3)
        self.assertEqual([r["service"] for r in s["root_error_spans"]], ["cart"])
        self.assertEqual(s["root_error_spans"][0]["operation"], "CartService/EmptyCart")
        self.assertIn("aa" * 16, jaeger_tools.EVIDENCE)

    def test_error_hotspots_aggregates(self):
        tr = jaeger_tools._group_otlp([otlp_trace()])[0]
        with mock.patch.object(jaeger_tools, "find_traces", return_value=[tr, tr]):
            out = jaeger_tools.error_hotspots("frontend")
        self.assertEqual(out["root_error_hotspots"][0]["count"], 2)
        self.assertEqual(out["root_error_hotspots"][0]["service"], "cart")

    def test_empty_result_is_not_reported_as_healthy(self):
        with mock.patch.object(jaeger_tools, "find_traces", return_value=[]):
            self.assertIn("NOT proof of health", jaeger_tools.error_hotspots("cart")["note"])

    def test_v1_normalisation(self):
        v1 = {"traceID": "ab" * 8, "processes": {"p1": {"serviceName": "cart"}, "p2": {"serviceName": "flagd"}},
              "spans": [
                  {"spanID": "s1", "processID": "p1", "operationName": "EmptyCart", "duration": 5000, "references": [],
                   "tags": [{"key": "error", "value": True}, {"key": "otel.status_description", "value": "boom"}]},
                  {"spanID": "s2", "processID": "p2", "operationName": "x", "duration": 1, "references": [], "tags": []}]}
        tr = jaeger_tools._norm_v1(v1)
        self.assertEqual(len(tr["spans"]), 1)
        self.assertTrue(tr["spans"][0]["error"])
        self.assertEqual(tr["spans"][0]["message"], "boom")

    def test_bad_trace_id_rejected(self):
        with self.assertRaises(ValueError):
            jaeger_tools.fetch_trace("../../etc/passwd")


# ------------------------------------------------------------------ registry / grounding
class RegistryTests(unittest.TestCase):
    def setUp(self):
        registry.reset_session()

    def test_output_is_always_valid_json_even_when_huge(self):
        big = {"rows": [{"service": "cart", "detail": "x" * 400} for _ in range(100)]}
        with mock.patch.dict(registry.TOOLS, {"big": lambda: big}):
            out = registry.call_tool("big", {})
        self.assertLessEqual(len(out), registry.MAX_OUTPUT_CHARS)
        parsed = json.loads(out)
        self.assertEqual(parsed["obs"], "obs-1")
        self.assertTrue(parsed["_truncated"])

    def test_unknown_args_ignored_and_unknown_tool_reported(self):
        with mock.patch.dict(registry.TOOLS, {"t": lambda minutes=5: {"m": minutes}}):
            out = json.loads(registry.call_tool("t", {"minutes": 3, "bogus": 1}))
        self.assertEqual(out["m"], 3)
        self.assertEqual(out["ignored_args"], ["bogus"])
        self.assertIn("tool_error", json.loads(registry.call_tool("nope", {})))

    def test_grounding(self):
        with mock.patch.dict(registry.TOOLS, {"t": lambda: {"service": "cart", "message": "Can't access cart storage", "trace": "3f9a1c77b2d44e10"}}):
            registry.call_tool("t", {})
        g = registry.grounded
        self.assertTrue(g("obs-1: cart message Can't access cart storage"))
        self.assertTrue(g("trace 3f9a1c77b2d44e10 in cart"))
        self.assertFalse(g("obs-9: cart message Can't access cart storage"))      # observation does not exist
        self.assertFalse(g("obs-1: payment gateway timed out after 30 seconds"))  # fabricated
        self.assertFalse(g("trace deadbeef12345678 in cart"))                       # fabricated id
        self.assertFalse(g(""))

    def test_observed_services_use_whole_tokens(self):
        with mock.patch.dict(registry.TOOLS, {"t": lambda: {"note": "payload upload loaded"}}):
            registry.call_tool("t", {})
        self.assertNotIn("ad", registry.OBSERVED_SERVICES)  # 'ad' inside 'payload'/'upload' must not count

    def test_pillar_tracking(self):
        self.assertEqual(set(registry.missing_signal_categories()), set(registry.SIGNAL_CATEGORIES))
        for t in ("triage", "error_hotspots", "get_logs", "deploy_history"):
            registry.CALLED_TOOLS.add(t)
        self.assertEqual(registry.missing_signal_categories(), [])


# ------------------------------------------------------------------ ops tools
class OpsTests(unittest.TestCase):
    @staticmethod
    def _fake_prom(chronic):
        def fake_prom(path, **p):
            q = p.get("query", "")
            if "span_name" in q:
                err = 'STATUS_CODE_ERROR' in q
                failing = chronic or "offset" not in q   # baseline windows are healthy unless the failure is chronic
                rows = [("cart", "EmptyCart", (4.0 if failing else 0.0) if err else 20.0), ("cart", "AddItem", 0.0 if err else 50.0)]
                return {"result": [{"metric": {"service_name": s, "span_name": o}, "value": [0, str(v)]} for s, o, v in rows if v > 0]}
            return {"result": [{"metric": {"service_name": "cart"}, "value": [0, "7.0"]}]}
        return fake_prom

    def test_triage_catches_single_operation_failure(self):
        with mock.patch.object(ops_tools, "_prom", self._fake_prom(chronic=False)), mock.patch.object(ops_tools, "container_health", return_value={}):
            out = ops_tools.triage(window_min=5)
        ops = [a for a in out["anomalies"] if a["type"] == "operation_error_rate"]
        self.assertEqual(ops[0]["operation"], "EmptyCart")

    def test_chronic_operation_failure_is_not_a_new_incident(self):
        with mock.patch.object(ops_tools, "_prom", self._fake_prom(chronic=True)), mock.patch.object(ops_tools, "container_health", return_value={}):
            out = ops_tools.triage(window_min=5)
        self.assertFalse([a for a in out["anomalies"] if a["type"] == "operation_error_rate"])

    def test_flag_telemetry_blocked_in_queries_and_logs(self):
        self.assertIn("note", ops_tools.metric_query("sum(rate(flagd_evaluations[1m]))"))
        self.assertIn("note", ops_tools.get_logs("--help"))
        self.assertIn("note", ops_tools.get_logs("flagd"))


# ------------------------------------------------------------------ action API
class FakeAdapters:
    def __init__(self):
        self.calls = []

    def restart_service(self, service, reset_limits=False):
        self.calls.append(("restart", service, reset_limits)); return f"Restarted {service}"

    def set_flag(self, flag, variant):
        self.calls.append(("flag", flag, variant)); return "100%"

    def throttle_load(self, users, rate):
        self.calls.append(("throttle", users, rate)); return 40


class ActionApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(action_api, "KILL_SWITCH_FILE", t / "KILL_SWITCH"),
            mock.patch.object(action_api, "LOGS_DIR", t / "logs"),
            mock.patch.object(action_api, "AUDIT_LOG_FILE", t / "logs" / "audit.jsonl"),
            mock.patch.object(action_api, "REPORTS_DIR", t / "reports"),
            # offline: the verifier sees steady traffic unless a test says otherwise
            mock.patch.object(action_api.ops_tools, "service_rates", return_value={"cart": 0.5, "checkout": 0.2, "frontend": 1.0}),
        ]
        for p in self.patches:
            p.start()
        self.fake = FakeAdapters()
        a = mock.patch.multiple(action_api.adapters, restart_service=self.fake.restart_service,
                                set_flag=self.fake.set_flag, throttle_load=self.fake.throttle_load)
        a.start(); self.patches.append(a)
        self.diag = {"fault_class": "app_error", "failing_component": "cart", "cause": "EmptyCart fails", "confidence": "high",
                     "evidence": ["obs-1: x"], "suggested_remedy": "toggle a feature flag", "escalate_to_human": False}

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def plan(self, **over):
        d = {**self.diag, **over}
        return action_api.build_action_plan("inc-1", d, {"cart", "checkout"})

    def approve(self, answer="yes", plan=None):
        plan = plan or self.plan()
        with mock.patch.object(builtins, "input", return_value=answer), mock.patch("builtins.print"):
            return plan, action_api.request_human_approval(self.diag, plan)

    # -- policy
    def test_policy_maps_diagnosis_to_one_allowlisted_action(self):
        p = self.plan()
        self.assertEqual((p["action_type"], p["parameters"]["flag_name"], p["parameters"]["variant"]), ("toggle_feature_flag", "cartFailure", "off"))
        self.assertEqual(len(p["approval_digest"]), 64)

    def test_policy_escalates_when_it_should(self):
        self.assertTrue(self.plan(confidence="low")["escalate"])
        self.assertTrue(self.plan(escalate_to_human=True)["escalate"])
        self.assertTrue(self.plan(suggested_remedy="none/escalate")["escalate"])
        self.assertTrue(self.plan(suggested_remedy="format the disk")["escalate"])
        self.assertTrue(self.plan(failing_component="flagd")["escalate"])
        self.assertTrue(self.plan(failing_component="shipping", suggested_remedy="restart a service")["escalate"])  # never observed
        self.assertTrue(self.plan(failing_component="frontend-proxy", suggested_remedy="restart a service")["escalate"])  # protected
        self.assertTrue(self.plan(suggested_remedy="throttle the load generator")["escalate"])  # only for traffic_flood

    def test_hesitant_model_with_strong_evidence_still_gets_a_fix_proposed(self):
        """Regression: round 2 named payment (medium, grounded evidence) but asked for a human because the same fix had
        been applied earlier, so no fix was proposed and the operator was never asked."""
        d = {"fault_class": "app_error", "failing_component": "payment", "cause": "charges fail", "confidence": "medium",
             "evidence": ["obs-1: payment error rate 100%", "obs-3: Payment request failed"], "suggested_remedy": "none/escalate",
             "escalate_to_human": True}
        p = action_api.build_action_plan("i", d, {"payment", "checkout"})
        self.assertTrue(p["allowed"])
        self.assertEqual(p["parameters"]["flag_name"], "paymentFailure")
        self.assertIn("YOUR decision", p["policy_note"])
        self.assertTrue(action_api.build_action_plan("i", {**d, "confidence": "low"}, {"payment"})["escalate"])
        self.assertTrue(action_api.build_action_plan("i", {**d, "evidence": d["evidence"][:1]}, {"payment"})["escalate"])

    def test_policy_overrides_pointless_restart_with_switch_fix(self):
        """Regression: LLM proposed restarting cart for an app-level fault; a restart cannot clear it."""
        p = self.plan(suggested_remedy="restart a service")
        self.assertEqual((p["action_type"], p["parameters"]["flag_name"]), ("toggle_feature_flag", "cartFailure"))
        self.assertIn("Runbook override", p["policy_note"])

    def test_policy_restarts_when_container_is_actually_down(self):
        p = action_api.build_action_plan("i", {**self.diag, "failing_component": "cart", "suggested_remedy": "toggle a feature flag"},
                                         {"cart"}, down_services={"cart"})
        self.assertEqual(p["action_type"], "restart_service")

    def test_restart_load_generator_is_not_mistaken_for_throttle(self):
        p = action_api.build_action_plan("i", {**self.diag, "failing_component": "load-generator", "suggested_remedy": "restart the load generator"}, {"load-generator"})
        self.assertEqual(p["action_type"], "restart_service")

    def test_validate_params(self):
        v = action_api.validate_params
        v("restart_service", {"service_name": "cart"})
        for bad in [("restart_service", {"service_name": "flagd"}), ("toggle_feature_flag", {"flag_name": "cartFailure", "variant": "on"}),
                    ("throttle_load_generator", {"user_count": 500, "spawn_rate": 1}), ("scale_service", {}), ("rm_rf", {})]:
            with self.assertRaises(ValueError):
                v(*bad)

    # -- approval gate
    def test_only_explicit_yes_approves(self):
        for ans, ok in [("yes", True), ("y", False), ("", False), ("no", False)]:
            self.assertEqual(self.approve(ans)[1]["approved"], ok, ans)

    def test_kill_switch_blocks_every_stage(self):
        plan, appr = self.approve()
        action_api.set_kill_switch(True, "test")
        with mock.patch.object(builtins, "input", return_value="yes"):
            self.assertEqual(action_api.request_human_approval(self.diag, plan)["status"], "kill_switch_active")
        self.assertEqual(action_api.execute_action(plan, appr)["status"], "aborted_kill_switch")
        self.assertFalse(action_api.rollback_action(plan, {"previous_variant": "100%"})["rolled_back"])
        self.assertEqual(self.fake.calls, [])

    # -- executor gates
    def test_executes_once_then_replay_blocked(self):
        plan, appr = self.approve()
        r1 = action_api.execute_action(plan, appr)
        self.assertTrue(r1["executed"])
        self.assertEqual(r1["previous_variant"], "100%")
        self.assertEqual(self.fake.calls, [("flag", "cartFailure", "off")])
        self.assertEqual(action_api.execute_action(plan, appr)["status"], "replay_blocked")
        self.assertEqual(len(self.fake.calls), 1)

    def test_tampered_plan_is_rejected(self):
        plan, appr = self.approve()
        plan["parameters"]["flag_name"] = "paymentFailure"
        self.assertEqual(action_api.execute_action(plan, appr)["status"], "digest_mismatch")
        self.assertEqual(self.fake.calls, [])

    def test_unapproved_and_expired_are_rejected(self):
        plan, appr = self.approve("no")
        self.assertEqual(action_api.execute_action(plan, appr)["status"], "rejected_by_human")
        plan, appr = self.approve("yes")
        appr["decided_epoch"] -= action_api.APPROVAL_TTL_S + 5
        self.assertEqual(action_api.execute_action(plan, appr)["status"], "approval_expired")
        self.assertEqual(self.fake.calls, [])

    def test_dry_run_changes_nothing(self):
        plan, appr = self.approve("dry-run")
        res = action_api.execute_action(plan, appr)
        self.assertTrue(res["dry_run"])
        self.assertIn("WOULD CALL", res["detail"])
        self.assertEqual(self.fake.calls, [])

    def test_circuit_breaker(self):
        for _ in range(action_api.MAX_ACTIONS_PER_HOUR):
            plan, appr = self.approve()
            self.assertTrue(action_api.execute_action(plan, appr)["executed"])
        plan, appr = self.approve()
        self.assertEqual(action_api.execute_action(plan, appr)["status"], "circuit_breaker_open")

    def test_rollback_restores_previous_variant(self):
        plan, appr = self.approve()
        res = action_api.execute_action(plan, appr)
        out = action_api.rollback_action(plan, res)
        self.assertTrue(out["rolled_back"])
        self.assertEqual(self.fake.calls[-1], ("flag", "cartFailure", "100%"))
        rp = self.plan(failing_component="cart", suggested_remedy="restart a service")
        self.assertFalse(action_api.rollback_action(rp, {})["rolled_back"])

    # -- verifier
    def _triage(self, anomalies=None, notes=None, down=None):
        return {"anomalies": anomalies or [], "notes": notes or [], "containers": {"not_running": down or []}}

    def test_verifier_pass_fail_and_blind(self):
        with mock.patch.object(action_api.time, "sleep"), mock.patch.object(action_api.ops_tools, "topology", return_value={"called_by": ["checkout"]}):
            with mock.patch.object(action_api.ops_tools, "triage", return_value=self._triage()):
                self.assertTrue(action_api.verify_recovery("cart")["verified"])
            bad = self._triage([{"service": "checkout", "type": "error_rate", "detail": "5%"}])
            with mock.patch.object(action_api.ops_tools, "triage", return_value=bad):
                self.assertFalse(action_api.verify_recovery("cart")["verified"])  # a caller is still failing
            blind = self._triage(notes=["prometheus scan failed: boom"])
            with mock.patch.object(action_api.ops_tools, "triage", return_value=blind):
                self.assertFalse(action_api.verify_recovery("cart")["verified"])  # no data is NOT recovery

    # -- adapters on a temp flag file
    def test_flag_adapter_edits_file_case_insensitively(self):
        flag_file = Path(self.tmp.name) / "flags.json"
        flag_file.write_text(json.dumps({"flags": {"cartFailure": {"defaultVariant": "100%", "variants": {"off": False, "100%": True}}}}))
        calls = []
        with mock.patch.object(adapters, "FLAG_FILE", flag_file), mock.patch.object(adapters, "_compose", lambda *a, **k: calls.append(a)):
            self.assertEqual(REAL_SET_FLAG("CARTFAILURE", "off"), "100%")
            self.assertEqual(json.loads(flag_file.read_text())["flags"]["cartFailure"]["defaultVariant"], "off")
            self.assertEqual(calls, [])  # no restart: the switch service picks up the file change itself
            with self.assertRaises(ValueError):
                REAL_SET_FLAG("cartFailure", "bogus")
            with self.assertRaises(ValueError):
                REAL_SET_FLAG("nope", "off")


# ------------------------------------------------------------------ detector
class DetectorTests(unittest.TestCase):
    ERR = {"type": "operation_error_rate", "service": "cart", "operation": "EmptyCart", "score": 95.0, "detail": "operation EmptyCart error rate 100.0%"}

    def test_verifier_fails_while_a_dependency_is_stopped_or_nothing_is_seen(self):
        """Regression: restarting cart 'verified' while valkey-cart was still stopped (too little traffic to alarm)."""
        stopped = {"anomalies": [], "notes": [], "containers": {"not_running": [{"service": "valkey-cart", "state": "exited"}]}}
        clean = {"anomalies": [], "notes": [], "containers": {}}
        busy, silent = {"cart": 0.2, "checkout": 0.1}, {"frontend-proxy": 1.0}
        with mock.patch.object(action_api.time, "sleep"):
            with mock.patch.object(action_api.ops_tools, "triage", return_value=stopped),                     mock.patch.object(action_api.ops_tools, "service_rates", return_value=busy):
                v = action_api.verify_recovery("cart")
            self.assertFalse(v["verified"] or v["target_recovered"])
            self.assertEqual(v["checks"][0]["stopped_dependencies"], ["valkey-cart"])
            with mock.patch.object(action_api.ops_tools, "triage", return_value=clean):
                with mock.patch.object(action_api.ops_tools, "service_rates", return_value=silent):
                    self.assertFalse(action_api.verify_recovery("cart")["verified"])  # no traffic is not recovery
                with mock.patch.object(action_api.ops_tools, "service_rates", return_value=busy):
                    self.assertTrue(action_api.verify_recovery("cart")["verified"])

    def test_needs_persistence_then_cooldown(self):
        d = detector.Detector(persist=2, cooldown_s=600)
        self.assertEqual(d.step([self.ERR], now=0), [])               # one blip is not an incident
        self.assertEqual(len(d.step([self.ERR], now=30)), 1)          # persisted -> incident
        d.mute([self.ERR], now=30)
        self.assertEqual(d.step([self.ERR], now=60), [])              # cooldown
        self.assertEqual(d.step([self.ERR], now=90), [])
        self.assertEqual(len(d.step([self.ERR], now=700)), 1)         # cooldown over, still broken -> reopen

    def test_vanished_anomaly_loses_streak(self):
        d = detector.Detector(persist=2)
        d.step([self.ERR], now=0)
        d.step([], now=30)
        self.assertEqual(d.step([self.ERR], now=60), [])              # streak restarted

    def test_alert_text_has_symptoms_not_cause(self):
        text = detector.describe([self.ERR])
        self.assertIn("EmptyCart error rate 100.0%", text)

    def test_scan_filters_noise_and_adds_container_signals(self):
        fake = {"anomalies": [{"type": "error_rate", "service": "load-generator", "score": 90, "detail": "x"},
                              {"type": "latency", "service": "ad", "score": 10, "detail": "weak"}, self.ERR],
                "containers": {"not_running": [{"service": "valkey-cart", "state": "exited", "exit_code": 137}]}, "notes": []}
        with mock.patch.object(detector.ops_tools, "triage", return_value=fake):
            found = detector.scan()
        self.assertEqual({(a["type"], a["service"]) for a in found}, {("operation_error_rate", "cart"), ("container_down", "valkey-cart")})

    def test_resource_pressure_detected_but_infra_ignored(self):
        fake = {"anomalies": [], "notes": [], "containers": {"hot": [
            {"service": "ad", "cpu_pct": 95.0, "mem_pct_of_limit": 40.0},          # at its 1-CPU cap: starved
            {"service": "email", "cpu_pct": 1.0, "mem_pct_of_limit": 97.0},
            {"service": "frontend", "cpu_pct": 227.0, "mem_pct_of_limit": 50.0},   # busy on several cores, no cap: ignored
            {"service": "grafana", "cpu_pct": 1.0, "mem_pct_of_limit": 99.0},      # observability stack: ignored
            {"service": "quote", "cpu_pct": 3.0, "mem_pct_of_limit": 75.0}],      # ordinary warm container: ignored
            "cpu_limited": [{"service": "ad", "cpus": 1.0}]}}
        with mock.patch.object(detector.ops_tools, "triage", return_value=fake):
            found = detector.scan()
        self.assertEqual({a["service"] for a in found}, {"ad", "email"})

    def test_blind_telemetry_is_reported(self):
        with mock.patch.object(detector.ops_tools, "triage", return_value={"anomalies": [], "containers": {}, "notes": ["prometheus scan failed: boom"]}):
            self.assertEqual(detector.scan()[0]["type"], "telemetry_blind")

    def test_watch_opens_incident_once_then_mutes(self):
        calls = []
        scans = iter([[self.ERR]] * 6)
        with mock.patch.object(agent.detector, "scan", lambda: next(scans)), \
             mock.patch.object(agent, "run_full_incident_loop", lambda alert, **kw: calls.append(alert) or {"status": "x", "diagnosis": {}}), \
             mock.patch.object(agent, "render", lambda o: ""), mock.patch("builtins.print"), \
             mock.patch.object(agent.time, "sleep", side_effect=[None, None, None, None, None, KeyboardInterrupt]):
            agent.watch(interval=1, persist=2, cooldown=600)
        self.assertEqual(len(calls), 1)
        self.assertIn("EmptyCart", calls[0])


# ------------------------------------------------------------------ agent end-to-end with a scripted LLM
def tc(i, name, args):
    return SimpleNamespace(id=f"c{i}", function=SimpleNamespace(name=name, arguments=json.dumps(args)))


class ScriptedLLM:
    def __init__(self, steps):
        self.steps = list(steps)
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kw):
        s = self.steps.pop(0)
        msg = SimpleNamespace(content=s.get("content"), tool_calls=s.get("tool_calls"))
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


class AgentLoopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(action_api, "KILL_SWITCH_FILE", t / "KILL_SWITCH"),
            mock.patch.object(action_api, "LOGS_DIR", t / "logs"),
            mock.patch.object(action_api, "AUDIT_LOG_FILE", t / "logs" / "audit.jsonl"),
            mock.patch.object(action_api, "REPORTS_DIR", t / "reports"),
            mock.patch.dict(registry.TOOLS, {
                "triage": lambda window_min=5: {"anomalies": [{"type": "operation_error_rate", "service": "cart", "operation": "EmptyCart", "detail": "operation EmptyCart error rate 17.0%"}], "containers": {}},
                "error_hotspots": lambda service, minutes=15: {"root_error_hotspots": [{"service": "cart", "operation": "CartService/EmptyCart", "message": "Can't access cart storage", "example_traces": ["3f9a1c77b2d44e10"]}]},
                "get_logs": lambda service, minutes=10: {"service": service, "top_patterns": [{"count": 4, "example": "rpc error: Can't access cart storage"}]},
                "deploy_history": lambda minutes=120: {"recent_git_commits": [], "recent_agent_actions": []},
            }),
        ]
        for p in self.patches:
            p.start()
        self.fake = FakeAdapters()
        a = mock.patch.multiple(action_api.adapters, restart_service=self.fake.restart_service, set_flag=self.fake.set_flag, throttle_load=self.fake.throttle_load)
        a.start(); self.patches.append(a)
        self.rescan = mock.patch.object(agent, "_confirm_still_wrong", return_value=[])  # offline: nothing left after a fix
        self.rescan.start(); self.patches.append(self.rescan)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def llm(self, evidence, confidence="high"):
        final = {"fault_class": "app_error", "failing_component": "cart", "cause": "CartService/EmptyCart fails: Can't access cart storage",
                 "confidence": confidence, "evidence": evidence, "secondary_findings": [], "suggested_remedy": "toggle a feature flag", "escalate_to_human": False}
        return ScriptedLLM([
            {"tool_calls": [tc(1, "triage", {}), tc(2, "error_hotspots", {"service": "frontend"})]},
            {"tool_calls": [tc(3, "get_logs", {"service": "cart"}), tc(4, "deploy_history", {})]},
            {"content": json.dumps(final)},
        ])

    def run_loop(self, llm, answer="dry-run", **kw):
        with mock.patch.object(agent, "_build_llm_client", return_value=(llm, "fake")), \
             mock.patch.object(builtins, "input", return_value=answer), mock.patch("builtins.print"):
            return agent.run_full_incident_loop("checkout errors", verbose=False, settle_seconds=0, **kw)

    GOOD = ["obs-2: cart CartService/EmptyCart Can't access cart storage trace 3f9a1c77b2d44e10",
            "obs-3: rpc error: Can't access cart storage"]

    def test_diagnose_only_grounds_evidence(self):
        d = self.run_loop(self.llm(self.GOOD + ["obs-2: payment gateway exploded at 3am"]), diagnose_only=True)
        self.assertEqual(len(d["evidence"]), 2)
        self.assertEqual(len(d["dropped_ungrounded_evidence"]), 1)
        self.assertEqual(d["confidence"], "medium")  # dropped evidence caps confidence

    def test_fabricated_evidence_forces_escalation(self):
        d = self.run_loop(self.llm(["obs-2: the database caught fire"]), diagnose_only=True)
        self.assertEqual((d["confidence"], d["escalate_to_human"], d["suggested_remedy"]), ("low", True, "none/escalate"))

    def test_dry_run_full_loop_changes_nothing_and_writes_reports(self):
        rep = self.run_loop(self.llm(self.GOOD), "dry-run")
        self.assertEqual(rep["status"], "Simulated")
        self.assertEqual(self.fake.calls, [])
        self.assertTrue(Path(rep["report_files"]["json"]).exists() and Path(rep["report_files"]["markdown"]).exists())
        self.assertEqual(len(rep["observations"]), 4)

    def test_approved_run_executes_and_verifies(self):
        with mock.patch.object(action_api, "verify_recovery", return_value={"verified": True, "status": "Resolved"}):
            rep = self.run_loop(self.llm(self.GOOD), "yes")
        self.assertEqual(rep["status"], "Resolved")
        self.assertEqual(self.fake.calls, [("flag", "cartFailure", "off")])

    def test_masked_second_fault_gets_its_own_round(self):
        """Regression: with the cache down no checkout reached payment, so the payment fault only appeared after the
        first fix. The agent declared 'Resolved' too early; now it re-scans and opens round 2."""
        pay = {"fault_class": "app_error", "failing_component": "payment", "cause": "payment charge fails",
               "confidence": "high", "evidence": self.GOOD, "secondary_findings": [], "suggested_remedy": "toggle a feature flag"}
        llm = self.llm(self.GOOD)
        llm.steps += [{"tool_calls": [tc(5, "triage", {}), tc(6, "error_hotspots", {"service": "frontend"})]},
                      {"tool_calls": [tc(7, "get_logs", {"service": "cart"}), tc(8, "deploy_history", {})]},
                      {"content": json.dumps(pay)}]
        left = [{"type": "error_rate", "service": "payment", "detail": "error rate 100.0% (baseline 0.0%)", "score": 100.0}]
        self.rescan.stop()
        with mock.patch.object(agent, "_confirm_still_wrong", side_effect=[left, []]),                 mock.patch.object(action_api, "verify_recovery", return_value={"verified": True, "status": "Resolved"}),                 mock.patch.dict(registry.TOOLS, {"triage": lambda window_min=5: {"anomalies": left + [
                    {"type": "operation_error_rate", "service": "cart", "operation": "EmptyCart", "detail": "x"}], "containers": {}}}):
            rep = self.run_loop(llm, "yes")
        self.rescan.start()
        self.assertEqual(len(rep["rounds"]), 2)
        self.assertEqual(rep["status"], "Resolved")
        self.assertEqual(self.fake.calls, [("flag", "cartFailure", "off"), ("flag", "paymentFailure", "off")])

    def test_failed_verification_rolls_back_and_escalates(self):
        with mock.patch.object(action_api, "verify_recovery", return_value={"verified": False, "status": "Failed_Verification_Escalated"}):
            rep = self.run_loop(self.llm(self.GOOD), "yes")
        self.assertEqual(rep["status"], "Failed_Verification_Escalated")
        self.assertTrue(rep["verification"]["rollback"]["rolled_back"])
        self.assertEqual(self.fake.calls[-1], ("flag", "cartFailure", "100%"))

    def test_human_rejection_executes_nothing(self):
        rep = self.run_loop(self.llm(self.GOOD), "no")
        self.assertEqual(rep["status"], "Rejected")
        self.assertEqual(self.fake.calls, [])

    def test_kill_switch_halts_investigation(self):
        action_api.set_kill_switch(True)
        d = self.run_loop(self.llm(self.GOOD), diagnose_only=True)
        self.assertTrue(d["kill_switch_aborted"])

    def test_pillar_nudge_when_model_answers_early(self):
        final = {"fault_class": "app_error", "failing_component": "cart", "cause": "x", "confidence": "low", "evidence": [], "suggested_remedy": "none/escalate", "escalate_to_human": True}
        llm = ScriptedLLM([{"content": json.dumps(final)},
                           {"tool_calls": [tc(1, "triage", {}), tc(2, "error_hotspots", {"service": "cart"}), tc(3, "get_logs", {"service": "cart"}), tc(4, "deploy_history", {})]},
                           {"content": json.dumps(final)}])
        self.run_loop(llm, diagnose_only=True)
        self.assertEqual(len(registry.OBSERVATIONS), 4)

    def test_running_backing_store_cannot_be_blamed(self):
        """Regression: agent blamed a healthy valkey-cart because container_health only lists problems."""
        registry.reset_session()
        with mock.patch.dict(registry.TOOLS, {"container_health": lambda: {"running": ["cart", "valkey-cart"], "not_running": []},
                                              "get_logs": lambda service: {"top_patterns": [{"example": "Wasn't able to connect to redis"}]}}):
            registry.call_tool("container_health", {})
            registry.call_tool("get_logs", {"service": "cart"})
        wrong = {"fault_class": "dependency_down", "failing_component": "valkey-cart", "cause": "redis unreachable", "confidence": "high",
                 "evidence": ["obs-2: Wasn't able to connect to redis"], "suggested_remedy": "restart a service", "escalate_to_human": False}
        d = agent.finalize(json.dumps(wrong))   # no caller implicated -> escalate
        self.assertEqual((d["confidence"], d["escalate_to_human"], d["suggested_remedy"]), ("low", True, "none/escalate"))
        self.assertIn("guard_triggered", d)
        # the cause itself implicates the caller -> reclassified to the caller instead of just escalating
        wrong2 = {**wrong, "cause": "cart service cannot connect to redis", "evidence": ["obs-2: Wasn't able to connect to redis"]}
        d = agent.finalize(json.dumps(wrong2))
        self.assertEqual((d["failing_component"], d["fault_class"], d["escalate_to_human"]), ("cart", "app_error", False))
        self.assertEqual((d["confidence"], d["guard_triggered"]), ("medium", "reclassified_to_caller"))
        # a genuinely stopped container is still accepted
        registry.reset_session()
        with mock.patch.dict(registry.TOOLS, {"container_health": lambda: {"running": ["cart"], "not_running": [{"service": "valkey-cart", "state": "exited"}]}}):
            registry.call_tool("container_health", {})
        wrong["evidence"] = ["obs-1: valkey-cart exited"]
        self.assertNotIn("guard_triggered", agent.finalize(json.dumps(wrong)))

    def test_unreachable_service_that_serves_traffic_is_an_app_error(self):
        """Regression: payment failed every charge (app fault) but was called 'dependency_down', so the wrong switch was used."""
        registry.reset_session()
        with mock.patch.dict(registry.TOOLS, {"container_health": lambda: {"running": ["payment", "checkout"], "not_running": []}}):
            registry.call_tool("container_health", {})
        claim = {"fault_class": "dependency_down", "failing_component": "payment", "cause": "payment cannot be reached",
                 "confidence": "high", "evidence": ["obs-1: payment checkout running"], "suggested_remedy": "toggle a feature flag"}
        with mock.patch.object(agent.ops_tools, "service_rates", return_value={"payment": 0.03}):
            d = agent.finalize(json.dumps(claim))
        self.assertEqual((d["fault_class"], d["guard_triggered"]), ("app_error", "unreachable_but_serving_traffic"))
        plan = action_api.build_action_plan("i", d, {"payment", "checkout"})
        self.assertEqual(plan["parameters"]["flag_name"], "paymentFailure")
        with mock.patch.object(agent.ops_tools, "service_rates", return_value={"checkout": 0.1}):   # payment gets nothing
            self.assertEqual(agent.finalize(json.dumps(claim))["fault_class"], "dependency_down")

    def test_stopped_container_beats_a_low_confidence_guess(self):
        """Regression: valkey-cart was exited but the model chased email slowness (low confidence) and escalated."""
        registry.reset_session()
        with mock.patch.dict(registry.TOOLS, {"container_health": lambda: {"running": ["cart", "email"],
                                                                           "not_running": [{"service": "valkey-cart", "state": "exited"}]}}):
            registry.call_tool("container_health", {})
        guess = {"fault_class": "latency_regression", "failing_component": "email", "cause": "email is slow",
                 "confidence": "low", "evidence": [], "suggested_remedy": "none/escalate", "escalate_to_human": True}
        d = agent.finalize(json.dumps(guess))
        self.assertEqual((d["failing_component"], d["fault_class"], d["confidence"], d["guard_triggered"]),
                         ("valkey-cart", "dependency_down", "medium", "stopped_container_takes_priority"))
        self.assertTrue(any("email" in s for s in d["secondary_findings"]))
        plan = action_api.build_action_plan("i", d, {"valkey-cart", "email"}, set(registry.DOWN_SERVICES))
        self.assertEqual((plan["action_type"], plan["target"]), ("restart_service", "valkey-cart"))

    def test_caller_blamed_for_stopped_dependency_is_retargeted(self):
        """Regression: valkey-cart was stopped but the agent named cart (dependency_down), so policy restarted cart."""
        registry.reset_session()
        with mock.patch.dict(registry.TOOLS, {"container_health": lambda: {"running": ["cart", "checkout"],
                                                                           "not_running": [{"service": "valkey-cart", "state": "exited"}]}}):
            registry.call_tool("container_health", {})
        blamed = {"fault_class": "dependency_down", "failing_component": "cart", "cause": "cart cannot reach its cache",
                  "confidence": "high", "evidence": ["obs-1: valkey-cart exited"], "suggested_remedy": "restart a service"}
        d = agent.finalize(json.dumps(blamed))
        self.assertEqual((d["failing_component"], d["fault_class"], d["guard_triggered"]),
                         ("valkey-cart", "dependency_down", "retargeted_to_stopped_dependency"))
        plan = action_api.build_action_plan("i", d, {"cart", "valkey-cart"}, set(registry.DOWN_SERVICES))
        self.assertEqual((plan["action_type"], plan["target"]), ("restart_service", "valkey-cart"))
        self.assertTrue(agent._downstream("checkout") >= {"cart", "valkey-cart", "payment"})

    def test_dropped_evidence_caps_confidence(self):
        d = self.run_loop(self.llm(self.GOOD + ["obs-2: payment gateway exploded at 3am"]), diagnose_only=True)
        self.assertEqual(d["confidence"], "medium")

    def test_readable_summary_and_diagnosis_file(self):
        d = self.run_loop(self.llm(self.GOOD), diagnose_only=True)
        text = agent.render(d)
        self.assertIn("Diagnosis : cart (app_error)", text)
        self.assertTrue((action_api.REPORTS_DIR / f"{d['incident_id']}-diagnosis.json").exists())
        rep = self.run_loop(self.llm(self.GOOD), "dry-run")
        text = agent.render(rep)
        self.assertIn("Simulated", text)
        self.assertIn("toggle_feature_flag on cart", text)

    def test_json_extraction_is_forgiving(self):
        good = '{"fault_class": "app_error", "failing_component": "cart", "cause": "x", "confidence": "low", "evidence": [], "escalate_to_human": true}'
        for text in ["Here you go:\n```json\n" + good + "\n```", "analysis {not json} then " + good + " trailing {braces}", good.replace('"x"', '"line1\nline2"')]:
            self.assertEqual(agent.finalize(text)["failing_component"], "cart", text[:40])
        self.assertIn("raw_output", agent.finalize("no json here"))

    def test_unparseable_final_answer_gets_one_repair_turn(self):
        final = {"fault_class": "app_error", "failing_component": "cart", "cause": "x", "confidence": "low", "evidence": [], "suggested_remedy": "none/escalate", "escalate_to_human": True}
        llm = ScriptedLLM([
            {"tool_calls": [tc(1, "triage", {}), tc(2, "error_hotspots", {"service": "cart"}), tc(3, "get_logs", {"service": "cart"}), tc(4, "deploy_history", {})]},
            {"content": "I believe the cart is at fault."},            # prose, no JSON
            {"content": json.dumps(final)},                            # repair answer
        ])
        d = self.run_loop(llm, diagnose_only=True)
        self.assertEqual(d["failing_component"], "cart")
        self.assertNotIn("raw_output", d)

    def test_bad_json_is_safe(self):
        d = agent.finalize("sorry, I cannot")
        self.assertTrue(d["escalate_to_human"])


if __name__ == "__main__":
    unittest.main()
