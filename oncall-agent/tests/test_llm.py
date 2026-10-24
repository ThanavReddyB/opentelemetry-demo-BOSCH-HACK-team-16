"""Offline tests for the LLM router: no network calls are made."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import llm  # noqa: E402


class RouterTests(unittest.TestCase):
    def test_paused_run_resumes_when_a_new_key_appears(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / ".env"
            env.write_text("GROQ_API_KEY=gsk_old\nGROQ_MODEL=openai/gpt-oss-120b\n")
            router = llm.Router(llm._providers({"GROQ_API_KEY": "gsk_old"}), env)
            router.providers[0].exhausted = True

            def user_adds_key(_s):
                env.write_text("GROQ_API_KEY=gsk_new\nGROQ_MODEL=openai/gpt-oss-120b\n")
            with mock.patch.object(llm.time, "sleep", side_effect=user_adds_key):
                p = router._pick()
            self.assertFalse(p.exhausted)
            self.assertEqual(p.model, "openai/gpt-oss-120b")
            self.assertEqual(len(router.providers), 2)

    def test_same_key_again_is_not_new_and_waiting_has_a_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / ".env"
            env.write_text("GROQ_API_KEY=gsk_old\n")
            router = llm.Router(llm._providers({"GROQ_API_KEY": "gsk_old"}), env)
            router.providers[0].exhausted = True
            clock = iter(range(0, 100000, 20))
            with mock.patch.object(llm.time, "sleep"), mock.patch.object(llm.time, "time", lambda: next(clock)), \
                    mock.patch.dict(llm.os.environ, {"LLM_WAIT_FOR_KEY_S": "60"}):
                with self.assertRaises(llm.LLMUnavailable):
                    router._pick()

    def test_no_weaker_fallback_unless_listed(self):
        self.assertEqual([p.model for p in llm._providers({"GROQ_API_KEY": "k"})], ["openai/gpt-oss-120b"])

    def test_durations(self):
        self.assertEqual(llm._seconds("1m26.4s"), 86.4)
        self.assertAlmostEqual(llm._seconds("697ms"), 0.697)


if __name__ == "__main__":
    unittest.main()
