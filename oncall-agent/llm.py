# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""LLM access that survives small free-tier quotas: provider fallback, per-minute pacing, clear failures.

Providers come from oncall-agent/.env and are tried in this order:
  1. API_KEY + LLM_BASE_URL + LLM_MODEL    any OpenAI-compatible endpoint (organisers' key, Cerebras, Gemini...)
  2. GROQ_API_KEY + GROQ_MODEL             then each model in GROQ_FALLBACK_MODELS, only if you list any
When every provider is out of quota the agent escalates to a human instead of quietly using a weaker model.

Pacing: after every call the provider's rate-limit headers say how many tokens are left this minute and when
the window resets. Before the next call we estimate its size and wait for the window instead of being rejected.
A provider that reports a DAILY limit is skipped for the rest of the run and the next one takes over.

The router exposes the same `client.chat.completions.create(**kw)` shape as the OpenAI SDK, so agent.py and the
offline tests treat it like any client.
"""
import json
import os
import re
import sys
import time
from types import SimpleNamespace

DAILY_HINTS = ("per day", "tokens per day", "requests per day", "(tpd)", "(rpd)", "daily", "quota exceeded")
TOO_LARGE_HINTS = ("request too large", "context_length", "context length", "reduce the length", "maximum context")
MALFORMED_HINTS = ("tool_use_failed", "failed to call a function", "failed_generation", "invalid tool")


class LLMUnavailable(RuntimeError):
    """Every configured provider is out of quota or failing."""


class RequestTooLarge(RuntimeError):
    """The prompt is bigger than the provider accepts in one request; the caller must shrink it."""


def _log(msg):
    print(f"[LLM] {msg}", file=sys.stderr, flush=True)


def _seconds(text):
    """'697ms', '7.66s', '1m26.4s', '2h0m5s' or plain '12.3' -> seconds."""
    s = str(text or "").strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        pass
    total, found = 0.0, False
    # Each match is a number followed by a unit: h, m, s or ms ("ms" is listed before "m" so it wins).
    for num, unit in re.findall(r"([\d.]+)\s*(ms|h|m|s)", s):
        found = True
        total += float(num) * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[unit]
    return total if found else None


def estimate_tokens(messages, tools=None):
    return int(len(json.dumps(messages, default=str)) / 3.4 + len(json.dumps(tools or [])) / 3.4) + 50


class Provider:
    def __init__(self, name, client, model, max_tokens, reasoning_effort=None, key=""):
        self.name, self.client, self.model = name, client, model
        self.key = f"{name}:{model}:{hash(key)}"  # identity only; the secret itself is never stored or logged
        self.max_tokens, self.reasoning_effort = max_tokens, reasoning_effort
        self.remaining = None      # tokens left in the current minute window (from headers)
        self.reset_at = 0.0        # when that window refills
        self.exhausted = False     # daily quota hit
        self.calls = self.tokens = 0

    @property
    def label(self):
        return f"{self.name}:{self.model}"

    def note_headers(self, headers):
        h = {k.lower(): v for k, v in (headers or {}).items()}
        rem = h.get("x-ratelimit-remaining-tokens") or h.get("x-ratelimit-remaining-tokens-minute")
        reset = h.get("x-ratelimit-reset-tokens") or h.get("x-ratelimit-reset-tokens-minute")
        try:
            self.remaining = int(float(rem)) if rem is not None else None
        except ValueError:
            self.remaining = None
        secs = _seconds(reset)
        self.reset_at = time.time() + secs if secs is not None else 0.0


class Router:
    def __init__(self, providers, env_file=None):
        if not providers:
            raise LLMUnavailable("No LLM key found. Put API_KEY + LLM_BASE_URL + LLM_MODEL or GROQ_API_KEY in oncall-agent/.env")
        self.providers = providers
        self.env_file = env_file
        self.keys = {p.key for p in providers}
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def _wait_for_new_key(self):
        """All quota is gone: pause and re-read .env until someone adds a key we have not used, then carry on.
        Gives up (and the agent escalates) after LLM_WAIT_FOR_KEY_S seconds."""
        limit = int(os.environ.get("LLM_WAIT_FOR_KEY_S", "1200"))
        if not self.env_file or limit <= 0:
            return False
        from dotenv import dotenv_values

        _log(f"every provider is out of quota. PAUSED: put a new key in {self.env_file} "
             f"(the run continues by itself; giving up in {limit // 60} min)")
        end = time.time() + limit
        while time.time() < end:
            time.sleep(15)
            fresh = [p for p in _providers({k: v for k, v in dotenv_values(self.env_file).items() if v})
                     if p.key not in self.keys]
            if fresh:
                self.providers = fresh + self.providers
                self.keys |= {p.key for p in fresh}
                _log(f"new key found in .env; resuming with {fresh[0].label}")
                return True
        return False

    @property
    def model(self):
        return self.providers[0].label

    def stats(self):
        return [{"provider": p.label, "calls": p.calls, "tokens": p.tokens, "daily_quota_hit": p.exhausted} for p in self.providers]

    def _pick(self):
        for p in self.providers:
            if not p.exhausted:
                return p
        if self._wait_for_new_key():
            return self.providers[0]
        raise LLMUnavailable("All LLM providers hit their daily quota: " + ", ".join(p.label for p in self.providers))

    def _pace(self, p, need):
        if p.remaining is None or need <= p.remaining:
            return
        wait = p.reset_at - time.time()
        if wait > 0:
            wait = min(wait + 0.5, 65)
            _log(f"pacing {wait:.0f}s for the {p.label} per-minute token budget (need ~{need}, {p.remaining} left)")
            time.sleep(wait)
        p.remaining = None

    def create(self, messages, tools=None, temperature=0, **_ignored):
        last = None
        for attempt in range(10):
            p = self._pick()
            kw = {"model": p.model, "messages": messages, "temperature": temperature if attempt < 2 else 0.3,
                  "max_tokens": p.max_tokens}
            if tools:
                kw["tools"] = tools
            if p.reasoning_effort:
                kw["reasoning_effort"] = p.reasoning_effort
            self._pace(p, estimate_tokens(messages, tools) + p.max_tokens)
            try:
                raw = p.client.chat.completions.with_raw_response.create(**kw)
                resp = raw.parse()
                p.note_headers(raw.headers)
                p.calls += 1
                p.tokens += int(getattr(getattr(resp, "usage", None), "total_tokens", 0) or 0)
                return resp
            except Exception as e:  # noqa: BLE001 - classified below
                last = e
                status = getattr(e, "status_code", None)
                text = f"{type(e).__name__} {e}".lower()
                headers = getattr(getattr(e, "response", None), "headers", {}) or {}
                if status == 413 or any(h in text for h in TOO_LARGE_HINTS):
                    raise RequestTooLarge(str(e)[:300]) from e
                if status == 429 and any(h in text for h in DAILY_HINTS):
                    p.exhausted = True
                    _log(f"{p.label} hit its daily quota; switching provider")
                    continue
                if status == 429:
                    wait = _seconds(headers.get("retry-after")) or _seconds((re.findall(r"try again in ([\d.hms]+)", text) or [""])[0]) or 10
                    wait = min(wait + 0.5, 65)
                    _log(f"{p.label} per-minute limit; retrying in {wait:.0f}s")
                    time.sleep(wait)
                    continue
                if any(h in text for h in MALFORMED_HINTS) or status == 400 and "tool" in text:
                    _log(f"{p.label} produced a malformed tool call; retrying")
                    if attempt >= 2 and len([q for q in self.providers if not q.exhausted]) > 1:
                        p.exhausted = True  # this model keeps failing the format; let the next one try
                    continue
                if status in (500, 502, 503, 504) or any(k in text for k in ("timeout", "connection", "temporarily")):
                    time.sleep(min(2 * (attempt + 1), 10))
                    continue
                raise
        raise LLMUnavailable(f"LLM call kept failing: {type(last).__name__}: {str(last)[:200]}")


def _effort_from(env, model, name):
    effort = env.get(name, "")
    if effort.lower() in ("none", "off"):
        return None
    return effort or ("low" if "gpt-oss" in model else None)


def _providers(env):
    """Providers described by an environment mapping (os.environ, or a fresh read of .env)."""
    providers = []
    key = env.get("API_KEY") or env.get("OPENAI_API_KEY")
    if key:
        from openai import OpenAI

        model = env.get("LLM_MODEL", "gpt-oss-120b")
        providers.append(Provider("api", OpenAI(api_key=key, base_url=env.get("LLM_BASE_URL") or None, timeout=90, max_retries=0),
                                  model, int(env.get("LLM_MAX_TOKENS", "2500")), _effort_from(env, model, "LLM_REASONING_EFFORT"), key))
    gkey = env.get("GROQ_API_KEY")
    if gkey:
        from groq import Groq

        client = Groq(api_key=gkey, timeout=90, max_retries=0)
        models = [env.get("GROQ_MODEL") or "openai/gpt-oss-120b"]
        # No silent downgrade: a weaker fallback model is used only if explicitly listed in GROQ_FALLBACK_MODELS.
        models += [m.strip() for m in env.get("GROQ_FALLBACK_MODELS", "").split(",") if m.strip()]
        for m in dict.fromkeys(models):
            providers.append(Provider("groq", client, m, int(env.get("GROQ_MAX_TOKENS", "1000")),
                                      _effort_from(env, m, "GROQ_REASONING_EFFORT"), gkey))
    return providers


def build_router(env_file=None):
    return Router(_providers(os.environ), env_file)
