# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Fair-play filters: the single place that knows which telemetry the agent must never see.

Competition rule: the agent may not diagnose from feature-flag state. Flag-mirroring telemetry
(the flag service itself, flag evaluation spans, feature_flag.* attributes) is therefore dropped
before any tool output reaches the LLM. Every read-only tool imports its filters from here, so
the rule is enforced (and tested) in one module.

tests/test_offline.py fails if any other module in this package mentions flag-service internals,
except the post-approval remediation module.
"""
import re

BLOCKED_SERVICES = frozenset({"flagd", "flagd-ui"})
BLOCKED_TEXT = ("flagd", "feature_flag", "featureflag", "faultctl")
BLOCKED_ATTR_PREFIXES = ("feature_flag", "flagd")
BLOCKED_SPAN_REGEX = ".*(flagd|feature_flag|featureflag).*"  # for PromQL span_name!~"..."

_BLOCKED_RE = re.compile("|".join(re.escape(t) for t in BLOCKED_TEXT), re.I)


def is_blocked_service(name) -> bool:
    return str(name or "").lower() in BLOCKED_SERVICES


def is_blocked_text(text) -> bool:
    """True if a metric name, span name, log line, commit line or PromQL string mentions flag telemetry."""
    return bool(_BLOCKED_RE.search(str(text or "")))


def is_blocked_attr(key) -> bool:
    return str(key or "").lower().startswith(BLOCKED_ATTR_PREFIXES)
