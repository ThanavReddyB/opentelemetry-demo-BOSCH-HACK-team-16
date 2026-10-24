# Incident Zero: AI On-Call Engineer (one-page overview)

**Idea:** the LLM proposes, deterministic code decides. The agent investigates with read-only tools, cites evidence, asks a human before any change, acts only through the action layer, and verifies recovery from fresh telemetry. If it is not confident, it escalates with its findings.

```
detector ─► agent loop (LLM) ◄─► read-only tools (fairplay-filtered) ─► Prometheus · Jaeger · docker logs & health
(no LLM)          │
         registry (obs-N) + grounding + finalize() ─► diagnosis (JSON, confidence, cited evidence)
                  │
         build_action_plan (runbook allowlist) ─► HUMAN APPROVAL (SHA-256 digest, dry-run option)
                  │                                        │
     execution gates (kill switch ...) ─► remediation_adapters ─► verify_recovery ─► incident report
```

## Components
- **Detector (`detector.py`, no LLM):** scans Prometheus span metrics and Docker state against a healthy baseline: error rate >2% and 2% above baseline, p95 >50 ms and >2x baseline, traffic <20% of baseline, containers down, restarted or OOM-killed, CPU or memory pressure. An anomaly must persist for 2 consecutive scans; a handled signature is ignored for 600 s. Scores rank severity.
- **Agent loop (`agent.py`, LLM):** picks the next tool from what it has found so far. The alert gives symptoms only. It must query all five pillars (metrics, traces, logs, containers, deploys) before finalizing.
- **Tools (read-only):** `triage`, `get_metrics`, `metric_trend`, `error_hotspots`, `trace_detail`, `attribute_skew`, `edge_latency_gap`, `get_logs`, `container_health`, `topology`, `deploy_history`. Each returns a short summary tagged with an observation ID, never a raw dump.
- **Evidence grounding (`registry.py`):** every citation must point to an existing, non-empty observation and share at least 60% of its words with that output; quoted trace IDs must appear in it. `finalize()` drops ungrounded items, downgrades confidence, and applies container-state guards.
- **Policy, approval, executor, verifier, reporter (`action_api.py`) and `remediation_adapters.py`:** deterministic code, described below.
- **LLM router (`llm.py`):** provider fallback, rate-limit pacing, key hot-swap.

## How the agent decides
1. The detector opens an incident; the agent chooses tools step by step.
2. It cites observations. High confidence needs at least 2 grounded items, nothing dropped and all 5 pillars queried; with no grounded evidence it escalates.
3. Deterministic guards override the LLM when container state contradicts it (for example a stopped dependency).
4. `build_action_plan` maps the diagnosis to one of 4 allowlisted actions (`restart_service`, `toggle_feature_flag`, `throttle_load_generator`, `scale_service`, which is unsupported on Docker Compose) or escalates. A human then approves.
5. `verify_recovery` waits 75 s, then needs 2 clean scans 20 s apart. If recovery fails, it rolls back where reversible and escalates. Up to 3 rounds handle cascading faults.

## Safety controls
- **Human approval first.** The LLM has no execution tool and there is no auto-approval path. Approval is single-use, expires after 600 s, and is bound to a SHA-256 digest of the exact plan.
- **Execution gates:** kill switch, approval, single-use, expiry, digest, allowlist re-validation, and a circuit breaker (fewer than 3 actions per hour). Only `remediation_adapters.py` changes the demo.
- **Dry-run.** Typing `dry-run` at the approval prompt shows the exact request without sending it.
- **Kill switch.** A `KILL_SWITCH` file or `KILL_SWITCH=1` makes the executor refuse every action.
- **No answer-key reads.** `fairplay.py` blocks flagd telemetry and anything mentioning flag state before it reaches the LLM. Remediation flag names come from the runbook, never from flagd.
- **Untrusted telemetry, no secrets.** Log text is data, and keys live in a gitignored `.env`.
- **Honest reporting.** Every action is appended to `logs/audit.jsonl`; each incident gets a JSON and a Markdown report. Limitations are listed in the README and evaluation note.
