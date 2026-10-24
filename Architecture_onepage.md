# Incident Zero: AI On-Call Engineer (one-page overview)

**Idea:** the LLM proposes, deterministic code decides. The agent investigates with read-only tools, cites evidence, asks a human before any change, acts only through the Action API, and verifies recovery from fresh telemetry. If it is not confident, it escalates with its findings.

```
alert ─► detector ─► agent loop (LLM) ◄─► read-only tools ─► Prometheus · Jaeger · logs · container health · deploy history
                          │
                   evidence store + validator ─► diagnosis (JSON schema, confidence, cited evidence)
                          │
                   remediation policy (runbook allowlist) ─► HUMAN APPROVAL (bound to exact action, dry-run shown)
                          │                                        │
              kill switch ─┴──► executor ─► Action API (only) ─► recovery verifier ─► incident report
```

## Components
- **Detector:** error-rate and latency thresholds per service and per operation, plus restarts, against a healthy baseline.
- **Agent loop:** the LLM picks the next tool from what it has found so far (step cap, repeat skipping, one repair attempt for bad output).
- **Tools (read-only):** `get_metrics`, `search_traces`, `get_trace`, `search_logs`, `get_container_health`, `get_deploy_history`, `find_anomalies`. Each returns a short summary with source IDs, never a raw dump.
- **Evidence store and validator:** every claim cites observations that exist, belong to this incident and came from successful queries.
- **Policy, approval, executor, verifier, reporter:** deterministic code, described below.

## How the agent decides
1. The detector opens an incident; the agent chooses tools step by step.
2. It forms hypotheses with supporting and contradicting evidence and a confidence level.
3. The validator accepts a diagnosis only if the evidence checks pass; otherwise the agent investigates more or escalates.
4. It proposes one allowlisted fix with a short reason, then waits for a human.
5. After an approved action, a verifier checks fresh telemetry for several consecutive healthy samples. If recovery fails, it rolls back where an inverse exists and escalates.

## Safety controls
- **Action API only, human approval first.** The LLM has no execution tool. Approval is single-use, expires, and is bound to a digest of the exact action, target, parameters and rollback.
- **Dry-run mode.** Shows the exact request without sending it; always shown at approval time.
- **Kill switch.** One command halts the loop, voids pending approvals and blocks all Action API calls.
- **Allowlist and target checks** before approval; **no secrets** in prompts or logs; telemetry text treated as untrusted data.
- **No answer-key reads.** The agent never reads feature-flag settings, faultctl or the injector; flag-mirroring telemetry is filtered, and a guard test enforces it.
- **Honest reporting.** Offline runs are labelled Simulated; limitations are listed in the README and evaluation note.