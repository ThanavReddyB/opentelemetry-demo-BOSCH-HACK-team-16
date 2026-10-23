# Incident Zero: AI On-Call Engineer

*Architecture document. Bosch Incident Zero hackathon, PES University. Team: \[team name and members\]*

## 1. Overview

When a production system breaks, an on-call engineer reads logs, checks dashboards, looks at recent changes, guesses the cause and applies a fix under pressure. Most of that first hour is searching and correlating. Our system does that first hour automatically on the OpenTelemetry Demo (the Astronomy Shop): it detects an incident, investigates with real observability tools, names the root cause with cited evidence and a confidence level, proposes a fix from the approved runbook, waits for explicit human approval, executes the fix, and verifies from fresh telemetry that the system actually recovered. It then produces an incident report.

The central design rule is that the **LLM proposes and deterministic code decides**. The language model chooses which tool to call next, ranks hypotheses and proposes a remediation. Plain code checks the evidence, enforces the allowlist, enforces approval, executes through the Action API only, and judges recovery. When the agent is not confident, it escalates to a human with everything it found, which the brief treats as a correct outcome.

## 2. Requirements and constraints

- Handle application faults: payment charge failure, cart failures, a failing product in the catalog, a memory leak in recommendations, high CPU or garbage collection in the ad service, and a traffic flood on the homepage.
- Handle infrastructure faults injected by the organisers: a stopped or restarting container, cache or database unavailable, network latency or packet loss between services, and CPU or memory starvation.
- Handle unseen incidents and combinations at evaluation, so the agent must reason from telemetry and must not read feature-flag settings as the answer.
- Change the system only through the Action API: restart a service, toggle a feature flag, throttle the load generator, scale a service (Kubernetes only). Every call is logged.
- Evidence must exist in the data. Invented evidence is penalised.
- Nothing changes without an explicit human yes. Provide dry-run and a kill switch.

## 3. Architecture at a glance

The solution is one agent process with ten modules and one SQLite file, running alongside the existing demo stack. We deliberately avoid microservices, queues and a server database because the workflow is sequential and the time is short.

| Module | Role | Nature |
| --- | --- | --- |
| Intake and detector | Watches error rate, latency and restarts against a healthy baseline and opens an incident | Deterministic |
| Orchestrator | Drives the incident state machine; the only writer of state | Deterministic |
| Agent loop | Chooses the next read-only tool, interprets observations, proposes hypotheses and a remediation | LLM (Groq) |
| Observability tools | Typed, read-only access to traces, metrics, logs, container health and deployment history | Deterministic |
| Evidence and validator | Stores sourced observations; checks that each diagnostic claim is supported | Deterministic |
| Remediation policy | Checks that a proposed action is allowlisted, has valid parameters and targets a service seen in this incident | Deterministic |
| Approval service | Records the human decision, bound to the exact action | Deterministic |
| Executor and Action adapter | The only code that calls the Action API, and only after a valid approval | Deterministic |
| Recovery verifier | Judges recovery from fresh telemetry against measurable criteria | Deterministic |
| Audit log and reporter | Append-only event log; builds the report from it | Deterministic |

## 4. The investigation loop

1. The detector opens an incident with the anomalous services and signals, the time window and the baseline.
2. The agent receives a compact view of the incident and chooses a tool from the read-only set. It decides based on what it has found so far, not from a fixed order.
3. The orchestrator validates the call against the tool schema and the budgets, skips exact repeats, runs the tool, and stores the result as an observation with its source identifiers.
4. Generic anomaly localisation always runs: error rate by service and by span attribute, the earliest failing span, resource trends and restart counts. Signature rules for the known faults add scored hints. The LLM ranks hypotheses and asks for more evidence where they conflict.
5. The loop is bounded by limits on steps, tool calls, LLM calls and wall-clock time (all configurable and tuned on the practice incidents). When a limit nears, the agent must decide: diagnose or escalate. Malformed model output gets one repair attempt, then a deterministic fallback or escalation.

Tool results are summarised before they reach the model, so the model sees the top error groups, trends and a few log lines, not raw dumps. Telemetry text is treated as untrusted input: it is truncated, labelled, and can never trigger an action by itself.

## 5. Evidence and diagnosis

Every tool result becomes an **observation**: tool, query, time window, service, collection time, a bounded summary and identifiers pointing back to the source (trace IDs, log record IDs, metric series). A **hypothesis** lists supporting and contradicting observations, confidence with a rationale, and the missing evidence. A **diagnosis** is accepted only if deterministic checks pass:

- every cited observation exists and belongs to this incident;
- it concerns the claimed component (or a direct dependency seen in a trace) and overlaps the incident window;
- at least one supporting observation is independent of the original symptom;
- no cited observation came from a failed or timed-out query;
- contradicting and negative evidence is recorded, and an unresolved contradiction lowers confidence and blocks remediation.

This lets the system separate cases that look alike, for example a payment service that fails on charge (it receives traffic and errors) from one that is unreachable (checkout errors while payment receives nothing).

## 6. Incident lifecycle

The orchestrator runs a small state machine. States: Received, Investigating, Diagnosed, Awaiting approval, Approved, Executing, Verifying, and the terminal states Resolved, Escalated and Cancelled. Outcomes such as rejection, action failure, partial recovery and failed verification are recorded as reason codes on transitions, which keeps the machine small and every path testable.

Key rules enforced in code:

- Transitions use compare-and-swap, so two concurrent approvals cannot both proceed.
- State is persisted in SQLite, so a restart during approval, execution or verification resumes correctly.
- If a restart or timeout leaves the outcome of an action unknown, the system never re-executes blindly. It moves to verification with an unknown-outcome flag, or reconciles against the Action API call log if it can be read.
- Limits on rounds and retries stop endless loops; exhausting them escalates.

## 7. Safety design

- **Only the Action API can change the system.** The LLM has no execution tool, and only the executor module can reach the Action API client.
- **Backend-enforced approval.** An approval is bound to a digest of the exact incident, proposal version, action, target and parameters. The executor reloads it, recomputes the digest, checks expiry and single use, and consumes it in the same transaction that moves the incident to Executing. A changed proposal creates a new version, which voids earlier approvals. Replaying an approval for another incident or action fails.
- **Policy before approval.** An action must be in the runbook allowlist, parameters must match the action's schema, and the target must be a service seen in this incident's observations.
- **Dry-run and kill switch** are available at the approval and execution steps.
- **Reversibility is explicit.** Rollback is offered only where the Action API has a natural inverse (such as turning a flag back or restoring a throttle). A service restart has none, so a failed restart leads to escalation rather than an assumed rollback.
- **No secrets** in prompts, logs, records or reports.

## 8. Recovery verification

Executing an action and resolving an incident are separate phases. After the Action API call, the verifier builds criteria from the anomaly that opened the incident and the healthy baseline, for example error rate for the affected service back within its normal band. It then collects only telemetry gathered after the action completed plus a settle period, requires several consecutive passing samples, and waits through a hold window to catch regression. If telemetry is missing, the result is inconclusive and the system escalates. An incident is reported Resolved only when every criterion passes on fresh evidence. Successful API execution alone never counts.

## 9. Unseen and combined incidents

An incident holds a set of open anomalies, each keyed by service and signal. Each remediation round targets one hypothesis and is verified on its own. If anomalies remain, the incident returns to investigation for another round, up to a round limit. Because generic localisation always runs and signature rules are only hints, the system can reason about faults it has no rule for, and the agent is evaluated on a held-out set of invented faults and combinations in addition to the practice incidents.

## 10. Fault coverage

| Fault | Main signals the agent looks for | Typical allowlisted response |
| --- | --- | --- |
| Payment charge fails | Error spans on charge, checkout 5xx | Disable the fault flag, or restart payment |
| Payment unreachable | Checkout connection errors, payment receives no traffic | Disable the fault flag |
| Cart fails intermittently | Partial error rate on one cart operation | Disable the fault flag |
| One product fails in catalog | Errors concentrated on one product attribute | Disable the fault flag |
| Recommendation memory leak | Memory growing steadily, restarts, rising latency | Restart, then disable the flag |
| Ad service high CPU or GC | CPU and GC pause series, ad latency | Disable the flag, or scale |
| Homepage traffic flood | Request-rate spike at the frontend from the load generator | Throttle the load generator |
| Container stopped or restarting | Restart count, missing spans | Restart the service |
| Cache or database unavailable | Downstream connection errors | Restart the dependency |
| Latency or loss between services | Client span time far above server span time | Escalate if no allowlisted fix applies |
| CPU or memory starvation | Throttling, out-of-memory restarts | Scale the service, or restart |

The agent never reads feature-flag configuration as evidence. It diagnoses from telemetry, and flag toggles are used only as a remediation through the Action API.

## 11. Deployment and technology

- **Existing, reused:** the OpenTelemetry Demo stack with its collector and bundled trace, metric and log backends, the load generator, the organiser's `faultctl`, the Action API, offline incident bundles, the template repository and the provided LLM access.
- **New:** one agent process (language and framework following the template), a SQLite file for state and audit, a small approval endpoint with a command-line client, and the test harness.
- **LLM:** Groq through its OpenAI-compatible API, with retry and backoff, token caps, and deterministic fallbacks so a rate limit does not stall an incident.
- **Offline mode:** if a laptop cannot run the full demo, the same tools read from the offline bundles. Every record is marked offline, actions go to a clearly labelled mock, and the final status is Simulated, not Resolved, unless the bundle contains real post-action telemetry.
- **Deliberately not built:** a message queue, a server database, a multi-agent framework, a custom dashboard and model training.

## 12. Testing and evaluation

A harness injects each practice incident through `faultctl`, runs combinations by injecting two faults, resets between runs, and checks the event log. A mock Action API supports timeouts, errors and duplicate calls so safety behaviour can be tested without risk. The safety tests cover: prompt injection in logs, a non-allowlisted action, an unobserved target, a modified proposal after approval, approval replay, concurrent approvals, an expired approval, a timeout where the action was applied, a crash after execution, a duplicate request, recovery that fails, recovery that regresses, and unavailable verification telemetry. Measured results (root-cause accuracy, evidence quality, unsafe action rate, approval bypass rate, verification correctness, tool calls and duration) are reported separately from targets.

## 13. Limitations and future work

- Deployment history and some backend details depend on what the starter kit provides.
- Network faults may have no allowlisted fix, in which case the correct outcome is escalation with findings.
- Possible later improvements: learned per-service baselines, topology-based causal checks, replay scoring over recorded incidents, and a read-only status page.
