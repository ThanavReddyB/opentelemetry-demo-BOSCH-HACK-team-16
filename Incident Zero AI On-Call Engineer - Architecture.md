# Incident Zero: AI On-Call Engineer

*Architecture and design document (v2). Bosch Incident Zero hackathon, PES University. Team 16: [team name and members].*

## 1. Overview

When a production system breaks, an on-call engineer reads logs, checks dashboards, looks at recent changes, guesses the cause and applies a fix under pressure. Our agent does that first hour on the OpenTelemetry Demo (the Astronomy Shop): it detects an incident, investigates with read-only observability tools, names the root cause with cited evidence and a confidence level, proposes a fix from the approved runbook, waits for an explicit human yes, executes through the Action API only, and verifies from fresh telemetry that the system recovered. It then writes an incident report.

**Design rule: the LLM proposes, deterministic code decides.** The model chooses which tool to call next, ranks hypotheses and proposes a remediation. Plain code checks the evidence, enforces the allowlist and approval, executes through the Action API, and judges recovery. When the agent is not confident, it escalates to a human with everything it found. The brief treats that as a correct outcome that scores better than a confident wrong fix.

## 2. Rules we design to

Every rule from the brief, and the mechanism that enforces it.

| Rule from the brief | How we enforce it |
| --- | --- |
| Change the system only through the Action API, only after human approval | The LLM has no execution tool. Only the `executor` module can reach the Action client, and it requires a valid, unconsumed approval. The agent package has no `docker stop/restart/update`, no `docker compose up/down`, and no flag-file write. |
| Reading feature-flag settings to diagnose is disqualifying | The agent package never touches `flagd`, `demo.flagd.json`, the `/feature` UI or flagd's OFREP endpoint. A guard test greps the agent package for these strings and fails the build. Telemetry that mirrors flag state is filtered (section 5). Flag names used in remediation come from the runbook allowlist, never from flagd. |
| Tampering with the demo, faultctl, hidden incidents or the scoring harness is disqualifying | Our own injector lives outside the agent package (`devtools/`), is never imported by the agent, and is named differently from the organisers' `faultctl` so it cannot be mistaken for it. We never read the organisers' tool or incident definitions from agent code. |
| Evidence must exist in the data; invented evidence is penalised | Every claim cites observation IDs. The validator rejects any citation that does not exist, is from another incident, or came from a failed query (section 7). |
| Provide a dry-run mode and a kill switch | Section 9. Both are required for the Day 2 minimum, so they are built and demonstrated, not just designed. |
| Be honest about what does not work | Limitations and the evaluation note list real failures. Offline runs are labelled Simulated. |
| Every member commits code (Team of 5); all code written on the day from 09:15 | Each of the 5 team members owns at least one module/deliverable (section 14) and commits code directly. No pre-built code is pushed. |
| AI coding assistants must be declared; every member can explain and change what they submit | Team form lists every AI assistant and model used. Each owner walks the mentor through their module. |
| Open-source libraries and agent frameworks are allowed | We use a plain tool-calling loop plus a few libraries (HTTP client, `jsonschema`). Libraries go on the team form. |

## 3. Scope tiers

The milestones set the minimum: by Checkpoint 1 an agent that sees real evidence, by Checkpoint 2 correct diagnosis on at least 3 practice incidents, and by code freeze a full loop on at least one incident, a kill switch that works, and all deliverables. We build in that order and cut from the bottom if time runs short.

| Tier | What | Target |
| --- | --- | --- |
| Must (Day 1) | Detector, tools for traces, metrics, logs, container health and deployment history, agent loop, evidence store, diagnosis in the organisers' JSON schema, 1-page sketch | Checkpoints 1 and 2 |
| Must (Day 2) | Remediation policy, approval CLI, executor with dry-run, kill switch, recovery verifier, incident report, README, evaluation note, team form | Checkpoint 3 and code freeze |
| Should | Validator contradiction handling, signature hints, multi-round combined incidents, prompt-injection tests | After the first full loop works |
| Stretch | Calibrated confidence, prevention suggestion in the report, chat-style approval UI, incident memory, reviewer agent | Only if everything above is solid |

## 4. Architecture at a glance

One agent process, run alongside the demo stack. No queue, no server database, no multi-agent framework, no model training.

```
alert/detector ─► orchestrator (state machine) ─► agent loop (LLM) ─► read-only tools ─► Prometheus / Jaeger / logs / docker health
                        │                              │
                        │                              ▼
                        │                      evidence store ─► validator ─► diagnosis (JSON schema)
                        ▼                                                         │
                  audit log (JSONL)                                  remediation policy (allowlist)
                        ▲                                                         │
                        │                                              approval (human, bound to action)
                        │                                                         │
                 report builder ◄─ recovery verifier ◄─ executor ◄── kill switch ──┘
                                                          │
                                                    Action API (only)
```

| Module | Role | Nature |
| --- | --- | --- |
| Detector | Watches error rate and latency per service and per operation, plus restarts, against a healthy baseline, and opens an incident | Deterministic |
| Orchestrator | Drives the incident state machine; the only writer of state | Deterministic |
| Agent loop | Chooses the next read-only tool, interprets results, proposes hypotheses and a remediation | LLM |
| Observability tools | Typed, read-only, summarised access to telemetry | Deterministic |
| Evidence store and validator | Stores sourced observations and checks each claim | Deterministic |
| Remediation policy | Allowlist, parameter schema, target seen in this incident | Deterministic |
| Approval service | Records the human decision, bound to the exact action | Deterministic |
| Executor and Action client | The only code that calls the Action API, and only after valid approval | Deterministic |
| Recovery verifier | Judges recovery from fresh telemetry | Deterministic |
| Audit log and reporter | Append-only event log; builds the report from it | Deterministic |

## 5. Data sources and tools

The agent sees telemetry only through typed tools. Each tool takes a time window with a recent default and returns a compact summary (top N groups, counts, trends, a few sample lines), never a raw dump. Tool output is untrusted text: it is truncated, labelled, and can never trigger an action.

| Tool | Backend (verified in our environment unless noted) | Returns |
| --- | --- | --- |
| `get_metrics(service, metric, window)` | Prometheus at `localhost:9090`. Filter by the `service_name` label, not `job` (only `ad` appears under `job`). Container CPU and memory series exist (`container_cpu_utilization_ratio`, `container_memory_percent_ratio`), plus HTTP client and DB duration histograms, and span-derived RED metrics (`traces_span_metrics_calls_total`, `traces_span_metrics_duration_milliseconds_bucket`). | Trend, current value, change versus baseline |
| `search_traces(service, operation, only_errors, window, limit)` | Jaeger through the proxy at `localhost:8080/jaeger/api` (or `/jaeger/ui/api`). Other services use random ports that change on restart, so we never hardcode them. | Failing or slow traces with trace IDs, failing span names and error tags |
| `get_trace(trace_id)` | Same Jaeger API | Span tree summary: the earliest failing span and its parent chain |
| `search_logs(service, pattern, level, window)` | OpenSearch is not running on our laptops, so the live fallback is container logs through `docker compose logs`. Offline bundles carry recorded logs. | Top repeated error lines with counts and sample IDs |
| `get_container_health()` | Read-only container status: state, restart counts, health | Stopped, restarting or unhealthy services |
| `get_deploy_history(window)` | Action API call log and the starter kit's source (to confirm) | Recent restarts, flag toggles, scaling actions |
| `find_anomalies(window)` | Computed from the tools above | Error rate by service and operation, earliest failing span, resource trends. The agent chooses to call it. |

**Filtered because it mirrors the answer key.** Tool output excludes the `flagd` service's spans, any `feature_flag.*` attributes or events, and the `feature_flag_evaluation_requests_total` metric (confirmed present in our Prometheus). Evidence for every fault remains derivable from error spans, latency, resources and restarts. We will ask the mentor whether this is stricter than required.

**Lesson from our first injected fault.** With the cart failure active, the checkout service showed a 17% error rate on one operation (`CartService/EmptyCart`) while the overall error graph barely moved. Detector and tools must therefore work per operation, not only per service.

**Noise to ignore.** Locust shows failures on `/prompt` because the demo's chatbot is not running, and startup errors appear while the stack boots. The detector computes baselines from service telemetry, not from Locust output.

## 6. The investigation loop

1. The detector opens an incident with the anomalous services and signals, the time window and the baseline.
2. The agent receives a compact incident view and chooses a read-only tool based on what it has found so far, not from a fixed order and not from one large pasted prompt.
3. The orchestrator validates the call against the tool schema and budgets, skips exact repeats, runs it, and stores the result as an observation with source identifiers.
4. The agent may call `find_anomalies` at any point. Signature hints for known faults (section 12) are optional scored hints inside that tool, never forced conclusions, so unseen faults are still reasoned from telemetry.
5. The loop is bounded by steps, tool calls, LLM calls and wall-clock time (configurable, tuned on the practice incidents, starting at 8 to 10 steps). Near a limit the agent must diagnose or escalate. Malformed model output gets one repair attempt, then a deterministic fallback or escalation.

## 7. Evidence and diagnosis

Every tool result becomes an **observation**: tool, query, window, service, collection time, a bounded summary and source identifiers (trace IDs, log record IDs, metric series). A **hypothesis** lists supporting and contradicting observations, confidence with rationale, and missing evidence.

A **diagnosis** is accepted only if deterministic checks pass:

- every cited observation exists and belongs to this incident;
- it concerns the claimed component, or a direct dependency seen in a trace, and overlaps the incident window;
- at least one supporting observation is independent of the original symptom;
- no cited observation came from a failed or timed-out query;
- contradicting evidence is recorded, and an unresolved contradiction lowers confidence and blocks remediation.

**Output format.** The final diagnosis conforms to the organisers' JSON schema from the template repository (failing component, cause, confidence, evidence). We validate with `jsonschema` before emitting and adopt the schema verbatim once we have it. Our internal model maps onto it and adds nothing the schema forbids.

**Escalation is a first-class outcome.** If validation fails, confidence is below the threshold, or no allowlisted action fits, the agent emits an escalation with its findings instead of a fix.

## 8. Incident lifecycle

States: Detected, Investigating, Diagnosed, Awaiting approval, Approved, Executing, Verifying, and terminal Resolved, Escalated, Rejected, Failed and Cancelled. Rejection, partial recovery and failed verification are recorded as reason codes on transitions.

- Single process, sequential workflow, one approver at a time. This keeps the machine small, so we skip compare-and-swap and concurrency machinery.
- State is written to a JSON file after each transition and every event to an append-only JSONL audit log. After a restart, an incident that was Executing moves to Verifying with an unknown-outcome flag and is never re-executed blindly.
- Round and retry limits stop endless loops; exhausting them escalates.

## 9. Safety design

- **Only the Action API can change the system.** The LLM has no execution tool. The executor reloads the approval, recomputes the digest, checks it is unexpired and unused, and consumes it before calling the API.
- **Approval is bound to the exact plan.** The approval records a SHA-256 digest of incident ID, proposal version, action, target, parameters and the declared rollback. A changed proposal creates a new version and voids earlier approvals. Replaying an approval for another incident or action fails.
- **Policy before approval.** The action must be in the runbook allowlist, parameters must match its schema, and the target must be a service seen in this incident.
- **Dry-run.** The approval prompt always shows the exact Action API request the executor would send. `--dry-run` runs the whole loop and logs `WOULD CALL ...` without calling anything.
- **Kill switch.** A single command (`killswitch on`) writes a marker file and takes effect immediately: the loop stops before its next step, every pending approval is voided, and the executor refuses all Action API calls. The loop and executor check it before every tool call and every action. We demonstrate it live; it is a Day 2 minimum requirement.
- **Rollback is part of the approved plan.** If verification fails and the action has a natural inverse (a flag turned back, a throttle restored), the rollback is shown at approval time and covered by the same yes. A restart has no inverse, so a failed restart escalates instead of assuming a rollback.
- **No secrets** in prompts, logs, records or reports. API keys live in a git-ignored `.env`.
- **Telemetry is untrusted.** Log text that looks like an instruction is treated as data.

## 10. Recovery verification

Executing an action and resolving an incident are separate phases. After the Action API call, the verifier builds criteria from the anomaly that opened the incident and its healthy baseline, for example the affected operation's error rate back inside its normal band. It collects only telemetry from after the action plus a settle period, requires several consecutive passing samples, and waits through a hold window to catch regression. Defaults are tuned on practice incidents. Missing telemetry means inconclusive, and the system escalates. Resolved requires every criterion to pass on fresh evidence; a successful API response alone never counts.

## 11. Unseen and combined incidents

The final evaluation uses unseen incidents, including infrastructure faults and combinations. An incident holds a set of open anomalies, each keyed by service and signal. Each remediation round targets one hypothesis and is verified on its own; if anomalies remain, the incident returns to investigation, up to a round limit. Signature hints are only hints, so the agent can reason about faults it has no rule for. This is a Should-tier item, built after the first full loop.

## 12. Fault coverage

The responses below are expectations to confirm against the real Action API allowlist once we have the starter kit.

| Fault | Main signals | Likely allowlisted response |
| --- | --- | --- |
| Payment charge fails | Error spans on charge, checkout 5xx | Toggle the fault flag off, or restart payment |
| Payment unreachable | Checkout connection errors, payment receives no traffic | Toggle the flag off |
| Cart fails intermittently | Partial error rate on one cart operation | Toggle the flag off |
| One product fails in catalog | Errors concentrated on one product | Toggle the flag off |
| Recommendation memory leak | Memory growing steadily, restarts, rising latency | Restart, then toggle the flag off |
| Ad service high CPU or GC | CPU and GC series, ad latency | Toggle the flag off |
| Homepage traffic flood | Request-rate spike at the frontend from the load generator | Throttle the load generator |
| Container stopped or restarting | Restart count, missing spans | Restart the service |
| Cache or database unavailable | Downstream connection errors | Restart the dependency |
| Latency or loss between services | Client span time far above server span time | Escalate if nothing allowlisted applies |
| CPU or memory starvation | Throttling, out-of-memory restarts | Restart; scaling only on Kubernetes |

Our environment runs on Docker Compose, so the scale action is not available locally. Policy must read available actions from the Action API instead of assuming scaling exists.

## 13. Deployment and technology

- **Reused:** the OpenTelemetry Demo with its collector, Prometheus and Jaeger, the load generator, the organisers' Action API, offline incident bundles, JSON schema, template repository and the provided LLM access (all from the starter kit; see open questions).
- **New:** one agent process following the template's language, JSON/JSONL files for state and audit, a small approval CLI, a mock Action client, and the test harness.
- **LLM:** a provider-agnostic OpenAI-compatible client configured through `LLM_BASE_URL`, `LLM_MODEL` and `API_KEY`. The default is the organisers' provided key. We use another provider only if the mentor confirms it is allowed, and we declare it on the team form. Retry with backoff, token caps, and deterministic fallbacks so a rate limit never stalls an incident.
- **Offline mode:** laptops that cannot run the full demo read the offline bundles. Every record is marked offline, actions go to a labelled mock, and the final status is Simulated, not Resolved, unless the bundle holds real post-action telemetry.
- **Backends are config, not code:** all endpoints live in one config file. Ports other than 8080 and 9090 are random, so tools resolve them at startup or go through the proxy.

## 14. Repository layout and ownership (Team of 5)

```
oncall-agent/          agent package (never imports faultctl or reads flagd to diagnose)
  agent.py             LLM investigation loop + grounded diagnosis + full incident orchestrator
  jaeger_tools.py      Read-only Jaeger trace & root-error hotspot tools
  ops_tools.py         Read-only Prometheus metrics, container health, logs, topology & triage tools
  registry.py          Merged tool registry, observation store & evidence grounding validator
  action_api.py        Allowlisted Action API, SHA-256 human approval gate, kill switch, verifier & reporter
  check_llm.py         LLM connectivity & tool-calling verification script
  ask_llm.py           Quick LLM sanity check CLI
faultctl.py            Practice-incident injector (dev/test tool only, outside agent package)
Incident Zero AI On-Call Engineer - Architecture.md
```

Each of the **5 team members** owns and commits a distinct component:
1. **Member 1 (Infra & Fault Injection)**: `faultctl.py`, Docker Compose setup & environment verification.
2. **Member 2 (Trace & Topology Tools — "Eyes")**: `oncall-agent/jaeger_tools.py` (`error_hotspots`, `trace_detail`, `attribute_skew`, `edge_latency_gap`).
3. **Member 3 (Metrics, Logs & Triage Tools — "Eyes")**: `oncall-agent/ops_tools.py` (`triage`, `container_health`, `get_logs`, `metric_trend`, `topology`).
4. **Member 4 (Agent Loop & Evidence Grounding — "Brain")**: `oncall-agent/agent.py`, `oncall-agent/registry.py`, `oncall-agent/check_llm.py`.
5. **Member 5 (Safety, Human Approval, Action API & Reporting — "Hands")**: `oncall-agent/action_api.py` (Approval Gate, Kill Switch, Dry-Run, Recovery Verifier, Incident Reports) & Architecture/Evaluation docs.

## 15. Testing and evaluation

A harness injects each practice incident, runs combinations by injecting two faults, resets between runs, and checks the audit log. A mock Action API supports timeouts, errors and duplicate calls. Safety tests cover: prompt injection in logs, a non-allowlisted action, an unobserved target, a modified proposal after approval, approval replay, an expired approval, a timeout where the action was applied, a crash after execution, a duplicate request, a failed recovery, a regression after recovery, unavailable verification telemetry, kill switch during each state, and the guard test that the agent package never references flag files or the injector. We report measured results (root-cause accuracy, evidence quality, unsafe action rate, approval bypass rate, verification correctness, tool calls, duration) separately from targets, and list wrong diagnoses honestly in `EVALUATION.md`.

## 16. Deliverables checklist (due at code freeze)

- [ ] Source code forked from the template, with a README covering setup, how to run, the approval gate, the kill switch and known limitations
- [ ] One-page architecture overview (components, tools, how the agent decides, safety controls)
- [ ] Incident reports for the practice incidents in the provided JSON schema plus a readable form (timeline, root cause, evidence, action taken, what would prevent a repeat)
- [ ] Evaluation note: which practice incidents the agent got right and wrong, and why
- [ ] Team form: name, members, who built which part, tools and AI models used (including AI coding assistants), third-party libraries

## 17. Limitations (current, to keep honest)

- Logs: OpenSearch is not running on our laptops, so live log search falls back to container logs.
- Span-derived metric names are unconfirmed, so error-rate queries are not final.
- The Action API, JSON schema, template repository and offline bundles have not been seen yet; interfaces are written against a mock until they arrive.
- Network faults may have no allowlisted fix; the correct outcome there is escalation with findings.
- Deployment history depends on what the starter kit provides.

## 18. Open questions for the mentor

1. Where do we get the starter kit: Action API, JSON schema, template repository, offline bundles?
2. Teams of 5, but one rule says "all 3 members must commit". Which applies?
3. Code freeze: 14:00 on Day 2 (milestones slide) or 16:30 (deliverables slide)?
4. Do span attributes or metrics that mirror flag state count as reading feature-flag settings?
5. Is a third-party hosted LLM (for example Groq) allowed, or must we use the provided key?
6. How does the automated hidden test handle approval? We will not add any auto-approve path without explicit permission.
7. Is the scale action available on Docker Compose?