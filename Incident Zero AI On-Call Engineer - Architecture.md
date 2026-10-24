# Incident Zero: AI On-Call Engineer

*Architecture and design document (v3, aligned with the implemented system). Bosch Incident Zero hackathon, PES University. Team 16: [team name and members].*

## 1. Overview

When a production system breaks, an on-call engineer reads logs, checks dashboards, looks at recent changes, guesses the cause and applies a fix under pressure. Our agent does that first hour on the OpenTelemetry Demo (the Astronomy Shop): it detects an incident, investigates with read-only observability tools, names the root cause with cited evidence and a confidence level, proposes a fix from the approved runbook, waits for an explicit human yes, executes through the Action API only, and verifies from fresh telemetry that the system recovered. It then writes an incident report. It is built from scratch in plain Python (no agent framework) as a 7-step flow: detection, investigation, evidence grounding, policy, human approval, execution, verification.

**Design rule: the LLM proposes, deterministic code decides.** The model chooses which tool to call next, ranks hypotheses and proposes a remediation. Plain code checks the evidence, enforces the allowlist and approval, executes through the Action API, and judges recovery. When the agent is not confident, it escalates to a human with everything it found. The brief treats that as a correct outcome that scores better than a confident wrong fix.

## 2. Rules we design to

Every rule from the brief, and the mechanism that enforces it.

| Rule from the brief | How we enforce it |
| --- | --- |
| Change the system only through the Action API, only after human approval | The LLM has no execution tool. Only `action_api.py` can trigger remediation, and its executor requires a valid, unconsumed approval. `remediation_adapters.py` is the only module that changes the running demo (container restart, flag edit, load-generator throttle). The agent loop, tools and registry contain no such calls. |
| Reading feature-flag settings to diagnose is disqualifying | `fairplay.py` filters every tool result before it reaches the LLM: all telemetry from `flagd` and `flagd-ui`, any span, metric or log containing "flagd", "feature_flag", "featureflag" or "faultctl", attributes starting `feature_flag.*` or `flagd.*`, and connections to flag-service ports (8013, 8015, 8016). The diagnosis path never reads flag settings. Flag names used in remediation come from the runbook allowlist, never from flagd. |
| Tampering with the demo, faultctl, hidden incidents or the scoring harness is disqualifying | Our own injector lives outside the agent package (`devtools/`), is never imported by the agent, and is named differently from the organisers' `faultctl` so it cannot be mistaken for it. We never read the organisers' tool or incident definitions from agent code. |
| Evidence must exist in the data; invented evidence is penalised | Every claim cites observation IDs (`obs-N`). The grounding check rejects any citation whose observation does not exist, was empty, or does not match the observation's actual output (section 7). |
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
detector ─► orchestrator (agent.py) ─► LLM investigation loop ─► read-only tools (fairplay-filtered) ─► Prometheus / Jaeger / docker logs & health
(no LLM)          │                            │
                  │                            ▼
                  │                  registry: obs-N observations ─► grounding + finalize() ─► diagnosis (JSON)
                  ▼                                                                │
            audit log (logs/audit.jsonl)                              build_action_plan (runbook allowlist)
                  ▲                                                                │
                  │                                                  human approval (SHA-256 digest, dry-run option)
                  │                                                                │
       reports (JSON + MD) ◄─ verify_recovery ◄─ execute_action ◄── gates (kill switch, expiry, circuit breaker ...)
                                                       │
                                              remediation_adapters.py (only code that changes the demo)
```

| Module | File | Role | Nature |
| --- | --- | --- | --- |
| Detector | `detector.py` | Scans for anomalies against a healthy baseline, with persistence and cooldown, and opens an incident | Deterministic |
| Orchestrator | `agent.py` | Drives detection, investigation, finalize, approval, execution and multi-round handling | Deterministic |
| Agent loop | `agent.py` | Chooses the next read-only tool, interprets results, proposes a diagnosis and remedy | LLM |
| LLM router | `llm.py` | Provider fallback, rate-limit pacing, key hot-swap | Deterministic |
| Observability tools | `ops_tools.py`, `jaeger_tools.py`, `metrics.py` | Typed, read-only, summarised access to telemetry | Deterministic |
| Fair play filter | `fairplay.py` | Blocks flag-service telemetry before it reaches the LLM | Deterministic |
| Registry and grounding | `registry.py` | Tool registry, observation store, evidence grounding | Deterministic |
| Policy, approval, executor, verifier, reporter | `action_api.py` | Allowlist and runbook, human approval gate, execution gates, recovery check, incident reports | Deterministic |
| Remediation adapters | `remediation_adapters.py` | The only module that changes the running demo | Deterministic |

## 5. Data sources and tools

The agent sees telemetry only through typed, read-only tools. Each returns a compact summary (top groups, counts, trends, a few sample lines), never a raw dump. Tool output is untrusted text: it is truncated, labelled, filtered by `fairplay.py`, and can never trigger an action.

| Backend | What it stores | How the agent reads it |
| --- | --- | --- |
| Prometheus (`localhost:9090`) | Span-derived metrics and container CPU and memory gauges | HTTP API (`/api/v1/query`). Filter by the `service_name` label, not `job` |
| Jaeger (`localhost:8080`) | Distributed traces with timing, errors and attributes | HTTP API (v3 OTLP JSON). Other services use random ports, so we never hardcode them |
| Docker | Container state, restart counts, OOM kills, logs | `docker inspect`, `docker compose logs` (OpenSearch is not running on our laptops) |

Key metrics: `traces_span_metrics_calls_total` (request and error rates per service, operation and status), `traces_span_metrics_duration_milliseconds_bucket` (p95 latency), `container_cpu_utilization_ratio` (1.0 = 100% of one core, so 5.4 = 540% across cores) and `container_memory_percent_ratio`.

| Tool | Module | Source | Returns |
| --- | --- | --- | --- |
| `triage` | `ops_tools.py` | Prometheus + Docker | Anomalies across all services versus baseline (about 15 parallel queries) |
| `container_health` | `ops_tools.py` | `docker inspect` + stats | Running, down, hot and restarted containers |
| `get_logs` | `ops_tools.py` | `docker compose logs` | Error lines for one service, grouped by pattern |
| `metric_trend` | `ops_tools.py` | Prometheus range query | First, last, min and max values plus leak detection |
| `topology` | `ops_tools.py` | Static call graph | Who calls whom |
| `deploy_history` | `ops_tools.py` | `docker inspect` + audit log | Recent container changes and past agent actions |
| `error_hotspots` | `jaeger_tools.py` | Jaeger | Deepest erroring spans (root causes) aggregated across traces |
| `trace_detail` | `jaeger_tools.py` | Jaeger | One trace: root errors and slowest spans |
| `attribute_skew` | `jaeger_tools.py` | Jaeger | Attributes over-represented in failing spans |
| `edge_latency_gap` | `jaeger_tools.py` | Jaeger | Client-versus-server span time gap per edge (network faults) |
| `get_metrics(metric=...)` | `metrics.py` | Prometheus | `error_rate` (per operation, worst first), `cpu`, `memory`, `latency_p95`, `request_rate` |

**Filtered because it mirrors the answer key.** `fairplay.py` removes the `flagd` and `flagd-ui` services' telemetry, anything mentioning flag state, and flag-service connections (section 2). Evidence for every fault remains derivable from error spans, latency, resources and restarts.

**Lesson from our first injected fault.** With the cart failure active, the checkout service showed a 17% error rate on one operation (`CartService/EmptyCart`) while the overall error graph barely moved. Detector and tools therefore work per operation, not only per service.

**Noise to ignore.** Locust shows failures on `/prompt` because the demo's chatbot is not running, and startup errors appear while the stack boots. The detector computes baselines from service telemetry, not from Locust output.

## 6. Detection and the investigation loop

**Detection (`detector.py`, no LLM).** `scan()` calls `ops_tools.triage()` and adds container signals from Docker. Triage compares the last 5 minutes with an earlier healthy baseline. It uses two earlier windows and picks the healthiest, so a previous incident does not poison the comparison.

| Signal | Source | Threshold | Score |
| --- | --- | --- | --- |
| Error-rate spike | Prometheus span metrics | > 2% and > 2% above baseline | 0 to 100 (= error %) |
| Latency spike | Prometheus duration histogram | p95 > 50 ms and > 2x baseline | 0 to 100 (ratio x 10) |
| Traffic drop | Prometheus request rate | below 20% of baseline | 90 |
| Container down | `docker inspect` | status not "running" | 100 |
| Container restarted or OOM-killed | `docker inspect` | recent restart or OOM kill | 70 |
| Container pressure | Docker stats via Prometheus | CPU >= 85% of cap or memory >= 92% | 60 |

An anomaly must appear in 2 consecutive scans before an incident opens, so one noisy scrape never pages anyone. After a fault is handled, the same signature is ignored for 600 seconds so a just-fixed fault does not reopen. Scores rank severity: dead containers and failing requests outrank slowness and resource pressure, and are investigated first.

**Investigation (`agent.py`, `_investigate()`).**

1. The alert text (symptoms only, never causes) goes to the LLM with a system prompt holding the service topology, an investigation strategy (batch tool calls, aim for 4 to 5 turns), rules of proof and the required JSON output format.
2. The agent chooses tools from what it has found so far, not from a fixed order. The registry runs each call through the fairplay filter, skips exact repeats, and stores the result as a numbered observation.
3. **Five-pillar rule.** Before finalizing, the agent must have queried all five categories: metrics, traces, logs, containers and deploys. If it tries to finalize early it is told to query the remaining pillars.
4. The loop is bounded by steps, tool calls, LLM calls and wall-clock time. Near a limit the agent must diagnose or escalate.

## 7. Evidence and diagnosis

Every tool call gets an observation ID (`obs-1`, `obs-2`, ...) injected into its response, and the registry stores the response text per observation. The LLM cites these IDs. For each cited item the grounding check verifies that:

- the observation exists;
- it was a non-empty result (an empty query proves nothing);
- at least 60% of the words in the citation appear in that observation's actual output;
- any long hex ID (trace or span ID) quoted appears in the tool output.

`finalize()` keeps grounded evidence in `evidence` and moves failed items to `dropped_ungrounded_evidence`. With zero grounded evidence, confidence is forced to low and the remedy to none/escalate.

**Confidence.** The LLM proposes a level and `finalize()` can override it.

| Confidence | When it is assigned |
| --- | --- |
| High | LLM said high, and at least 2 evidence items are grounded, and nothing was dropped, and all 5 pillars were queried |
| Medium | LLM said high but a condition above failed (downgraded); or LLM said medium and grounding passed; or a deterministic guard reclassified the diagnosis |
| Low | No grounded evidence survived (forced); or LLM said low; or LLM set `escalate_to_human` with fewer than 2 evidence items |

**Deterministic guards in `finalize()`.** These override the LLM when container state contradicts its diagnosis:

1. **Stopped dependency:** the blamed service depends on a container that is actually stopped, so retarget to that container.
2. **Unreachable but serving traffic:** "dependency_down" for a service that is receiving requests is reclassified to `app_error`.
3. **Stopped container priority:** any stopped container plus low confidence overrides to restarting the stopped container.
4. **Backing store running:** a claim that valkey-cart or astronomy-db is down while it is running becomes the caller's `app_error`.

**Output format.** The final diagnosis conforms to the organisers' JSON schema from the template repository (failing component, cause, confidence, evidence). We validate with `jsonschema` before emitting and adopt the schema verbatim once we have it. Our internal model maps onto it and adds nothing the schema forbids.

**Escalation is a first-class outcome.** If grounding leaves too little evidence, confidence is low with no runbook mapping, or no allowlisted action fits, the agent emits an escalation with its findings instead of a fix.

## 8. Incident lifecycle and rounds

Stages: detected, investigating, diagnosed, awaiting approval, approved, executing, verifying, then a terminal outcome (resolved, escalated, rejected or failed). Rejection, partial recovery and failed verification are recorded with reasons.

- Single process, sequential workflow, one approver at a time.
- Every action (approval requests, decisions, executions, rollbacks) is appended to `logs/audit.jsonl`, giving a complete audit trail.
- **Multi-round handling.** After a fix, the agent runs two fresh detector scans 30 seconds apart; anomalies present in both are real remaining faults. A new round then starts with the context "those faults are fixed, find what is still wrong", so it does not re-diagnose the same thing. Up to 3 rounds run. Exhausting them escalates.

## 9. Remediation policy and safety design

**Policy (`build_action_plan()`).** Deterministic code maps the diagnosis to one allowlisted action, or escalates. Allowed actions: `restart_service` (restart a Docker container), `toggle_feature_flag` (set a remediation flag to "off"), `throttle_load_generator` (reduce synthetic traffic through the Locust API) and `scale_service` (not supported on Docker Compose).

1. Parse the LLM's `suggested_remedy` for keywords ("restart", "toggle" or "flag", "throttle").
2. Runbook fallback: if nothing actionable was suggested, a component in `down_services` gets `restart_service`, and a known `(component, fault_class)` pair gets `toggle_feature_flag`.
3. Runbook override: a container that is actually down forces a restart (a flag toggle cannot revive it); a switch-fixable fault class with a known flag forces the toggle (a restart will not clear an app-level fault).
4. Low confidence: with no runbook mapping the incident auto-escalates; with a mapping the action is still proposed with a LOW CONFIDENCE warning and the human decides.

Runbook examples: `(payment, app_error)` to `paymentFailure`; `(cart, app_error)` to `cartFailure`; `(product-catalog, partial_failure)` to `productCatalogFailure`; `(ad, cpu_saturation)` to `adHighCpu`; `(recommendation, memory_leak)` to `recommendationCacheFailure`; `(email, memory_leak)` to `emailMemoryLeak`.

**Human approval (`request_human_approval()`).** The human sees the incident ID, component, fault class, confidence, root cause, all grounded evidence, the exact action, target and parameters, the rollback policy, a SHA-256 approval digest and any policy warnings (LOW CONFIDENCE, runbook override). They type `yes`, `dry-run` or `no`. **There is no auto-approval path.**

**Execution gates (`execute_action()`).** Every gate must pass:

| Gate | What it checks |
| --- | --- |
| Kill switch | The `KILL_SWITCH` file must not exist and env `KILL_SWITCH=1` must not be set |
| Approval | The human said yes |
| Single-use | The approval token has not been consumed |
| Expiry | The approval is under 600 seconds old |
| Digest | The plan's SHA-256 still matches, so it was not modified after approval |
| Re-validation | Parameters pass the allowlist checks again |
| Circuit breaker | Fewer than 3 actions executed in the last hour |

Only then does the executor call `remediation_adapters.py`, the only module that changes the running demo:

| Action | What it does | How |
| --- | --- | --- |
| `restart_service` | Restart or recreate a container | `docker compose restart` or `up -d --force-recreate` |
| `set_flag` | Set the remediation flag's variant to "off" | Write JSON to `src/flagd/demo.flagd.json` |
| `throttle_load` | Reduce synthetic traffic | POST to the Locust web API |

**Other controls.**

- **Dry-run.** Typing `dry-run` at the approval prompt shows the exact request the executor would send, and sends nothing.
- **Kill switch.** Creating the `KILL_SWITCH` file (or setting `KILL_SWITCH=1`) makes the executor refuse every action. We demonstrate it live; it is a Day 2 minimum requirement.
- **Rollback.** If verification fails and the action is reversible (for example a flag restored to its previous variant), it is rolled back and the incident is escalated. A restart has no inverse, so a failed restart escalates.
- **No secrets** in prompts, logs, records or reports. API keys live in a git-ignored `.env`.
- **Telemetry is untrusted.** Log text that looks like an instruction is treated as data.

## 10. Recovery verification

Executing an action and resolving an incident are separate phases. `verify_recovery()` first waits 75 seconds so old error metrics leave the 1-minute Prometheus rate window; checking immediately would still show stale errors. It then runs 2 consecutive clean scans, 20 seconds apart. A scan is clean only if:

- there are no anomalies for the target service or its callers;
- the target is not in `not_running` and is not CPU-capped;
- its dependencies are not stopped;
- traffic is actually flowing (silence is not recovery);
- telemetry is reachable (a blind scan never counts as a pass).

Two spaced samples guard against noise. If verification fails, the action is rolled back where reversible and the incident is escalated to a human. A successful API response alone never counts as recovery.

## 11. Unseen and combined incidents

The final evaluation uses unseen incidents, including infrastructure faults and combinations. The agent reasons from telemetry through generic tools; the runbook only maps known fault classes to actions, and a fault with no mapping escalates with findings. Combined and cascading faults are handled by the multi-round loop (section 8): each round targets what is still wrong and is verified on its own. For example, valkey-cart stopped (round 1: restart) exposes the cart service's own `app_error` (round 2: toggle flag).

## 12. Fault coverage

| Fault | What shows in telemetry | Agent's diagnosis | Fix |
| --- | --- | --- | --- |
| `paymentFailure` | `error_hotspots(checkout)` shows the root error in payment; error rate spikes | payment `app_error` | Toggle `paymentFailure` off |
| `cartFailure` | `get_logs(cart)` shows storage errors while valkey-cart is running | cart `app_error` (not dependency_down) | Toggle `cartFailure` off |
| valkey-cart stopped | `container_health()` lists valkey-cart in not_running | `container_crash_or_restart` | Restart service |
| `productCatalogFailure` | `error_hotspots` shows product-catalog errors | `partial_failure` | Toggle `productCatalogFailure` off |
| `recommendationCacheFailure` | `metric_trend(memory)` rises monotonically | `memory_leak` | Toggle `recommendationCacheFailure` off |
| `adHighCpu` | `get_metrics(cpu)` above 0.5, memory above 70%, no errors | `cpu_saturation` | Toggle `adHighCpu` off |

Other expected cases rely on the same tools and runbook: a homepage traffic flood is answered by throttling the load generator, and latency or loss between services (`edge_latency_gap`) escalates when nothing allowlisted applies. Our environment runs on Docker Compose, so `scale_service` is not available locally.

## 13. Deployment and technology

- **Reused:** the OpenTelemetry Demo with its collector, Prometheus and Jaeger, the load generator, the organisers' Action API, offline incident bundles, JSON schema, template repository and the provided LLM access (all from the starter kit; see open questions).
- **New:** one agent process in plain Python (files in section 14), a JSONL audit log, per-incident JSON and Markdown reports, an approval CLI, and offline unit tests (`tests/test_offline.py`, no Docker or LLM needed).
- **LLM:** `llm.py` is a router over providers. It falls back to the next provider when one's daily quota is hit, paces requests from the `x-ratelimit-remaining-tokens` headers instead of being rejected, and when every provider is exhausted it pauses and re-reads `.env` every 15 seconds so a new key can be dropped in and the agent resumes. It never silently switches to a weaker model unless explicitly configured. We declare every provider on the team form and use a third-party one only if the mentor confirms it is allowed.
- **Offline mode:** laptops that cannot run the full demo read the offline bundles. Every record is marked offline, actions go to a labelled mock, and the final status is Simulated, not Resolved, unless the bundle holds real post-action telemetry.
- **Backends are config, not code:** all endpoints live in one config file. Ports other than 8080 and 9090 are random, so tools resolve them at startup or go through the proxy.

## 14. Repository layout and ownership (Team of 5)

```
oncall-agent/              agent package (diagnosis path never reads flag settings)
  agent.py                 Orchestrator: LLM loop, system prompt, finalize, multi-round handling
  llm.py                   LLM router: provider fallback, rate-limit pacing, key hot-swap
  registry.py              Tool registry, evidence grounding, observation tracking
  detector.py              Incident detection (no LLM): persistence, cooldown, grouping
  ops_tools.py             Read-only tools: triage, containers, logs, trends, topology, deploys
  jaeger_tools.py          Read-only tools: error hotspots, trace detail, attribute skew, edge latency gap
  metrics.py               Read-only tool: focused Prometheus queries (CPU, memory, errors, latency, rate)
  fairplay.py              Blocks flag-service telemetry (anti-cheat)
  action_api.py            Policy layer: allowlist, runbook, approval gate, executor, verifier, reports
  remediation_adapters.py  The only file that changes the running demo
  check_llm.py             LLM connectivity & tool-calling verification script
  ask_llm.py               Quick LLM sanity check CLI
  .env                     API keys (gitignored, never committed)
  tests/test_offline.py    Unit tests (no Docker or LLM needed)
faultctl.py                Practice-incident injector (dev/test tool only, outside agent package)
Incident Zero AI On-Call Engineer - Architecture.md
```

Each of the **5 team members** owns and commits a distinct component:
1. **Member 1 (Infra & Fault Injection)**: `faultctl.py`, Docker Compose setup & environment verification.
2. **Member 2 (Trace & Topology Tools — "Eyes")**: `oncall-agent/jaeger_tools.py` (`error_hotspots`, `trace_detail`, `attribute_skew`, `edge_latency_gap`).
3. **Member 3 (Metrics, Logs & Triage Tools — "Eyes")**: `oncall-agent/ops_tools.py` (`triage`, `container_health`, `get_logs`, `metric_trend`, `topology`, `deploy_history`) and `oncall-agent/metrics.py` (`get_metrics`).
4. **Member 4 (Agent Loop & Evidence Grounding — "Brain")**: `oncall-agent/agent.py`, `oncall-agent/registry.py`, `oncall-agent/check_llm.py`.
5. **Member 5 (Safety, Human Approval, Action API & Reporting — "Hands")**: `oncall-agent/action_api.py` (Approval Gate, Kill Switch, Dry-Run, Recovery Verifier, Incident Reports) & Architecture/Evaluation docs.

Owner still to assign: `detector.py`, `llm.py`, `fairplay.py`, `remediation_adapters.py`.

## 15. Testing and evaluation

A harness injects each practice incident, runs combinations by injecting two faults, resets between runs, and checks the audit log. A mock Action API supports timeouts, errors and duplicate calls. Safety tests cover: prompt injection in logs, a non-allowlisted action, an unobserved target, a modified proposal after approval, approval replay, an expired approval, a timeout where the action was applied, a crash after execution, a duplicate request, a failed recovery, a regression after recovery, unavailable verification telemetry, kill switch during each state, and the guard test that the agent package never references flag files or the injector. We report measured results (root-cause accuracy, evidence quality, unsafe action rate, approval bypass rate, verification correctness, tool calls, duration) separately from targets, and list wrong diagnoses honestly in `EVALUATION.md`.

Offline unit tests live in `tests/test_offline.py` and need neither Docker nor an LLM.

## 16. Deliverables checklist (due at code freeze)

- [ ] Source code forked from the template, with a README covering setup, how to run, the approval gate, the kill switch and known limitations
- [ ] One-page architecture overview (components, tools, how the agent decides, safety controls)
- [ ] Incident reports for the practice incidents in the provided JSON schema plus a readable form (timeline, root cause, evidence, action taken, what would prevent a repeat)
- [ ] Evaluation note: which practice incidents the agent got right and wrong, and why
- [ ] Team form: name, members, who built which part, tools and AI models used (including AI coding assistants), third-party libraries

## 17. Limitations (current, to keep honest)

- Logs: OpenSearch is not running on our laptops, so live log search falls back to `docker compose logs`.
- `scale_service` is not supported on Docker Compose.
- Network faults may have no allowlisted fix; the correct outcome there is escalation with findings.
- The runbook only covers known fault classes; a fault with no mapping and low confidence escalates instead of acting.
- Remediation runs through our own `action_api.py` and `remediation_adapters.py` (including a write to the flag file for `toggle_feature_flag`). Whether this meets the organisers' Action API requirement still needs mentor confirmation (question 7).
- Free-tier LLM quotas can slow an incident; the router paces and pauses rather than failing.
- Deployment history is limited to `docker inspect` and our own audit log.

## 18. Open questions for the mentor

1. Where do we get the starter kit: Action API, JSON schema, template repository, offline bundles?
2. Teams of 5, but one rule says "all 3 members must commit". Which applies?
3. Code freeze: 14:00 on Day 2 (milestones slide) or 16:30 (deliverables slide)?
4. Do span attributes or metrics that mirror flag state count as reading feature-flag settings?
5. Is a third-party hosted LLM (for example Groq) allowed, or must we use the provided key?
6. How does the automated hidden test handle approval? We will not add any auto-approve path without explicit permission.
7. Does remediation through our own `action_api.py` and `remediation_adapters.py` (including writing the flag file for `toggle_feature_flag`) satisfy the "Action API only" rule, or must it go through the organisers' Action API?
