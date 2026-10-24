# AI On-Call Engineer — Architecture & Flow

## Overview

The AI On-Call Engineer is a 7-step autonomous incident response agent built from scratch in plain Python (no agent frameworks). It monitors the OpenTelemetry Astronomy Shop (a ~20-microservice e-commerce demo), detects faults from telemetry, diagnoses root causes using an LLM, proposes fixes through a deterministic policy layer, and executes them only after human approval.

**Core design principle**: the LLM only proposes — deterministic code decides.

---

## Where the Telemetry Comes From

The OpenTelemetry Demo runs ~20 microservices in Docker Compose. Every service is instrumented with OpenTelemetry, which sends data to three backends:

| Backend | What It Stores | How the Agent Reads It |
|---------|---------------|----------------------|
| **Prometheus** (`localhost:9090`) | Span-derived metrics: request counts, latency histograms, error rates. Container CPU/memory gauges. | HTTP API (`/api/v1/query`) |
| **Jaeger** (`localhost:8080`) | Distributed traces — full request trees across services with timing, errors, and attributes | HTTP API (v3 OTLP JSON) |
| **Docker** | Container state, restart counts, OOM kills, log output | `docker inspect`, `docker compose logs` |

### Key Prometheus Metrics

| Metric | What It Measures |
|--------|-----------------|
| `traces_span_metrics_calls_total` | Counter of requests per service/operation/status — used for error rates and request rates |
| `traces_span_metrics_duration_milliseconds_bucket` | Histogram of request latency — used for p95 computation |
| `container_cpu_utilization_ratio` | CPU usage as a ratio where **1.0 = 100% of one core** (so 5.4 = 540% across cores) |
| `container_memory_percent_ratio` | Memory usage as a percentage of the container's limit |

> **Important**: The agent never reads feature-flag settings. That's the "answer key" — reading it means disqualification. All diagnosis is purely from telemetry.

---

## File-by-File Breakdown

```
oncall-agent/
├── agent.py                 # Orchestrator: LLM loop, system prompt, finalize, multi-round handling
├── llm.py                   # LLM router: provider fallback, rate-limit pacing, quota management
├── registry.py              # Tool registry, evidence grounding, observation tracking
├── detector.py              # Incident detection (no LLM): persistence, cooldown, grouping
├── ops_tools.py             # Read-only tools: triage, containers, logs, topology, deploys
├── jaeger_tools.py          # Read-only tools: traces, error hotspots, attribute skew
├── metrics.py               # Read-only tool: focused Prometheus queries (CPU, memory, errors...)
├── fairplay.py              # Blocks flag-service telemetry (anti-cheat)
├── action_api.py            # Policy layer: allowlist, runbook, approval gate, executor, verifier, reports
├── remediation_adapters.py  # ONLY file that changes the running demo
├── .env                     # API keys (gitignored, never committed)
└── tests/test_offline.py    # Unit tests (no Docker or LLM needed)
```

---

## The 7-Step Flow

### Step 1: Detection — `detector.py`

**What**: Decides WHEN an incident exists. Pure deterministic code, no LLM.

**How**: The `scan()` function calls `ops_tools.triage()` and adds container-level signals from Docker:

| Signal | Source | Threshold | Score |
|--------|--------|-----------|-------|
| Error rate spike | Prometheus span metrics | > 2% AND > 2% above baseline | 0–100 (= error %) |
| Latency spike | Prometheus duration histogram | p95 > 50ms AND > 2x baseline | 0–100 (ratio × 10) |
| Traffic drop | Prometheus request rate | Current < 20% of baseline | 90 (fixed) |
| Container down | `docker inspect` | Status != "running" | 100 (fixed, highest) |
| Container restarted/OOM | `docker inspect` | Recent restart or OOM killed | 70 (fixed) |
| Container pressure | Docker stats via Prometheus | CPU >= 85% of cap or memory >= 92% | 60 (fixed) |

**Why persistence**: The `Detector` class requires an anomaly to appear in 2 consecutive scans before opening an incident. One noisy scrape never pages anyone — this prevents false alarms.

**Why cooldown**: After handling a fault, the same signature is ignored for 600 seconds. Otherwise the just-fixed fault would immediately reopen.

**Why scores**: Scores rank severity. Dead containers (100) and failing requests always outrank slowness (latency) and resource pressure (60). The agent investigates the most severe symptoms first.

#### What is Triage?

Triage (`ops_tools.triage()`) is a single function that scans every service at once by firing ~15 Prometheus queries in parallel. It compares the last 5 minutes of error rates, latency, and traffic against an earlier healthy baseline, and also checks Docker for down/restarting/hot containers. It's the agent's "quick health check of the entire system" that tells it where to look deeper.

**Why two baselines**: Triage uses two earlier time windows and picks the healthiest one. If there was a previous incident in one window, it doesn't poison the comparison.

---

### Step 2: Investigation — `agent.py` (`_investigate()`)

**What**: An LLM-driven tool-calling loop that gathers evidence from all telemetry sources.

**How**: The alert text (symptoms only, never causes) is sent to the LLM along with a system prompt containing:
- Service topology and roles
- Investigation strategy (batch tools, aim for 4–5 turns)
- Rules of proof (domain-specific diagnostic logic)
- Required output format (structured JSON)

The LLM calls tools, reads results, calls more tools, and eventually produces a diagnosis JSON.

#### Available Tools

**Infrastructure tools** (`ops_tools.py`):

| Tool | What It Does | Data Source |
|------|-------------|-------------|
| `triage` | Scans all services for anomalies vs baseline | Prometheus + Docker |
| `container_health` | Lists running/down/hot/restarted containers | `docker inspect` + stats |
| `get_logs` | Error log lines for one service, grouped by pattern | `docker compose logs` |
| `metric_trend` | Time-series movement: first/last/min/max + leak detection | Prometheus range query |
| `topology` | Static call graph — who calls whom | Hardcoded architecture |
| `deploy_history` | Recent container changes + past agent actions | `docker inspect` + audit log |

**Tracing tools** (`jaeger_tools.py`):

| Tool | What It Does | Data Source |
|------|-------------|-------------|
| `error_hotspots` | Aggregates deepest erroring spans (root causes) across traces | Jaeger API |
| `trace_detail` | Summarizes one trace: root errors + slowest spans | Jaeger API |
| `attribute_skew` | Finds attributes over-represented in failing spans | Jaeger API |
| `edge_latency_gap` | Client-server span time gap per edge (network detection) | Jaeger API |

**Metrics tools** (`metrics.py`):

| Tool | What It Queries |
|------|----------------|
| `get_metrics(metric=error_rate)` | Per-operation error rates, worst first |
| `get_metrics(metric=cpu)` | Container CPU utilization ratio per service |
| `get_metrics(metric=memory)` | Container memory percentage per service |
| `get_metrics(metric=latency_p95)` | Per-operation p95 latency |
| `get_metrics(metric=request_rate)` | Per-service request throughput |

#### The 5-Pillar Enforcement

If the LLM tries to finalize before checking all 5 observability categories (metrics, traces, logs, containers, deploys), the agent forces it: "Before finalizing, query the remaining pillars." This ensures thorough diagnosis.

---

### Step 2b: Fair Play — `fairplay.py`

**Why**: Competition rule — diagnosing from feature-flag state is cheating.

**What it blocks**:
- All telemetry from `flagd` and `flagd-ui` services
- Any span/metric/log containing "flagd", "feature_flag", "featureflag", "faultctl"
- Attributes starting with `feature_flag.*` or `flagd.*`
- Connections to flag-service ports (8013, 8015, 8016)

Every tool imports `fairplay` and filters results before they reach the LLM.

---

### Step 3: Evidence Grounding — `registry.py`

**Why**: LLMs can hallucinate evidence. If the LLM says "obs-3: error rate 45%" but obs-3 actually showed CPU data, that's fabricated.

**How**:

1. Every tool call gets an observation ID (`obs-1`, `obs-2`, ...) injected into the response
2. The full text of each response is tokenized and stored per-observation
3. When the LLM cites `"obs-3: payment error rate 45%"`, the grounding check verifies:
   - Does obs-3 exist?
   - Was obs-3 a non-empty result? (empty queries prove nothing)
   - Do >= 60% of words in the citation match obs-3's actual output?
   - Any long hex ID (trace/span IDs) must exist in the tool output

4. `finalize()` processes the diagnosis:
   - Grounded evidence → kept in `evidence`
   - Failed evidence → moved to `dropped_ungrounded_evidence`
   - **Zero grounded evidence** → confidence forced to "low", remedy forced to "none/escalate"

---

### Step 3b: Confidence Levels Explained

The LLM proposes a confidence level, but `finalize()` can override it:

| Confidence | When It's Assigned |
|------------|-------------------|
| **high** | LLM said "high" AND >= 2 grounded evidence items AND nothing was dropped AND all 5 pillars were queried |
| **medium** | LLM said "high" but a condition above failed (downgraded). OR LLM said "medium" and grounding passed. OR a deterministic guard reclassified the diagnosis. |
| **low** | No grounded evidence survived (forced). OR LLM said "low" (thin/conflicting evidence). OR LLM set `escalate_to_human: true` with < 2 evidence items. |

#### Deterministic Guards in `finalize()`

These override the LLM when container state contradicts its diagnosis:

1. **Stopped dependency**: Blamed service depends on something that's actually stopped → retarget to the stopped container
2. **Unreachable but serving traffic**: LLM says "dependency_down" but the service is receiving requests → reclassify to `app_error`
3. **Stopped container priority**: Any container is stopped + LLM gave low confidence → override to restart the stopped container
4. **Backing store running**: LLM says valkey-cart/astronomy-db is down but it's actually running → reclassify to the caller's `app_error`

---

### Step 4: Policy & Action Plan — `action_api.py` (`build_action_plan()`)

**What**: Deterministic code that maps diagnosis → one concrete allowlisted action (or escalates).

**Only 4 actions are allowed**:
- `restart_service` — restart a Docker container
- `toggle_feature_flag` — set a remediation flag to "off"
- `throttle_load_generator` — reduce synthetic traffic via Locust API
- `scale_service` — not supported on Docker Compose

#### How It Decides

1. **Parse the LLM's suggestion**: Scan `suggested_remedy` for keywords ("restart" → restart_service, "toggle"/"flag" → toggle_feature_flag, etc.)

2. **Runbook fallback**: If the LLM didn't suggest anything actionable:
   - Component is in `down_services` → restart_service
   - `(component, fault_class)` has a known mapping → toggle_feature_flag

3. **Runbook override**: Even if the LLM suggested something, the policy can override:
   - Container is actually down → force restart (a flag toggle can't restart a dead container)
   - Fault class is switch-fixable with a known flag → force toggle (restarting won't clear an app-level fault)

4. **Low confidence handling**:
   - No runbook mapping + low confidence → **auto-escalate** (no action proposed to human)
   - Has runbook mapping + low confidence → **still propose** with "LOW CONFIDENCE" warning; human decides

#### The Runbook: Known Fault-to-Flag Mappings

```
(payment, app_error)           → paymentFailure
(cart, app_error)              → cartFailure
(product-catalog, partial_failure) → productCatalogFailure
(ad, cpu_saturation)           → adHighCpu
(recommendation, memory_leak)  → recommendationCacheFailure
(email, memory_leak)           → emailMemoryLeak
...and more
```

---

### Step 5: Human Approval — `action_api.py` (`request_human_approval()`)

The exact plan is displayed to the human:
- Incident ID, component, fault class, confidence
- Root cause explanation
- All grounded evidence items
- Exact action type, target, parameters
- Rollback policy
- SHA-256 approval digest (anti-tampering)
- Policy warnings (LOW CONFIDENCE, runbook override, etc.)

The human types `yes`, `dry-run`, or `no`. **There is no auto-approval path.**

---

### Step 6: Execution — `action_api.py` → `remediation_adapters.py`

Before executing, every gate must pass:

| Gate | What It Checks |
|------|---------------|
| Kill switch | File `KILL_SWITCH` or env `KILL_SWITCH=1` must not exist |
| Approval | Human said "yes" |
| Single-use | Approval token not already consumed |
| Expiry | Approval is < 600 seconds old |
| Digest | Plan SHA-256 still matches (plan wasn't modified after approval) |
| Re-validation | Parameters pass allowlist checks again |
| Circuit breaker | < 3 actions executed in the last hour |

Only then does `execute_action()` call `remediation_adapters.py` — the **only module that changes the running demo**:

| Action | What It Does | How |
|--------|-------------|-----|
| `restart_service` | Restart/recreate a container | `docker compose restart` or `up -d --force-recreate` |
| `set_flag` | Edit flag file, set variant to "off" | Write JSON to `src/flagd/demo.flagd.json` |
| `throttle_load` | Reduce synthetic traffic | POST to Locust web API |

---

### Step 7: Verification — `action_api.py` (`verify_recovery()`)

**Why wait 75 seconds**: Old error metrics need to leave the 1-minute Prometheus rate window. Checking immediately would still show stale errors.

Then it runs 2 consecutive clean scans, 20 seconds apart, checking:
- No anomalies for the target service or its callers
- Target not in `not_running`
- Target not CPU-capped
- Dependencies are not stopped
- Traffic is actually flowing (silence is not recovery)
- Telemetry is reachable (a blind scan never counts as a pass)

**Why 2 consecutive samples**: One clean scan could be noise. Two spaced 20s apart gives real confidence.

**If verification fails**: The action is rolled back (if reversible — e.g., flag restored to previous variant) and the incident is escalated to a human.

---

## Multi-Round Incident Handling

After fixing round 1, the agent runs two fresh detector scans 30 seconds apart. Anomalies that appear in both are real remaining faults.

If remaining faults exist, a new round starts with context: "Those faults are fixed. Find what is STILL wrong." This prevents re-diagnosing the same thing.

Up to 3 rounds run. This handles cascading faults — e.g., valkey-cart was down (round 1: restart), and once restarted, the cart service's own app_error became visible (round 2: toggle flag).

---

## LLM Layer — `llm.py`

**Why a Router**: Free-tier Groq has daily quotas and per-minute token limits. The Router handles:
- **Provider fallback**: Tries providers in order; when one's daily quota is hit, switches to the next
- **Rate-limit pacing**: Reads `x-ratelimit-remaining-tokens` headers and waits for the minute window to refill instead of getting rejected
- **Hot-swap keys**: If all providers are exhausted, pauses and re-reads `.env` every 15 seconds — someone can drop a new key in and the agent resumes automatically
- **No silent downgrade**: Never switches to a weaker model unless explicitly configured

---

## How Each Fault Gets Detected and Fixed

| Fault | What Happens in the Demo | What Shows in Telemetry | Agent's Diagnosis | Fix |
|-------|-------------------------|------------------------|-------------------|-----|
| **paymentFailure** | Payment service returns errors | `error_hotspots(checkout)` → root error in payment; error_rate spikes | payment `app_error` | Toggle `paymentFailure` off |
| **cartFailure** | Cart returns "can't access cart storage" | `get_logs(cart)` → storage errors; valkey-cart IS running | cart `app_error` (not dependency_down) | Toggle `cartFailure` off |
| **valkey-cart stopped** | Cache container exits | `container_health()` → valkey-cart in not_running | `container_crash_or_restart` | Restart service |
| **productCatalogFailure** | Product catalog errors on some requests | `error_hotspots` → product-catalog errors | `partial_failure` | Toggle `productCatalogFailure` off |
| **recommendationCacheFailure** | Recommendation memory grows unbounded | `metric_trend(memory)` → monotonic rise | `memory_leak` | Toggle `recommendationCacheFailure` off |
| **adHighCpu** | Ad service burns CPU | `get_metrics(cpu)` → value > 0.5 (>50%); memory > 70%; no errors | `cpu_saturation` | Toggle `adHighCpu` off |

---

## Reporting

Two files per incident:
- **JSON** (`reports/inc-TIMESTAMP.json`): Machine-readable full report — all observations, all rounds, LLM usage stats, verification results
- **Markdown** (`reports/inc-TIMESTAMP.md`): Human-readable post-mortem with per-round sections: diagnosis, evidence, investigation timeline, remediation outcome, verification, and prevention recommendations

Every action (approval requests, decisions, executions, rollbacks) is also appended to `logs/audit.jsonl` for a complete audit trail.
