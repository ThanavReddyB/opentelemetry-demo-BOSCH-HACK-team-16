# Incident Zero: Build an AI On-Call Engineer

Bosch one-day (two-day schedule) AI hackathon at PES University. This file is a full transcription of the organiser slides (kickoff brief, flow, milestones, incidents, starter kit, stretch goals, deliverables, rules). It is the source of truth for what this project must do.

> Items marked **[unclear]** were hard to read in the slide photos. Confirm with organisers.

---

## 1. Theme and problem statement

**Theme:** Agentic AI for IT Operations: from alert to safe, approved fix.

**Problem statement:** Build an **AI On-Call Engineer**: an agent that responds to a production incident in a cloud-native application, investigates it using real tools, identifies the root cause with evidence, and resolves it safely with human approval.

### What this means
When a production system breaks, an on-call engineer is paged, often at 2 a.m. They read logs, check dashboards, look at what was deployed recently, guess the cause, and apply a fix, all under pressure. Much of that first hour is searching and correlating, which is exactly what an AI agent can speed up.

Teams must build an AI agent that does this first hour of work. It:
1. receives an alert,
2. decides which tools to call and in what order,
3. reasons over logs, metrics, traces and deployment history,
4. names the root cause with the evidence behind it,
5. proposes a fix from an approved runbook,
6. asks a human for approval, applies it,
7. checks that the system has actually recovered.

> **A good agent is not the one that always acts. It is the one that acts when it has evidence, and says "I am not sure, here is what I found" when it does not.**

### Application for this hackathon
Every team works on the same open-source, cloud-native application: the **OpenTelemetry Demo** (the "Astronomy Shop"), a microservices e-commerce store written in a dozen languages, running on your own laptop. It already sends traces, metrics and logs, and has built-in switches (feature flags) that cause realistic failures.

GitHub: https://github.com/open-telemetry/opentelemetry-demo

---

## 2. What a team's solution should do (the 7-step loop)

| # | Step | Requirement |
|---|------|-------------|
| 1 | **Detect the incident** | Receive an alert (an error-rate or latency threshold on the demo's metrics) and start an investigation automatically. |
| 2 | **Investigate with tools** | Give the agent tools to query **traces, metrics, logs and container health**. The agent should decide which tool to call next based on what it has found so far, rather than pasting all the data into one prompt. |
| 3 | **Diagnose with evidence** | Name the failing component and the cause, with a **confidence level** and the **exact traces, log lines or metric values** that support it. Evidence must exist in the data; **invented evidence is penalised**. |
| 4 | **Propose a safe fix** | Pick a remedy **only from the allowlisted runbook actions in the Action API** (restart a service, toggle a feature flag, throttle the load generator, scale a service on Kubernetes), with a short reason. |
| 5 | **Ask for human approval** | Show the diagnosis and plan to a human and wait. **Nothing changes without an explicit yes.** Provide a **dry-run mode** and a **kill switch**. |
| 6 | **Act and verify** | Execute the approved action, then check health metrics to confirm the system recovered. If it did not, **roll back and escalate**. |
| 7 | **Report** | Produce a short incident report: **timeline, root cause, evidence, action taken, and what would prevent a repeat**. |

> **When the agent is not confident, escalating to a human with its findings is a correct outcome and scores better than a confident wrong fix.**

---

## 3. Incidents the agent may face

Ten practice incidents are published at kickoff. The **final evaluation uses unseen incidents**, including infrastructure faults and combinations, so build an agent that **reasons from telemetry**, not one that reads the answers from the feature-flag settings (not allowed, see Rules).

### Application faults (the demo's built-in failure flags)
- The payment service fails when charging
- The cart service fails intermittently
- The product catalog fails for one specific product
- A memory leak in the recommendation service from a runaway cache
- High CPU or heavy garbage collection in the ad service
- A traffic flood on the homepage

### Infrastructure faults (injected by organisers)
- A service container is stopped or keeps restarting
- The cache or a database becomes unavailable
- Network latency or packet loss between two services
- A service is starved of CPU or memory

---

## 4. Starter kit and environment

Every team runs the same open-source application so results are comparable.

| Provided | What it is | Source |
|----------|-----------|--------|
| **OpenTelemetry Demo** | Microservices store (frontend, cart, checkout, payment, product catalog, recommendation, ad, shipping and more) with a Locust load generator; run with Docker Compose | Open source (GitHub) |
| **Telemetry** | Traces, metrics and logs from every service through the OpenTelemetry Collector, with the bundled trace and metrics viewers | Comes with the demo |
| **Failure flags** | Built-in switches for realistic failures, managed by flagd | Comes with the demo |
| **faultctl** | Command-line tool to inject a practice incident (a flag or an infrastructure fault) and reset everything | Organisers |
| **Action API** | The **only allowed way** for your agent to change the system: restart a service, toggle a feature flag, throttle the load generator, scale a service (Kubernetes only). **Every call is logged.** | Organisers |
| **Offline incident bundles** | Recorded telemetry for every practice incident, for laptops that cannot run the full demo | Organisers |
| **LLM access** | An API key with a spend limit; open-source or local models also allowed | Organisers |
| **Template repository** | Agent skeleton, required output format (JSON schema), README template, team form | Organisers |

---

## 5. Schedule and milestones

### Day 1: Build the foundation (11:30 to 18:45)

| Time | Milestone | Expected outcome |
|------|-----------|------------------|
| 11:30 to 12:00 | Kickoff | Problem reveal, starter kit walkthrough, rules |
| 12:00 to 13:00 | Setup | OpenTelemetry demo running with load; faultctl injects and resets an incident; LLM key works; repo forked; **all 3 members have committed** |
| 13:00 | **Checkpoint 0: Setup** | Mentor confirms the setup; blockers fixed on the spot |
| 13:00 to 15:30 | **The agent can see** | Tools for logs, metrics, traces and deploy history; agent summarises the symptoms of one practice incident; **1-page architecture sketch** |
| 15:30 | **Checkpoint 1: Eyes** | Live run on one practice incident, plus the sketch |
| 15:30 to 18:30 | **The agent can diagnose** | Root cause with evidence and confidence; output in the **JSON schema** |
| 18:30 | **Checkpoint 2: Brain** | Correct diagnosis on **at least 3 practice incidents chosen by the mentor** |
| 18:45 | Day 1 wrap up | Day 1 code state saved; mentors review Day 1 progress |

### Day 2: Enhance, analyse and showcase (09:00 to 18:45)

| Time | Milestone | Expected outcome |
|------|-----------|------------------|
| 09:00 to 09:30 | Day 2 alignment | Briefing for Day 2 goals, review feedback from Day 1 checkpoints |
| 09:30 to 12:00 | **The agent can act safely** | Allowlisted action proposed; approval gate; execute; recovery verified; dry run and kill switch; incident report generated |
| 12:00 | **Checkpoint 3: Hands** | One full run, alert to verified recovery, with the action log |
| 12:00 to 13:30 | Harden, document and prep submission | **No new features**; fix bugs; clean run from scratch; finish README, evaluation note and team form |
| 13:30 to 14:00 | Final verification and submission | Final code push; verify schema compliance and deliverables |
| **14:00** | **Code freeze and hard cutoff** | Final commit recorded; **later commits are ignored** |
| 14:00 to 15:30 | **Checkpoint 4: Hidden test and mentor review** | Organisers run unseen incidents on your setup; automated scoring and reviewer evaluations |
| 15:30 to 16:30 | Evaluation and elimination round | Mentors and judges review test scores and select qualifying teams for final demos |
| 16:30 to 18:45 | Finalist demos and individual interviews | 5-minute live demo plus 3 minutes of questions; short one-to-one technical conversation with shortlisted teams |

### Minimums
- **Minimum by Checkpoint (Day 1):** An agent that uses tools and correctly diagnoses practice incidents with **real evidence**.
- **Minimum by code freeze (Day 2, 14:00):** A full loop on **at least one incident** (diagnose, approve, act, verify, report), a **kill switch that works**, and **all deliverables in the repository**.

> Timing discrepancy: the deliverables slide says submit "by the 16:30 code freeze" **[unclear]**, while the milestones slide says code freeze is **14:00**. Treat **14:00** as the deadline until organisers say otherwise.

---

## 6. Deliverables (all in the repository by code freeze)

There is **no demo video**; you demo live.

| Deliverable | Details |
|-------------|---------|
| **Source code** | Team repository forked from the template, with a README covering setup, how to run, how the approval gate and kill switch work, and **known limitations** |
| **Architecture overview** | One page: components, the tools the agent uses, how it decides, and the safety controls (a photo of a whiteboard sketch is fine) |
| **Incident reports** | Reports produced by **your agent** for the practice incidents it handled, in the provided **JSON schema** plus a readable form |
| **Evaluation note** | Which practice incidents your agent got right and wrong in your own testing, and why |
| **Team form** | Team name, members, who built which part, tools and AI models used (**including AI coding assistants**), third-party libraries |

---

## 7. Rules

1. Teams of 3. **All code is written on the day, from 09:15 [unclear]; commits before then are not allowed.**
2. Open-source libraries and agent frameworks are allowed. **AI coding assistants are allowed if declared in the team form**; every member must be able to explain and change the code they submit.
3. **All three members must commit code.**
4. The agent changes the demo **only through the Action API, and only after human approval.**
5. Mentors help you get unblocked; they **do not write code for you**. No outside help.
6. **Reading feature-flag settings to diagnose, or tampering with the demo, faultctl, the hidden incidents or the scoring harness, means disqualification.**
7. **Be honest about what does not work.** Stating a limitation costs nothing; hiding a failure in the demo loses points.

---

## 8. Optional stretch goals

1. **Incident memory:** reuse earlier incident reports to diagnose a repeat incident faster.
2. **Reviewer agent:** a second agent tries to disprove the diagnosis before the human sees it.
3. **Calibrated confidence:** show that the agent's stated confidence matches how often it is right on the practice set.
4. **Chat-style approval:** the on-call human approves or rejects from a simple chat UI or dashboard.
5. **Prevention:** after fixing, the agent suggests a code, config or alerting change that would stop the incident recurring.

---

## 9. What gets scored (inferred from the slides)

- Correct diagnosis backed by **real evidence that exists in the telemetry** (invented evidence is penalised).
- Tool use driven by the agent's own reasoning, not one giant prompt.
- Confidence that is honest; **escalating to a human beats a confident wrong fix**.
- Safe action: allowlist only, approval gate, dry run, kill switch, rollback, every call logged.
- Verified recovery via health metrics after acting.
- Schema-compliant incident reports.
- Performance on **unseen** incidents (including infrastructure faults and combinations) in the hidden test.
- Honesty about limitations; all deliverables present; all three members committed.

## 10. Hard "do nots"

- Do **not** read flagd / feature-flag settings to diagnose. Diagnose from telemetry.
- Do **not** modify the demo, faultctl, hidden incidents or the scoring harness.
- Do **not** change the system by any path other than the Action API, or without explicit human approval.
- Do **not** add new features after 12:00 on Day 2; do **not** commit before the allowed start time.
- Do **not** invent evidence or hide failures.
