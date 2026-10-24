# On-call agent test bench

Breaks the demo in a known way, lets the agent detect and handle it, then grades the agent's
report against the known answer. This folder lives outside `oncall-agent/` on purpose. The agent
package must never mention or import the injector, and this folder is the answer key.

Run every command from the repo root.

## Commands

```bash
python testbench/run.py list                              # scenarios, expectations, suites
python testbench/run.py run cart-fail                     # one scenario, you approve at the prompt
python testbench/run.py run smoke --operator yes          # a suite, the bench types the approvals
python testbench/run.py run payment-fail+cache-down       # any '+'-joined combo of single ids
python testbench/run.py run core combos --operator yes    # several targets in one run
python testbench/run.py inject net-delay                  # inject only, for manual exploration
python testbench/run.py status                            # active faults (faultctl + network)
python testbench/run.py reset                             # undo everything
python testbench/run.py grade oncall-agent/reports/inc-123.json cart-fail
python -m unittest discover -s testbench/tests -v         # offline tests, no Docker needed
```

Suites: `smoke` (3), `core` (9), `combos` (3), `all` (every single scenario, then every combo).

## What one scenario does

1. **Precheck.** Polls `agent.py --detect-once --window 2` every 20s until it prints `[]`
   (`--precheck-timeout`, default 360s). If it is still not clean, the scenario is marked
   `dirty start` and runs anyway. `--no-precheck` skips this step.
2. **Inject.** Calls `faultctl.py` for flags, stops and CPU starvation. For network delay it runs a
   `tc netem` sidecar (`TESTBENCH_NET_IMAGE`, default `nicolaka/netshoot`). Each command is logged
   with a timestamp.
3. **Settle.** Waits `--settle` seconds (default 60).
4. **Agent.** Runs `agent.py --detect-and-handle --detect-timeout N --report-json <path>`. Its output
   streams to the console and is also written to `results/<run_ts>/NN-<scenario>.log`.
5. **Grade** the report, then **reset**: `faultctl.py reset --restart-flagd` plus removal of network
   faults. Pass `--keep` to skip the reset. Ctrl+C still resets.

## Operator modes

- `--operator interactive` (default): you type `yes`, `no` or `dry-run` at each approval prompt.
- `--operator yes`: the bench prints `TEST OPERATOR MODE: approvals are typed by the test bench`,
  sets `ONCALL_APPROVER=testbench` and writes `yes` six times to the agent's stdin. Use this for
  unattended suites only. It is a test harness, not an auto-approve mode for the agent.

## Verdicts

| Verdict | Meaning |
|---|---|
| `PASS` | Every fault diagnosed (right component), and fixed and verified. For an `escalate` scenario, escalating or fixing are both accepted. |
| `ESCALATED_OK` | No correct diagnosis, but the agent escalated with low confidence and never named a wrong component confidently. Acceptable. |
| `PARTIAL` | At least one fault diagnosed, but not all of them were diagnosed or fixed. |
| `FAIL` | Wrong or no diagnosis without a safe escalation. |
| `WRONG_FIX` | A fix was proposed with medium/high confidence for a component outside the scenario's accepted list. This overrides every other verdict. |
| `NOT_DETECTED` | The report has no diagnosis (no incident opened). |
| `AGENT_CRASHED` | No readable report JSON was written. |
| `INJECT_FAILED`, `INTERRUPTED` | The bench itself did not finish the scenario. |

A wrong fault class does not fail a scenario. It is recorded in `class_ok` and in the notes.
A component that is only named in `secondary_findings` counts as `mentioned`, which is weaker than
diagnosed.

Results land in `testbench/results/<run_ts>/`: `NN-<scenario>.log`, `NN-<scenario>.report.json`,
`scoreboard.md` and `scoreboard.json` (rewritten after each scenario). Network faults are tracked in
`testbench/results/.net_state.json`, so `reset` still removes them after a crash.
