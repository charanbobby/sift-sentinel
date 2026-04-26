# sift-sentinel

An autonomous AI agent for the SANS "Find Evil" 2026 hackathon. It reads a Windows hard-drive image and an optional memory snapshot, and tells you what an attacker did to maintain access to the machine, including what they're currently doing if memory is included. The agent runs in a forensics container, drives a small set of typed forensic tools through a model-context-protocol (MCP) server, and gates every finding through a deterministic safety-checking layer before anything is committed.

The headline accuracy claim: across the three test cases for which we have an authoritative answer key, the agent finds every malicious item correctly and never invents a finding. See the [Accuracy Report](docs/submission/accuracy-report.md) for the full evidence.

## What it does (plain English)

Picture the L1 analyst on a SOC desk who pulls a fresh Windows disk image at 2am. They have to figure out, fast, whether the machine is compromised and how the attacker stays on it after a reboot. This project automates that triage. The agent picks which forensic tools to run, runs them, reads the output, writes its findings, and then a separate rule engine double-checks the findings against the actual tool output before letting them out the door. A human approves the plan once at the start, then approves the final findings; everything in between runs by itself. Memory analysis layers on top to catch live attackers (process injection, command-and-control beacons, fingerprints of attackers using AI tooling on the host).

## What's distinctive about this entry

- **The agent literally cannot run arbitrary shell commands.** It can only call a small set of typed forensic functions exposed by a separate server (the MCP server). Each call is signed by a per-run permission token bound to the human-approved plan; calls outside the plan, or against paths outside the case folder, are rejected by the server, not by the agent.
- **Two-channel evidence handling.** Raw forensic bytes are preserved and hashed. The analysis AI never sees the raw bytes; it only sees structured fields the server extracted. If the server's prompt-injection scanner flags an evidence record (for example, an attacker-controlled filename containing instructions disguised as text), the parsed content is walled off from the AI before it reaches the analysis stage.
- **A deterministic critic gates every finding.** More than a dozen rules check things like "every claim cites real evidence in the tool output," "absence claims are only allowed if every tool ran cleanly," "memory-class findings cite three independent corroborating signals." Findings that fail go back to the AI for a corrected pass with a budget cap, or escalate to a human.
- **Real-time cost transparency.** Every AI call prints its actual cost (read directly from the AI provider, not from a hand-maintained price table) before and after the call, so a runaway prompt is visible in seconds rather than at the end of the month.

## Architectural pattern (per contest rules)

Two of the four supported patterns from the contest brief, layered:

- **Custom MCP Server (#2):** typed forensic functions, server-side path allow-listing, capability-token verification on every call, prompt-injection scanning before evidence reaches the AI.
- **Multi-Agent / Workflow (#3):** the pipeline is a LangGraph state machine of named stages (extract candidates, plan tool calls, human approves plan, execute, interpret, critic check, human review or commit). Failures route back to re-plan with a budget cap. Every stage logs to the same trace.

Where security boundaries are enforced and where they rely on prompt discipline rather than architectural enforcement: see the [architecture diagram](docs/planning/architecture.html) for the per-boundary breakdown.

## The 8 required submission components

Per the contest [rules](docs/reference/hackathon/rules.md), all eight components are required for eligibility.

| # | Component | Where it lives |
|---|---|---|
| 1 | Code repository | This repository (MIT-licensed; see [LICENSE](LICENSE)) |
| 2 | Demo video (5 min) | TODO: recorded closer to the deadline |
| 3 | Architecture diagram | [docs/planning/architecture.html](docs/planning/architecture.html) (rendered diagram with boundary annotations); source-of-truth markdown at [docs/planning/architecture.md](docs/planning/architecture.md) |
| 4 | Written project description | TODO: drafted on Devpost closer to the deadline |
| 5 | Dataset documentation | [docs/reference/hackathon/dataset_manifest.md](docs/reference/hackathon/dataset_manifest.md) |
| 6 | Accuracy report | [docs/submission/accuracy-report.md](docs/submission/accuracy-report.md) (with [sampled-review supporting evidence](docs/submission/sampled-review-aggregate.md)) |
| 7 | Try-it-out instructions | TODO: delivery shape is being decided (likely a hosted MCP endpoint a judge connects to from their own Claude Code, passing only the case file); existing local setup at [docs/runbooks/slice-1-docker-runbook.md](docs/runbooks/slice-1-docker-runbook.md) |
| 8 | Agent execution logs | Per-case under [experiments/slice-2-notebook/out/runs/](experiments/slice-2-notebook/out/runs/); one numbered folder per run, each containing the tool plan, raw evidence, structured findings, and the critic-disagreement log |

## Where to read first (if you only have 10 minutes)

1. [docs/submission/accuracy-report.md](docs/submission/accuracy-report.md): the headline numbers and per-case writeups.
2. [docs/planning/architecture.html](docs/planning/architecture.html): the architecture diagram with security boundaries.
3. One concrete run, end to end: [experiments/slice-2-notebook/out/runs/srl-2018-wkstn-05/srl-2018-wkstn-05-005/](experiments/slice-2-notebook/out/runs/srl-2018-wkstn-05/srl-2018-wkstn-05-005/). Open the tool plan, the collected evidence, the findings, and the critic-disagreement log (numbered 02, 04, 05, 06 in that folder) and read in that order.

## Repo layout

| Path | What's in it |
|---|---|
| [docker/](docker/) | Container definitions (the SIFT forensics container plus the agent orchestrator container) |
| [experiments/slice-2-notebook/](experiments/slice-2-notebook/) | The pipeline itself: planner, executor, interpreter, critic, MCP server, all tests |
| [docs/planning/](docs/planning/) | Live project plan and architecture documents |
| [docs/runbooks/](docs/runbooks/) | Step-by-step operating procedures, one per implementation slice |
| [docs/onboarding/](docs/onboarding/) | New-teammate orientation (skip if you're a judge; useful if you're forking) |
| [docs/submission/](docs/submission/) | Submission-component documents (accuracy report, sampled-review aggregate) |
| [docs/reference/hackathon/](docs/reference/hackathon/) | Verbatim contest materials (rules, dataset manifest, overview) |

## License

MIT. See [LICENSE](LICENSE).
