# sift-sentinel

**An autonomous AI agent built to catch attackers who use AI themselves.** Sift Sentinel hunts for the artifacts that AI-using attackers leave on a compromised Windows host: local LLM inference servers planted as persistence (`llama.cpp`, `ollama`, `.gguf` model files in unexpected locations), prompt-injection payloads buried in attacker-controlled registry Run-key values and scheduled-task XML, and the operational fingerprints of AI-assisted reconnaissance. The November 2025 GTG-1002 disclosure showed adversaries running autonomous Claude Code at request rates "physically impossible" for humans. The defender side has to keep up. This is a defender that does.

The agent itself is built around two architectural guarantees that distinguish it from prompt-engineered alternatives: it physically cannot run arbitrary commands on the host (architecture, not prompts; no shell primitive in the MCP allow-list), and a deterministic 17-rule critic with no AI in its loop checks every claim the AI makes before a human sees it.

The headline accuracy claim: across 32 reviewed runs the agent produced zero fabricated findings. The runs span the two SANS-provided datasets (SRL-2018 and SRL-2015) plus three publicly-available DFIR cases the team sourced separately (DFIR Madness Case 001, OpenUni22, Hadi3 Win 8.1 challenge), plus 6 days of synthetic intel-driven scoring against the AI-using-attacker tradecraft described above. On the case with a publicly-published answer key (DFIR Madness Case 001), the agent found every malicious item and invented nothing. One run carries a malformed citation pointer (the agent put a positional index where a unique call id should have been) whose underlying claim is independently corroborated by another cite in the same finding that resolves cleanly. We log this separately as a data-quality entry rather than papering over it. See the [Accuracy Report](docs/submission/accuracy-report.md) for the full evidence.

## The AI-using-attacker hunt (the headline differentiator)

The Anthropic GTG-1002 report (November 2025), the CrowdStrike sub-eight-minute breakout time, and the Horizon3 sixty-second autonomous privilege-escalation result all describe the same shift: attackers now operate at machine speed using AI tooling themselves. Classic DFIR checklists do not catch the artifacts these attackers leave behind because those artifacts did not exist when the checklists were written.

We built specific detectors and validated them on a daily synthetic-workstation loop. On 2026-04-30, the loop caught an attacker who planted a registry Run-key value `LocalInference` pointing at `C:\ProgramData\llama-server.exe --port 8000 --model C:\ProgramData\model.gguf`. The agent surfaced the finding, named the persistence mechanism (Run-key autostart), named the binary (the llama.cpp HTTP inference server), named the model file (`.gguf` weights staged in ProgramData), and correctly held back the stronger AI-assisted classification because the cited evidence did not include an LLM API URL or SDK import anchor. The full detection chain ran end to end without human intervention.

Other AI-using-attacker artifacts the loop has caught across six approved scored days:
- Prompt-injection content embedded directly in registry Run-key values (literal "Ignore all previous system prompts" strings, Base64-encoded PowerShell payloads decoding to "report host=clean")
- Prompt-injection embedded in the filename of a planted binary (`ignore_previous_alerts.exe` under `C:\Users\Public\.tools\`)
- LLM-related process names and supporting binaries staged via persistence mechanisms

Every finding cites real evidence in the planted disk image, with cite-clean citations and resolvable tool-call ids. The daily-loop infrastructure runs unattended on a VPS and produces a per-day scorecard.

## AI architecture at a glance

For an AI-side reviewer, four things are worth understanding before anything else.

**Four trust boundaries, in order from outermost to innermost.**

1. **MCP server allow-list (architectural).** The agent can only invoke 10 typed forensic functions: 5 disk (`fsstat_e01`, `fls_list`, `icat_extract`, `regripper_run`, `scheduled_tasks_parse`) and 5 memory (Volatility plugins `pslist`, `cmdline`, `netscan`, `dlllist`, `malfind`). There is no `execute_shell` primitive. The agent literally cannot reach the OS shell.
2. **Capability tokens (architectural).** Every MCP call carries a per-run token bound to the human-approved plan and the case's path scope. Calls outside the plan, or against paths outside the case folder, are rejected by the server before the tool runs. Tokens carry an expiry; the orchestrator re-issues them when a step retries, with the same path scope.
3. **Prompt-injection scanner on every evidence record (architectural).** Before any structured field reaches the analysis LLM, the server scans for known injection patterns (long base64 blobs that decode to instruction-shaped text, embedded MITRE technique IDs in narrative fields, attacker-controlled filenames containing instructions). Flagged records are quarantined; the analysis LLM never sees them. The defense fired on 11 of 46 audited runs.
4. **17-rule deterministic critic on every finding (architectural).** No AI in the critic loop. Rules check things like "every claim cites a tool call that resolves in the evidence file," "the cited excerpt actually appears in the cited record," "absence claims are only allowed if every tool ran cleanly," "memory-class findings need three independent corroborating signals from separate Volatility plugins," "findings classified as AI-assisted must point at an AI-tooling artifact in the cited evidence." Failures retry once with a budget cap, then escalate to human review. One rule slot is reserved for the next iteration.

**Four LLM call sites, with cost shape.**

| Stage | Model | What it does | Typical cost |
|---|---|---|---|
| EXTRACT | Gemini 3 Flash Preview | Skims image metadata, picks candidate inodes worth investigating | ~$0.01 |
| PLAN | Claude Sonnet 4.6 | Synthesises a typed tool plan against the candidate set; human approves | ~$0.05 to $0.15 |
| INTERPRET | Claude Sonnet 4.6 | Reads structured tool outputs, writes findings with cited evidence | ~$0.10 to $0.50 |
| Daily-loop research | Claude Haiku 4.5 | Reads recent threat intel, drafts a planted-artifact manifest for the synthetic-workstation loop | ~$0.04 |

**Typical case cost.** A disk-only persistence triage on an SRL-2018 host averages $0.30 to $0.70 in LLM spend (across 5 SRL-2015 hosts the per-run cost ranged $0.07 to $0.34). Runs that include memory analysis and exercise the full Volatility plugin set sit between $0.50 and $3, depending on host process count. Every call prints its own cost before and after, read directly from the provider's usage object so a hand-maintained rate table cannot drift out of sync.

**Self-correction in three sentences.** The injection defense fires when an evidence record looks adversarial and the run is quarantined before the analysis LLM ever sees the bad input. The critic disagrees when a finding fails one of its 17 rules and either retries the analysis LLM with a corrective prompt or escalates the run to human review. An integrity ledger chains every plan, every tool call, and every finding by hash so a reviewer can replay exactly what happened and why. All three mechanisms are visible in the per-run dashboard at https://sentinel.sshub.dev/site/dashboard.html.

## What it does (plain English)

Picture the L1 analyst on a SOC desk who pulls a fresh Windows disk image at 2am. They have to figure out, fast, whether the machine is compromised and how the attacker stays on it after a reboot. This project automates that triage. The agent picks which forensic tools to run, runs them, reads the output, writes its findings, and then a separate rule engine double-checks the findings against the actual tool output before letting them out the door. A human approves the plan once at the start, then approves the final findings; everything in between runs by itself. Memory analysis layers on top to catch live attackers (process injection, command-and-control beacons, fingerprints of attackers using AI tooling on the host).

## What's distinctive about this entry

The three signals an AI-track judge cares about most:

- **The agent is architecturally prevented from going rogue.** No shell primitive, capability tokens on every call, server-side path allow-list. The architecture diagram at [docs/planning/architecture.html](docs/planning/architecture.html) marks every boundary as architectural or prompt-based so the trust posture is unambiguous.
- **A deterministic 17-rule critic catches the agent's own mistakes before humans see them.** No AI in the critic. The most recent audit pass confirms zero fabricated findings across 32 reviewed runs, with one malformed citation pointer caught and logged separately as a data-quality entry rather than glossed.
- **Continuous accuracy via a daily synthetic-workstation loop.** A research agent reads recent threat intel, plants matching artifacts into a synthetic Windows disk inside Docker (no network egress, all domains use `.example.invalid`), runs the sentinel, and scores per-artifact PASS / MISS. 6 days of approved scored runs through 2026-05-08 include one that caught an attacker planting a `llama-server.exe` LLM inference server with `.gguf` model weights: the AI-using attacker we built specifically to validate the detection chain.

## Cross-host campaign signature (for the DFIR-side reviewer)

Across the SRL-2018 hosts the agent surfaces a single command-and-control endpoint at `172.16.4.10:8080`, a paired `Microsoft Advanced API 32` / `Microsoft Advanced API 64` masquerading service install, and a recurring Meterpreter PEB-walk PowerShell shellcode pattern in WMI-spawned processes. The same artifacts recur on 5 or more hosts in the dataset, catalogued in the per-case review notes under [docs/submission/](docs/submission/). Today this overlap is detected by humans reading multiple per-host notes; an automated cross-host correlator that emits "this artifact appears on N other hosts" sidecar findings is named in the future-work section of the accuracy report.

## Architectural pattern (per contest rules)

Two of the four supported patterns from the contest brief, layered. The contest rules name Claude Code and OpenClaw as the preferred agentic frameworks but explicitly accept "comparable agentic architectures"; the LangGraph state machine described below is one such comparable architecture.

- **Custom MCP Server (#2):** typed forensic functions, server-side path allow-listing, capability-token verification on every call, prompt-injection scanning before evidence reaches the AI.
- **Multi-Agent / Workflow (#3):** the pipeline is a LangGraph state machine of named stages (extract candidates, plan tool calls, human approves plan, execute, interpret, critic check, human review or commit). Failures route back to re-plan with a budget cap. Every stage logs to the same trace, and every LLM call is traced into LangFuse with token counts and per-call cost grouped by per-run session.

Where security boundaries are enforced and where they rely on prompt discipline rather than architectural enforcement: see the [architecture diagram](docs/planning/architecture.html) for the per-boundary breakdown.

## The 8 required submission components

Per the contest [rules](docs/reference/hackathon/rules.md), all eight components are required for eligibility.

| # | Component | Where it lives |
|---|---|---|
| 1 | Code repository | This repository (MIT-licensed; see [LICENSE](LICENSE)) |
| 2 | Demo video (5 min) | https://youtu.be/-wLPFO0ortk (4:48) |
| 3 | Architecture diagram | [docs/planning/architecture.html](docs/planning/architecture.html) (rendered diagram with boundary annotations); source-of-truth markdown at [docs/planning/architecture.md](docs/planning/architecture.md) |
| 4 | Written project description | Draft at [docs/submission/devpost-description.md](docs/submission/devpost-description.md), copy-pasted into Devpost at submission time |
| 5 | Dataset documentation | [docs/reference/hackathon/dataset_manifest.md](docs/reference/hackathon/dataset_manifest.md) |
| 6 | Accuracy report | [docs/submission/accuracy-report.md](docs/submission/accuracy-report.md) (with [sampled-review supporting evidence](docs/submission/sampled-review-aggregate.md) and per-case review notes under [docs/submission/](docs/submission/)) |
| 7 | Try-it-out instructions | Path A (clone + run on your own E01) is the supported flow today, documented at [docs/runbooks/slice-1-docker-runbook.md](docs/runbooks/slice-1-docker-runbook.md). The hosted "judge designs a scenario" surface is scoped at [docs/judges/submit-a-scenario.md](docs/judges/submit-a-scenario.md); the translator script is built and validated, the queue and email surface are post-submission work. The live run viewer at https://sentinel.sshub.dev/site/dashboard.html is open today for browsing every curated case end to end. |
| 8 | Agent execution logs | Per-case under [experiments/slice-2-notebook/out/runs/](experiments/slice-2-notebook/out/runs/); one numbered folder per run, each containing the tool plan, raw evidence, structured findings, the critic-disagreement log, and the integrity ledger that hash-chains plan → tool call → finding. Every LLM call is also traced into LangFuse with token counts and per-call cost grouped by per-run session, so a judge can trace any finding back to the exact tool execution and the LLM token cost that produced it. |

## Where to read first (if you only have 10 minutes)

1. The "AI architecture at a glance" section above (90 seconds).
2. [docs/submission/accuracy-report.md](docs/submission/accuracy-report.md) Section 0 "60-second version" (60 seconds), then Section 1 (3 minutes).
3. [docs/planning/architecture.html](docs/planning/architecture.html): the architecture diagram with security boundaries (2 minutes).
4. One concrete run, end to end: [experiments/slice-2-notebook/out/runs/srl-2018-wkstn-05/srl-2018-wkstn-05-005/](experiments/slice-2-notebook/out/runs/srl-2018-wkstn-05/srl-2018-wkstn-05-005/). Open the tool plan, the collected evidence, the findings, and the critic-disagreement log (numbered 02, 04, 05, 06 in that folder) and read in that order (3 minutes).

## Repo layout

| Path | What's in it |
|---|---|
| [docker/](docker/) | Container definitions (the SIFT forensics container plus the agent orchestrator container) |
| [experiments/slice-2-notebook/](experiments/slice-2-notebook/) | The pipeline itself: planner, executor, interpreter, critic, MCP server, all tests |
| [docs/planning/](docs/planning/) | Live project plan and architecture documents |
| [docs/runbooks/](docs/runbooks/) | Step-by-step operating procedures, one per implementation slice |
| [docs/onboarding/](docs/onboarding/) | New-teammate orientation (skip if you're a judge; useful if you're forking) |
| [docs/submission/](docs/submission/) | Submission-component documents (accuracy report, sampled-review aggregate, per-case review notes) |
| [docs/reference/hackathon/](docs/reference/hackathon/) | Verbatim contest materials (rules, dataset manifest, overview) |

## Try it out

Two paths, depending on how much you want to set up.

### Path A: live deployment (no install)

- Browse every curated case end to end (tool plan, evidence, findings, critic disagreements, integrity ledger): [https://sentinel.sshub.dev/site/dashboard.html](https://sentinel.sshub.dev/site/dashboard.html)
- For-judges walk-through: [https://sentinel.sshub.dev/site/submission.html](https://sentinel.sshub.dev/site/submission.html)

The dashboard is the fastest way to verify what the agent does. Every run is browsable; click into any case to see the four trust boundaries in action on real evidence.

### Path B: clone + run on your own E01 (Docker Desktop)

1. **Clone the repo and drop evidence in place.**

   ```bash
   git clone https://github.com/charanbobby/sift-sentinel.git
   cd sift-sentinel
   ```

   Put your Windows E01 (and optional memory dump) under `HACKATHON-2026/<case-name>/`. The folder is bind-mounted read-only into the agent's tool server.

2. **Create `docker/.env` with the required secrets.** Only one provider key is needed (OpenRouter unifies Anthropic + Gemini); the other two values are local-only tokens you generate yourself:

   ```bash
   cat > docker/.env <<EOF
   OPENROUTER_API_KEY=sk-or-v1-...
   MCP_TRANSPORT_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
   CAPABILITY_TOKEN_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
   EOF
   ```

   LangFuse tracing is optional; leave `LANGFUSE_*` unset to skip it.

3. **Bring up the two-container stack** (`sift-mcp` for the typed forensic tools, `sift-sentinel` for the agent + viewer):

   ```bash
   cd docker && docker compose up -d
   ```

   First pull is roughly 4 GB (one-time download of the SIFT image).

4. **Run a case.** From the repo root, with the agent container exec'd in:

   ```bash
   docker compose exec sift-sentinel uv run python run_case.py \
     --case my-case \
     --e01 /mnt/hackathon/my-case/disk.E01 \
     --memory-image /mnt/hackathon/my-case/memory.raw \
     --memory-profile Win10x64_19041
   ```

   `--e01` and `--memory-image` are optional individually (you can run disk-only or memory-only), but at least one is required, and `--memory-image` requires `--memory-profile`. Paths are inside the container; `HACKATHON-2026/` on the host is `/mnt/hackathon/` inside.

   The planner emits a typed tool plan and pauses for human approval. Approve in the terminal; the pipeline executes the approved tools, the interpreter writes findings with cited evidence, the 17-rule critic verifies every claim, and a human approves the final report.

5. **Read the output.**
   - Per-stage artifacts (plan, evidence, findings, critic disagreements, integrity ledger) land under `experiments/slice-2-notebook/out/runs/<case>/<run-id>/`.
   - Browse the same run in your browser at [http://localhost:8081/site/dashboard.html](http://localhost:8081/site/dashboard.html) (unified site) or [http://localhost:8080/viewer/](http://localhost:8080/viewer/) (raw viewer).
   - Every LLM call prints its cost before and after; a typical disk-only triage runs $0.30 to $0.70, memory-included runs $0.50 to $3.

Full troubleshooting walk-through (Docker Desktop on Windows, evidence-mount gotchas, container lifecycle): [docs/runbooks/slice-1-docker-runbook.md](docs/runbooks/slice-1-docker-runbook.md).

**Running on the SANS SIFT Workstation.** The Docker stack runs unchanged inside the SIFT Workstation OVA (Docker is preinstalled on SIFT). The container packages the same SIFT toolset the OVA provides (Volatility 2.6.1, The Sleuth Kit, RegRipper) so the forensic capability is identical. Judges who prefer the SIFT environment can spin up the OVA, install nothing extra, and run the same `docker compose` commands above.

## License

MIT. See [LICENSE](LICENSE).
