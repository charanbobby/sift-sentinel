# Test Project Plan — Find Evil Hackathon

**Last updated:** 2026-04-20
**Submission deadline:** 2026-06-15 (~2 months)

---

## Goal

Ship a portfolio piece demonstrating AI engineering skills. Winning is secondary. Not competing on forensics domain depth.

**Portfolio positioning:** *MCP-native agent with architectural guardrails for high-stakes domains.*

**Gap this fills vs. existing portfolio:**
- MaplePulse / Apprentice / SAI don't use MCP
- None show architectural constraints (only HITL prompt-based)
- None show autonomous self-correction loops in execution
- None are in defensive AI / cybersecurity

---

## Scope Decision

**Narrow, not broad.** Don't clone Valhuntir's 9-server platform.

**Target question the agent answers:**
> *"Given a compromised Windows disk image, autonomously identify the initial access vector and persistence mechanism, with self-correction loop and full audit trail."*

---

## Autonomy Posture

The slice plan deliberately **climbs an autonomy dial** rather than shipping a static Workflow Agent. Framing (DFIR-grounded, per [autonomy-dial.md](autonomy-dial.md)):

- **L1 — Assisted Workflow:** Human approves PLAN before any tool runs; Critic gates findings. *(Slice 2 — shipped)*
- **L2 — Guarded Execution:** Human approves initial PLAN; agent may self-correct and re-execute via the deterministic Critic + bounded retry budget. *(Slice 3 — shipped; security substrate in Slice 5)*
- **L3 — Exception-Based Autonomy:** Agent runs end-to-end; only Low-confidence findings or Critic-fail-fast events pause for human review. Requires chain-of-custody hashing + confidence rubric. *(Slice 6 — submission target)*

**Submission headline:** L2 shipped today, **L3 at submission on the full Reference Dataset.** Slice 6 also includes a bounded sampled-audit pass across the Reference Dataset — a research artifact, not a full autonomous-deployment claim. The autonomy-dial doc retains a fourth posture (post-deployment Forensic Auditor) for completeness, but the submission does **not** headline aspirational levels; it ships L3 and documents the one justified next step.

The demo narrative sells the climb, not a single posture: *"we shipped a deliberate, measured transfer of control from human to agent as the compensating controls landed."*

*External-critique note (2026-04-20):* an independent critique flagged that advertising four autonomy levels in the headline dilutes decisiveness and invites questions about work we're explicitly not doing. The reshape above — one shipped level plus one justified next step — addresses that directly. The Slice 6 sampled-audit artifact stays (engineering value intact); we just don't label it L4 in the demo script.

---

## Iteration Plan

Each slice ships something demoable. If we stop at any slice, it's still a portfolio piece.

| #   | Slice                                                                                   | Status                                                                   | Autonomy Posture                   | SKILL.md Phase |
| --- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ---------------------------------- | -------------- |
| 1   | **Stack proof** — Protocol SIFT installed, Claude Code answers one question on one disk | ✅ Done 2026-04-17 (via Docker; agent pivoted mmls → fsstat autonomously) | —                                  | 1-2            |
| 2   | **Notebook prototype** — Jupyter pipeline: image → MCP tools → structured findings JSON | ✅ Done 2026-04-19 (pipeline end-to-end green on both 2.5 cases; Step 0 prompt hardening in C2+C9 landed 2026-04-19)                                                                       | **L1: Assisted Workflow**          | 3              |
| 2.5 | **Mini-eval** — ground-truth findings on two disk images, scoring fn (precision / recall / hallucination count), baseline run of Slice 2 pipeline against them | ✅ Done 2026-04-19. **Pre-Step-0 baseline:** TP=4, FP=2, FN=0, **P=0.67, R=1.00** (`base-wkstn-05` P=0.50, `dfirmadness` P=1.00). FPs shared one pattern: agent couldn't distinguish DFIR responder tools (F-Response, Mnemosyne) from attacker persistence. **Post-Step-0 (2026-04-19 ~15:03):** TP=4, FP=0, FN=0, **P=1.00, R=1.00, Hallucinations=0** across both cases. Step 0 = INTERPRET prompt hardening (DFIR/vendor/Windows-default disambiguation + masquerading counter-rule) + required `classification` field on `Finding`. No Critic layer needed to hit perfect precision on current baseline. Scoring at [`score.py`](../../experiments/slice-2-notebook/score.py); per-case `scorecard.json` at `out/runs/<case>/`; pre-Step-0 artifacts archived at `out/runs/<case>/pre-step-0/` for A/B reproducibility. | L1 (measures L1 baseline) | 8 |
| 3   | **Self-correction loop** — Stateless Critic subagent + deterministic rule set + structured error + bounded retry, judged against the Slice 2.5 baseline  | 🟡 **Phase A (Step 0)** ✅ 2026-04-19. **Phase B (R_01–R_11 Critic)** ✅ 2026-04-19 — C10–C14 + C4 LangGraph rewire. **Last-mile (C6/C9 corrective consumption)** ✅ 2026-04-19. **Phase C (committed 2026-04-20, ~6 hours, scope from round-3 critique items 10 + 11 + 14):** (a) R_06 Negative-Result-Metadata check (item 11, uses static checklist table until Slice 5 surfaces `expected_paths_covered`); (b) R_12 Evidence-of-Absence-vs-Absence-of-Evidence + R_13 Temporal Consistency Critic rules (item 10); (c) three L3 primitives — plan-hash dedup, pre-retry context-clearing (debounce hook), thread-scoped checkpointer (item 14); (d) plan_node idempotency-guard relaxation (C6 edit, ~15 min). **Full node-lift deferred to Slice 5** (moving C8/C9 inline bodies into `execute_node`/`interpret_node` requires async handling + state-mutation rewrite + graph re-compile — Slice 5 restructures the MCP server interface `ToolResult` → `EvidenceRecord` anyway, which forces the lift naturally; doing it in Phase C = ~4 hours of churn that gets partially rewritten next slice). Phase B's C14 synthetic-state scenarios already proved the retry routing works end-to-end; Phase C's L3 + new rules use the same synthetic-probe pattern. | **→ L2: Guarded Execution**        | 4-5            |
| 4   | ~~Full eval harness~~ — **Merged into Slice 6 on 2026-04-19.** The 10–20-case eval set becomes the *Reference Dataset* that also powers the L4 narrative demo. Collapse lets us ship L2-delta measurement + L3 controls + L4 audit loop as one coherent artifact instead of three. | ⬅ merged | — | — |
| 5   | **Dual-channel evidence boundary + capability tokens + 5th MCP tool (T1053.005)** — Runbook drafted 2026-04-20 ([slice-5-runbook.md](../runbooks/slice-5-runbook.md)). Dual-channel handler (structured-field extraction, quarantine-not-redact, per round-3 carried item 7) as the **primary adversarial-injection defense**; capability tokens as application-layer least-privilege routing scoped to `(case_id, allowed_tools, allowed_paths, plan_digest, expires_at)`; **new `scheduled_tasks_parse` MCP tool** (carried item 15, committed 2026-04-20) adds T1053.005 coverage without changing the investigation question. Every structured-field result surfaces `expected_paths_covered` + `tool_execution_status` to feed Slice 3 Phase C rules R_06 / R_12. | ⬜                                                                        | L2 (security substrate)            | 5              |
| 6   | **Reference Dataset + L3 ship + sampled-audit research artifact** — (a) *Reference Dataset:* stage ~5–7 SRL-2018 Windows/NTFS E01s (`base-dc`, `base-file`, `base-rd-01/02`, `base-wkstn-01`, plus the 3 already-analyzed — `base-wkstn-05`, `dfirmadness-001-desktop`, `dmz-ftp`); full ground-truth annotation on 3 cases (L2→L3 regression baseline); sampled post-hoc audit on the rest. (b) *L3 controls:* H/M/L confidence rubric with auto-escalation of Low, per-excerpt sha256 provenance linked to `plan_digest`, Critic-disagreement log, token/latency/tool-call audit trail, **append-only integrity ledger stored separately from case folders** (NIST guidance — hashes in the same mutable folder look like self-attestation). (c) *Sampled-audit research artifact:* autonomous run across the full Reference Dataset with post-hoc reviewer audit on sampled findings — scoped as a research artifact, not a claim of deployment-ready forensic-auditor operation. | ⬜ | **→ L3: Exception-Based Autonomy** | 7 + 8 |
| 7   | **Full-stack UI** (stretch — cut first if behind) — Next.js findings viewer + approval workflow. Audit trail (Slice 6) is the more impressive piece in a high-stakes domain than a polished UI | ⬜                                                                        | —                                  | 6              |
| 8   | **Demo + submission** — Scripts, diagrams, 5-min video                                  | ⬜                                                                        | —                                  | 10             |

---

## Current Status

- ✅ Phase 1 research — [Learning.md](../learning/Learning.md) covers Valhuntir + Protocol SIFT
- ✅ Forensics domain knowledge — Blue Cape DFIR course notes in `training/`
- ✅ Evidence downloaded + mounted read-only into Docker container (pivoted from SIFT VM → Docker on 2026-04-17 for Hyper-V/VirtualBox speed reasons)
- ✅ Docker + Protocol SIFT + Claude Code running (slice 1)
- ✅ First real MCP tool call against E01 — agent ran `fsstat` correctly, returned valid NTFS metadata
- ✅ Slice 2 end-to-end — Cells C1-C9 green as of 2026-04-19. C5 EXTRACT lives: `google/gemini-3.1-flash-lite-preview` via OpenRouter, `response_format={"type":"json_object"}` + inline schema + `Candidates.model_validate_json()`, traced to Langfuse. C6 PLAN lives: `anthropic/claude-sonnet-4.6`, `ToolPlan` schema, structural-invariants check (every `regripper_run` must have an `icat_extract` upstream in `depends_on`). C9 INTERPRET hardened 2026-04-19 post-Slice-2.5 with DFIR/vendor/Windows-default disambiguation + masquerading counter-rule + required `classification` field (Step 0 of Slice 3).
- ✅ **MCP toolset un-deferred (2026-04-19)** — `icat_extract` + `regripper_run` live. First 2-tool PLAN output made clear the pipeline couldn't reach Registry-based persistence (where most malware hides); added the two tools after fail-fast-verifying `icat` + `rip.pl` against the real E01. Patched an upstream Perl bug in `rip.pl` line 75 (orphan `:` branch of a commented ternary) in `docker/sift/Dockerfile`. C3 smoke test now drives all 4 tools end-to-end against the live SOFTWARE hive and regripper's `run` plugin.
- ✅ **Slice 2 EXECUTE produced findings on `base-wkstn-05` (2026-04-19)** — pipeline ran end-to-end, [`findings.json`](../../experiments/slice-2-notebook/out/runs/srl-2018-wkstn-05/findings.json) contains 4 persistence findings (F-Response Subject, mnemosyne, PerfMon, tbbd05). L1 baseline material exists.
- ✅ **Slice 2.5 ground-truth annotation for `base-wkstn-05` (2026-04-19)** — verdicts recorded in [`slice-2.5-ground-truth.md`](../runbooks/slice-2.5-ground-truth.md); machine-readable baseline at [`ground_truth.json`](../../experiments/slice-2-notebook/out/runs/srl-2018-wkstn-05/ground_truth.json). Scorecard: TP=2 (PerfMon, tbbd05), FP=2 (F-Response, mnemosyne — both legitimate DFIR responder tools the agent couldn't distinguish from attacker persistence), FN=0 within audited scope. **Precision 0.50, Recall 1.00.** FP pattern is uniform: "responder tool" is the specific failure mode Slice 3's Critic needs to address. False-negative spot-check covered the full 3,684-line services output (agent only saw first ~65% due to MCP 64 KB stdout cap); no additional findings missed by truncation.
- ✅ **Slice 2.5 second-image validation on `dfirmadness-001-desktop` (2026-04-19)** — DFIR Madness Case 001 DESKTOP image run through the same pipeline (after preprocessing the multi-segment E01 to raw NTFS `.dd` via `ewfmount` + `dd`, and extending the MCP `_check_read_path` allowlist to include `/mnt/derived`). Pipeline produced 2 high-confidence findings: HKLM Run key `coreupdate` (fileless PowerShell stager with Base64 payload in `HKLM:Software\q9Z1bssi`) and service `coreupdater` at `C:\Windows\System32\coreupdater.exe`. Cross-referenced against [published DFIR Madness answer key](https://dfirmadness.com/answers-to-szechuan-case-001/) and community writeups ([Netresec](https://www.netresec.com/?page=Blog&month=2021-07&post=Walkthrough-of-DFIR-Madness-PCAP), [MimirCyber](https://mimircyber.com/answers-to-the-case-of-the-stolen-szechuan-sauce-case-001/)) — both findings are named as attacker persistence (service `coreupdater` installed at `02:42:42 on DESKTOP-SDN1RPT` matches agent's extracted LastWrite `Sat Sep 19 03:42:42 2020 Z` with 1-hour TZ offset). Scorecard: TP=2, FP=0, FN=0, **Precision 1.00, Recall 1.00** within audited scope. Zero hallucinations. Full provenance + scope caveats in [`slice-2.5-ground-truth-dfirmadness.md`](../runbooks/slice-2.5-ground-truth-dfirmadness.md); machine-readable verdicts at [`ground_truth.json`](../../experiments/slice-2-notebook/out/runs/dfirmadness-001-desktop/ground_truth.json). Two-image contrast clarifies the Critic target: `base-wkstn-05` FPs are uniformly the "responder-tool cohabitation" failure mode, not random noise.
- ✅ **Slice 3 Step 0 — INTERPRET prompt hardening + `classification` schema field (2026-04-19 ~15:03)**. Landed in [`slice2.ipynb`](../../experiments/slice-2-notebook/slice2.ipynb) C2 (added `Classification` Literal + required `classification: Classification` field on `Finding`) and C9 (Hard Rule 3 = "Classify every finding", new Disambiguation section listing DFIR-responder / commercial-vendor / Windows-default signatures, masquerading counter-rule, required `notes` rationale for `attacker_persistence`). Re-ran pipeline against both 2.5 cases. `base-wkstn-05`: F-Response + Mnemosyne correctly classified as `legitimate_responder_tool` and suppressed; PerfMon + tbbd05 retained as `attacker_persistence`. **Precision: 0.50 → 1.00** on that case. `dfirmadness-001-desktop`: no responder tools to suppress, 2 TPs retained, **1.00 → 1.00** (no regression). Combined: **0.67 → 1.00**, Hallucinations still 0. Pre-Step-0 artifacts archived per case at `out/runs/<case>/pre-step-0/` for reproducible A/B. Rationale + lectured-optimized hierarchy walked through [slice-3-runbook.md Step 0](../runbooks/slice-3-runbook.md#step-0--upstream-hardening-interpret-prompt--classification-schema-field) — the bootcamp's "prompt → more LLM calls → retrieval → agents → fine-tuning" sequence was correct: prompt-layer fix resolved the full observed FP class without any Critic code.
- ✅ **Slice 3 Phase C closed 2026-04-20.** L3 primitives (plan-hash dedup, debounce hooks, thread-scoped checkpointer, idempotency-guard relaxation) + two new Critic rules (R_12 Evidence-of-Absence minimum-viable; R_13 Temporal Consistency stub) all landed in `slice2.ipynb` C2/C10/C10b/C12 via single surgery script, probed in container venv, post-surgery exec green. Registry now: 11 active rules + R_13 stub + R_06 checklist-coverage enhancement deferred-to-Slice-5 = 13 rule IDs. `ESCALATE_CODES` grew to `{EXCERPT_HALLUCINATION, INJECTION_FLAGGED_EVIDENCE, TEMPORAL_INCONSISTENT}`. Slice 3 end-to-end node-lift (C6/C8/C9 bodies → `plan_node`/`execute_node`/`interpret_node`) intentionally bundled with Slice 5's MCP refactor — see "Module promotion deferred to Slice 5 exit" decision below.
- ⬜ Next: Slice 5 per [slice-5-runbook.md](../runbooks/slice-5-runbook.md). Includes the combined node-lift + module extraction (notebook → `pipeline/*.py`). R_06 enhancement + R_13 real body land with Slice 5's structured-metadata surface.

## Learning the Domain

- **New here? Start with [what-we-are-building.md](what-we-are-building.md)** — plain-English overview + ASCII timeline of where our agent fits in a cyberattack lifecycle.
- Then [concepts.md](concepts.md) — primer on host vs. SIFT container vs. E01 evidence file, the MCP piece, and key file formats.
- [learning-resources.md](../learning/learning-resources.md) — external DFIR courses and references.
- **[slice-1-docker-runbook.md](../runbooks/slice-1-docker-runbook.md)** — Slice 1 runbook (✅ complete).
- **[slice-2-runbook.md](../runbooks/slice-2-runbook.md)** — Slice 2 runbook (active).
- **[slice-3-runbook.md](../runbooks/slice-3-runbook.md)** — Slice 3 runbook (drafted 2026-04-18 — implementation gated on Slice 2 + 2.5 completion).

---

## Key Decisions Made

| Decision                 | Choice                                                            | Why                                                                                                                                                                                             |
| ------------------------ | ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Agent runtime            | Claude Code (default)                                             | Hackathon-preferred; proven by Protocol SIFT; revisit if self-correction loop needs LangGraph                                                                                                   |
| Reference base           | Protocol SIFT (extend, not fork Valhuntir)                        | Valhuntir is the "example submission" — judges have seen it. Differentiate, don't clone                                                                                                         |
| Scope                    | Narrow — one investigation question                               | Portfolio quality over platform breadth                                                                                                                                                         |
| Evidence format          | E01 disk images + RAM dumps (Windows-focused)                     | Most common hackathon case data                                                                                                                                                                 |
| Runtime env (2026-04-17) | Docker container (`digitalsleuth/sift-docker:jammy`), not SIFT VM | Windows 11 with Docker Desktop/WSL2 forces Hyper-V on → VirtualBox runs in slow software-emulation mode. Docker uses Hyper-V natively → full speed. Also zero-copy bind mount to evidence on D: |
| LangGraph adopted in Slice 2 (2026-04-17) | `StateGraph` wraps the Extract→Plan→Execute→Interpret pipeline from notebook cell C4 onwards; not deferred to Slice 3 | Free Mermaid/PNG visualization as we build, explicit `PipelineState` contract, and Slice 3's self-correction branching slots in via one `add_conditional_edges()` call |
| Workflow Agent over Autonomous Agent (2026-04-18) | Permanent Human Checkpoint after PLAN; Critic gates findings before they're committed; agent never relinquishes 100% control | Forensics has irreversible-harm "blast radius" — wrong conclusions carry legal weight. Workflow Agent posture is a deliberate engineering choice for forensic integrity, not a capability gap. Reframes the portfolio narrative around control rather than autonomy |
| Indirect-prompt-injection scanning of evidence (2026-04-18, lands in Slice 5) | Pre-LLM scan of every `stdout_excerpt` from MCP tools for known injection patterns (e.g. `ignore previous instructions`, base64-encoded directives, embedded role markers); injection hits → either redact + flag, or fail the step | A malicious E01 can carry attacker-authored strings (filenames, registry values, document content) that read as prompts when `fls_list` / `regripper_run` returns them. Valhuntir doesn't address this — concrete differentiator |
| 4-tool MCP scope re-adopted in Slice 2 (2026-04-19, reversing the 2026-04-17 "build-small" trim) | `icat_extract` + `regripper_run` un-deferred; PLAN prompt now advertises all 4 tools + a 7-plugin allowlist + hive→plugin mapping; MCP server pins regripper's hive to `<case>/analysis/extracted/` so icat-before-regripper is enforced at the server, not just the prompt | Reviewing the first 2-tool PLAN output made clear the pipeline could only reach file-on-disk persistence (scheduled tasks, startup folder) — it literally could not open the Registry, which is where most Windows persistence lives. Shipping an end-to-end pipeline whose honest answer is `NOT_FOUND` for "pipeline can't look there" would have been hollow. Un-deferred after fail-fast-verifying `icat` + `rip.pl` against the real E01; patched an upstream Perl bug in `rip.pl` along the way |
| Capability-token framing reframed (2026-04-20, external round-3 critique) | Tokens described as "application-layer least-privilege logical routing" — **not** as an impenetrable defense against adversarial prompt-injection bypass. In our stdio transport (agent and MCP server run in the same container under the same UID), a truly hijacked agent has routes around the MCP server that capability tokens can't close (Python `subprocess` / direct FS access at the orchestrator layer). Dual-channel handler is the actual adversarial-injection defense — it keeps injection content out of the LLM context in the first place | Round-3 critic pointed out that conflating application-layer routing with system-level isolation invites immediate technical scrutiny from judges familiar with agentic threat modeling. The reframe preserves tokens as a real control (they still prevent logical out-of-scope tool requests, accidental agent drift, and poorly-formed LLM plans) while honestly describing what they *don't* defend against. Full isolation against adversarial bypass would require seccomp / eBPF / microVM — out of scope for an 8-week hackathon; documented as an extension point |
| Injection-scanner design revised to dual-channel (2026-04-20, supersedes the 2026-04-18 "redact + flag" row above) | Raw evidence preserved immutably and hashed (chain-of-custody channel); LLM receives server-side-extracted structured fields only; content flagged by the scanner is quarantined from the agent context and escalated for human review — **never silently redacted from the evidence record** | External critique pointed out two failure modes in the original design: (a) attacker-authored evidence strings (filenames, registry values, document content) are *legitimate forensic artifacts*; erasing or rewriting them compromises evidentiary integrity, (b) prompt-level filtering is weaker than structured-field extraction per newer indirect-prompt-injection literature. Dual-channel design keeps injection text out of the LLM context without mutating the evidence. Lands in Slice 5 per carried item 7 in External Critique Intake section |
| Plan generalizes at workflow level only; tool set is Windows-disk-scoped by deliberate choice (2026-04-19) | The EXTRACT → PLAN → HUMAN → EXECUTE → INTERPRET skeleton (with structural invariants, LangGraph, Langfuse, capability tokens) is evidence-type-agnostic and carries through the autonomy climb. The current 4-tool MCP set (`fsstat_e01`, `fls_list`, `icat_extract`, `regripper_run`) is **NTFS + Registry only**. Memory analysis (Volatility) and Linux-disk analysis are **out of scope for submission** and documented as stated limitations rather than gaps to close | Now holding `base-wkstn-05` (disk + memory), `dmz-ftp-cdrive.E01` (DMZ server, OS unconfirmed), `base-mail-memory.7z` (mail server RAM). Only the wkstn-05 disk is in current tool-set scope. Memory + Linux would each need a separate tool profile (Volatility MCP; log/service-file tools) plus per-profile PLAN prompts — net-new work that would blow the 2-month budget. Narrative framing in the submission: *"Windows disk persistence — a deliberate narrowing; memory + cross-platform are documented extension points, not unfinished work."* Cheap generalization test still worth doing: once Slice 2 is green on wkstn-05, point the same pipeline at `dmz-ftp-cdrive.E01` and see whether the PLAN stays coherent or hallucinates workstation-specific paths (`/Users/<name>/AppData`). If it hallucinates, add a `host_role` parameter to the PLAN prompt. Autonomous transition (L2/L3) introduces a new **evidence-dispatch** problem the workflow agent sidesteps (human picks which file to feed) — slot that as a Slice 3 / Slice 5 design question, not a Slice 2 fix |
| MCP tool scope broadened from 4 → 5 (2026-04-20, partially reversing 2026-04-19 "4-tool narrowing") | Add `scheduled_tasks_parse` as the 5th tool in Slice 5 (carried item 15). Extracts + parses XML from `C:\Windows\System32\Tasks\` to reach T1053.005. Remains NTFS + Registry-scope-compatible. Memory and Linux still out of scope | T1053.005 is top-three Windows persistence (with T1547.001 + T1543.003, both already in scope); ships the ATT&CK-mapping story the Slice 3 ATT&CK validator already promises. Re-estimated at observed velocity to ~½–1 day (round-3 critic's 1-week estimate was generic-velocity padding). Does not force a Q2 / demo / Reference-Dataset cut |
| Scope re-estimate calibration: use observed velocity, not external-critic generic estimates (2026-04-20) | External-critic scope estimates that reference 1–2-week costs are treated as priors to be re-verified against observed project pace. At observed pace (15 hours over a weekend shipped Slice 2 + Slice 2.5 + full Slice 3 Phase A/B + last-mile + ATT&CK + Slice 5 runbook), most 1-week estimates collapse to ~1 day of focused work with fail-fast rigor. This unblocks items that would otherwise force a stretch-scope cut | Three factors drive the delta: direct JSON notebook edits bypass tool-round-trip overhead; fail-fast probe pattern catches issues before they compound; architectural patterns from earlier slices translate directly to later ones. Documented so future decisions don't re-inherit inflated external estimates. Carried items 14 and 15 committed on this basis; future flagged items get the same re-verification treatment before scope cuts |
| Module promotion deferred to Slice 5 exit (2026-04-20, end of Phase C) | Notebook stays as the code home through Phase C close and into the start of Slice 5. `pipeline/schemas.py` + `pipeline/critic.py` + `pipeline/graph.py` + `pipeline/templates.py` are extracted AS PART OF Slice 5's node-lift + `ToolResult → EvidenceRecord` refactor — single bundled motion, not two separate migrations. `slice2.ipynb` is slimmed to a judge-walkthrough artifact (imports from `pipeline/`, runs one case, shows findings + audit inline with markdown narrative). `eval/` as a CLI lands in Slice 6 | User raised the "notebook is getting large" concern at end of Phase C. Three pressures pointed to Slice-5-bundled promotion rather than immediate extraction: (a) Slice 5 is already going to rewrite the executor's API (EvidenceRecord, dual-channel MCP) — promoting now means rewriting the modules next week; (b) the node-lift is the SAME motion as module extraction — moving function bodies into `*_node()` functions and into `pipeline/*.py` is one refactor, not two; (c) Slice 6's eval harness is naturally a CLI, giving a second `pipeline/*.py` milestone regardless. Doing it at Slice 5 exit amortizes the extraction cost against a rewrite already planned, and lets the notebook keep its narrative role for the submission artifact rather than competing with modules as a code home |

---

## Open Questions

- [x] ~~Where do we get ground-truth case data for Slice 4? (SANS training, CFReDS, Magnet CTF, or lab-generated). Slice 2.5 mini-eval can be hand-coded against `base-wkstn-05` we already have — only the 10–20-case expansion needs new evidence~~ — **Answered 2026-04-19 via the Slice-4→6 collapse:** Reference Dataset draws from the SANS SRL-2018 manifest ([dataset_manifest.md](../reference/hackathon/dataset_manifest.md)) — Windows/NTFS E01s only (`base-dc`, `base-file`, `base-rd-01/02`, `base-wkstn-01` + the 3 already-analyzed). No CFReDS / Magnet needed; stays within the hackathon's own Reference Dataset, which is the more defensible framing for the L4 audit narrative.
- [ ] **Slice 6 — sampled-audit framing for non-annotated cases:** with ground truth on only 3 cases, how do we judge findings on the remaining ~4? Options: (a) hand-annotate the N findings the pipeline surfaces (cheaper than full ground-truth since we only audit what the agent returns, not what it should have returned); (b) accept "plausibility-review" framing and state the recall-blind-spot explicitly in the submission. NotebookLM ask: *"Does 'sampled post-hoc audit on a Reference Dataset with partial ground truth' count as a defensible L4 demonstration in DFIR literature, or does it require stronger calibration telemetry?"*
- [ ] **Slice 6 — evidence-dispatch at L3/L4:** once the human stops picking which E01 to feed (L3 onward), how does the agent pick the next case? Options: iterate the manifest in order; score-and-rank by "likely initial access vector" heuristic; always run all N in parallel. This is the "evidence-dispatch" problem flagged in the 2026-04-19 Key Decision row; lands in Slice 6 design.
- [x] ~~**Slice 2.5 external-validation image** (parked 2026-04-19): run the pipeline against a public DFIR CTF image that ships with a published solution — **Ali Hadi's "Case 001 / Programmer Image"** (documented attacker persistence, known-good answer key) or Magnet Forensics' yearly CTF archives.~~ — **Answered 2026-04-19**: picked **DFIR Madness Case 001 "Stolen Szechuan Sauce"** (better fit than Ali Hadi because it ships a published answer key; Ali Hadi's solutions are instructor-only). Ran DESKTOP image through the pipeline; result in Current Status bullet above. Preprocessing recipe (`ewfmount` + `dd` the NTFS partition, mount under `/mnt/derived`) + allowlist extension to `_check_read_path` are documented in [`slice-2-runbook.md`](../runbooks/slice-2-runbook.md) / comments in `mcp_server/server.py`; reusable for any future multi-segment / GPT-disk CTF.
- [x] ~~Does self-correction need LangGraph multi-agent, or can Claude Code's native loop handle it?~~ — Answered 2026-04-17: LangGraph adopted starting Slice 2 (see Key Decisions)
- [x] ~~Full-stack UI (slice 7) — worth the effort for demo, or is terminal recording enough?~~ — Answered 2026-04-18: cut to "stretch only". Audit trail (Slice 6) is the more impressive piece
- [ ] **Slice 3 — Critic design specifics** (next NotebookLM ask): (a) what does the deterministic rule set look like for *persistence findings* — concrete checks, not categories; (b) when the Critic disagrees, what's the re-plan / retry budget that prevents infinite loops; (c) how does disagreement surface in the audit trail
- [ ] **Slice 5 — capability-token shape**: per-tool, per-case scoping; how does the MCP server validate without coupling to a specific orchestrator
- [ ] **Portfolio demo on SSHub.dev (post-competition, do later):** wire a public demo for [SSHub.dev](https://sshub.dev) — sibling to MaplePulse. Likely shape: sample E01 or memory-image upload → live agent reasoning stream (real-time LangGraph state per item 12) → final forensic report. **Repo name picked 2026-04-20: `sift-sentinel`** (SIFT Workstation nod + watchful-AI vibe; legible to forensic-domain readers). Defer build until after 2026-06-15 submission so it doesn't compete with the competition runway.
- [ ] **PLAN model — swap to `anthropic/claude-haiku-4.5` post-Slice-2.5?** Probe run 2026-04-19 ([probe_plan_models.py](../../experiments/slice-2-notebook/probe_plan_models.py), results in `out/model_probe.json`) compared 3 candidates against our current C6 prompt (all 3 passed the structural invariants):
    - **`anthropic/claude-sonnet-4.6`** (current): $0.049 → $0.040 with cache hit, 28–43 s, 18 steps. Caching works (`cached_tokens: 2409`).
    - **`anthropic/claude-haiku-4.5`**: $0.013 / call, 10 s, 16 steps. **3× cheaper + 3× faster than cached Sonnet**. BUT `cache_control` doesn't fire on Haiku via OpenRouter, AND the validator caught a semantic error Sonnet didn't make (step looked for `AppData` inode inside `/Users` listing, when `AppData` actually lives at `/Users/<name>/AppData`).
    - **`z-ai/glm-5.1`**: $0.023 / call, **73–193 s**. Eliminated — verbose (4500-token output vs 2500) and 2–7× slower than Sonnet. No win.
    - **Decision — stay on Sonnet 4.6 for now.** The Haiku cost / latency win is real (~$0.027 / call saved, 3× faster) but its semantic variance is measurable and our invariants can't catch domain-knowledge errors. Correct swap criterion is an accuracy-regression bound, which needs the Slice 2.5 mini-eval baseline. **Re-run the probe once Slice 2.5 has ground truth; if Haiku regresses < 5 % vs Sonnet on accuracy, swap for the cost win. Opus 4.7 remains a quality-upside option if Sonnet starts failing invariants.**

---

## External Critique Intake — 2026-04-20

Three external LLMs reviewed the vision + plan. **Round 1 (NotebookLM)** validated positioning and surfaced the R_06 Negative-Result-Metadata idea. **Round 2** (grounded in the public SANS brief + MCP spec + NIST guidance) raised the "three cases" inflation, legal-overclaim, chain-of-custody novelty, and L4-in-the-headline issues — four language fixes landed in `vision.md` + this file the same day. Items 5–8 below came from round 2. **Round 3** (grounded in LangGraph/MCP/NIST research) materially advanced the analysis — five new engineering issues the first two rounds missed. Items 9–13 below are the round-3 additions that are **committed to the plan**; items 14–15 are **flagged for decision, not committed** (they change scope/effort substantially and need explicit sign-off).

The `vision.md` changes from round 3 (same-day, already landed): Slice 5 rewrite to the dual-channel design; novelty-axis reframe (dual-channel as the adversarial defense, tokens as least-privilege routing); Slice 6 update to linear-hash-chained ledger; Hadi3 named in the pitch as a negative-case stress test; added success criterion #6 for negative-case discipline.

### Carried item 5 — Autonomy metrics in the scorecard *(Slice 6 scope)*

**What:** extend `score.py` and the submission accuracy report beyond precision/recall to measure the behaviours the judging rubric will actually probe:
- **Self-correction recovery rate** — fraction of Critic-triggered retries that end in a correct final finding within the bounded retry budget
- **Human intervention rate** — mean approvals/escalations per case; fraction of cases that finish without manual pause
- **Injection-defense efficacy** — TP / FP / FN on seeded adversarial strings planted in test E01s
- **Capability-bypass test results** — denied out-of-scope tool calls, denied path escapes, expired-token behaviour, tampered-plan-digest behaviour
- **Replay/provenance coverage** — fraction of findings where a reviewer can navigate finding → tool output → hash-linked excerpt
- **Run-to-run stability** — variance in findings / retries / latency across repeated runs of the same case
- **Cost + latency per case** — wall-clock, tokens, per-stage breakdown
- **Baseline delta** — score against unmodified Protocol SIFT on the same cases (see item 6)

**Why:** official judging priority leads with *autonomous execution quality* and *IR accuracy*, then *constraint implementation* and *audit trail*. Our current scorecard only measures final-output accuracy — it can't answer "did the critic actually help?" or "is this workflow dependable under repeat runs?" Without these numbers, the architecture is a plausibility argument, not a measured one.

**Where it ships:** Slice 6 deliverable. Scorecard schema lands alongside Reference Dataset annotation work. Probably a `scorecard_v2.json` extension, not a rewrite.

### Carried item 6 — Baseline + ablation section *(Slice 6 scope, submission artifact)*

**What:** two comparison tables in the submission accuracy report:
1. **Baseline comparison:** our pipeline vs. unmodified Protocol SIFT on the same Reference Dataset cases.
2. **Ablation:** our pipeline with each control disabled in turn — no Critic, no capability scoping, no injection quarantine, no classification field. Report the precision/recall/hallucination delta.

**Why:** converts "we added these controls" into "each control is worth *this much* measured accuracy." Directly answers the rubric's *constraint implementation* and *audit trail* axes. Also guards against quiet regression during Slice 5/6 work — if an ablation row suddenly matches the full pipeline, a control isn't actually doing anything.

**Where it ships:** accuracy-report appendix. Small ablation harness around `score.py`. Can be prototyped on the 2.5 cases before Reference Dataset expansion.

### Carried item 7 — Injection scanner design shift *(Slice 5 scope change)*

**What:** move the adversarial-evidence defense from "scan stdout, flag + redact injection patterns" to a **dual-channel design**:
- **Raw channel:** evidence bytes preserved immutably (hashed, stored, never mutated). Chain-of-custody operates here.
- **Agent channel:** structured facts extracted server-side (parsed registry keys, file paths, timestamps — not free-form stdout). Suspicious content is **quarantined** from the agent's reasoning context, not erased from the evidence record.
- **Escalation:** content flagged by the scanner triggers a human-review path, not silent redaction.

**Why:** the original "redact + flag" design was criticized on two grounds — (a) it can destroy or obscure legitimate evidence (attacker-authored filenames / registry values may look exactly like prompt-injection text, and they're forensically relevant); (b) prompt-level filtering is weaker than structured-field extraction. The dual-channel design preserves evidentiary integrity while still keeping adversarial strings out of the LLM's context window. Newer indirect-prompt-injection literature argues structured parsing + filtering beats pure prompt defenses.

**Where it ships:** Slice 5 (the runbook for which isn't written yet — draft it with this design, not the original one). MCP server grows a per-tool "structured extraction" mode; scanner becomes an LLM-context gate, not an evidence mutator.

### Carried item 8 — Append-only integrity ledger *(Slice 6 scope addition)*

**What:** hashes produced by the chain-of-custody mechanism get written to a separate, append-only store — not the same case folder that holds the evidence + findings. Concrete shape TBD; candidates: a separate `ledger/` tree with restricted write perms; a simple hash-chained JSONL where each line references the previous line's hash; an external database table.

**Why:** NIST guidance is explicit that hash records should be stored separately and secured against practitioner tampering. If the same process can generate evidence excerpts **and** update the store that supposedly attests to them, a skeptical reviewer will read it as self-attestation. A separate append-only ledger is a small addition that defeats that critique directly.

**Where it ships:** Slice 6, alongside the sha256-per-excerpt work. Pin the design before writing the `verify_chain_of_custody.py` replay tool so they're consistent.

### Carried item 9 — Linear hash chain on the integrity ledger *(Slice 6 scope addition — round 3, committed)*

**What:** every entry appended to the integrity ledger (item 8) includes the SHA-256 of the previous entry's signature block. Hash-of-entry-N = SHA-256(plan_digest ‖ tool_output_hash ‖ critic_decision ‖ hash-of-entry-(N-1)).

**Why:** plain append-only storage is a trust assumption; a linear hash chain is a cryptographic guarantee. If a single byte of a historical tool output is altered, the hash of that entry changes, which invalidates every subsequent entry — **mathematical non-repudiation**, a core tenet of NIST SP 800-86. Few lines of Python in the ledger-writer function, massive defensibility payoff. Supersedes the plain "append-only" framing in item 8 — that framing was correct NIST alignment but missed the cryptographic-chain novelty a judging panel will expect from an audit-trail-emphasized submission.

**Where it ships:** Slice 6, same file as item 8's ledger-writer. `verify_chain_of_custody.py` walks the chain on replay.

### Carried item 10 — Two new Critic rules: R_12 Evidence-of-Absence, R_13 Temporal Consistency *(Slice 3 Phase C or Slice 6 scope — round 3, committed)*

**What:**
- **R_12 — Evidence-of-Absence vs Absence-of-Evidence:** if a finding records "no persistence found in X hive," the Critic must verify that the collection tool (`regripper_run` / `fls_list` / `icat_extract`) executed successfully and returned a structurally valid (possibly empty) response. If the tool log shows a timeout, permission denial, or parse failure, the "empty" finding is rejected as a silent failure and routed to human review.
- **R_13 — Temporal Consistency:** the Critic cross-references agent-claimed timestamps against raw `fsstat_e01` / hive-LastWrite timestamps extracted by the dual-channel handler. A finding that places a persistence mechanism outside the hive's last-modified window is temporally impossible — definitive hallucinated-relationship signature. Escalates to human review.

**Why:** the two failure modes R_12 and R_13 address aren't structural — they're *semantic* (silent execution failures masquerading as clean findings; hallucinated causal links between real strings). The existing 11 rules check structural constraints (schema, path consistency, scope, tool-match, classification). R_12 and R_13 close the gap on the two most dangerous agentic-forensic failure modes identified in round 3.

**Where it ships:** Slice 3 Phase C (opportunistic, alongside the node-wiring close-out) or Slice 6 (if we wait until Reference Dataset work). Either way, must exist before the final submission demo.

### Carried item 11 — R_06 Negative-Result-Metadata Augmentation promoted to committed *(Slice 3 Phase C scope — rounds 1 + 3, committed)*

**What:** every collection tool call (`regripper_run`, `fls_list`) silently emits a checklist of *expected* artifact paths as part of its structured output. The Critic fails `SCOPE_INCOMPLETE` if the tool ran but the checklist isn't fully covered in `tool_calls.jsonl` before the agent returns `NOT_FOUND`.

**Why:** converts "agent thinks it's done" into "agent proves coverage." Originally suggested by NotebookLM (round 1), independently re-suggested by round 3. Three-for-three endorsement from external critics is decisive — move from candidate to decided.

**Where it ships:** Slice 3 Phase C with R_12 + R_13. Part of the same Critic-rule expansion.

### Carried item 12 — Real-time LangGraph state-transition visualization *(Slice 8 scope — round 3, committed)*

**What:** during the 5-minute demo, the terminal (or a lightweight side panel) continuously streams the active LangGraph node — EXTRACT → PLAN → EXECUTE → INTERPRET → CRITIC → (on Critic fail) → RE_PLAN → EXECUTE → ... — so the judge sees the cyclic routing in real time. Critical during the seeded-failure segment: the visualizer must show the Critic catching the fabricated excerpt, generating the corrective, and routing the graph back to PLAN.

**Why:** the weakest moment in an autonomous LangGraph demo is the 30–60 s LLM-thinking silence. Against Valhuntir's multi-server reactive UI, a static terminal waiting on an API response reads as sluggish and brittle. The real-time visualizer proves the autonomy is *controlled* rather than *chaotic*.

**Where it ships:** Slice 8 (demo prep). Can be built as a simple Rich-library terminal panel or a Mermaid-live renderer. Nothing fancy — must exist before the demo video is cut.

### Carried item 13 — Try-it-out hardening *(Slice 8 scope — round 3, committed)*

**What:** three specific tripwires the judging panel will hit if not pre-addressed:
1. **Docker bind-mount UID/GID translation.** E01 on Windows host → Linux container often hits "permission denied" inside the container. The try-it-out instructions must include the exact `docker run` flags (`--user $(id -u):$(id -g)` or equivalent) and document the UID/GID mapping explicitly.
2. **LangGraph checkpointer.** Ship the open-source release with `MemorySaver` exclusively — no `SqliteSaver` / `PostgresSaver` / external-DB dependency. Eliminates database-init friction entirely for judges.
3. **Anthropic API rate-limit handling.** Wrap all LLM calls with exponential backoff on HTTP 429; log a formatted "rate-limited, retrying in Ns" message rather than crashing with a raw stack trace mid-demo.

**Why:** "try-it-out instructions" is a required submission artifact. The fastest way to lose "usability and documentation" points (and credibility) is a brittle reproduction path.

**Where it ships:** Slice 8, before the submission package is zipped. Each of the three has a one-hour test: zip the repo, hand it to a clean machine, replicate.

---

### Carried item 14 — LangGraph L3 primitives *(COMMITTED 2026-04-20 after velocity-based re-estimate — see Key Decisions row)*

**What (three primitives, without which L3 self-correction melts down on live cases):**
1. **State deduplication via plan-hash:** the routing function hashes the proposed retry plan. If the hash matches a previously failed attempt in state history, the graph short-circuits to human review instead of re-executing. Prevents the agent from sycophantic-confirming an identical malformed plan.
2. **Pre-retry context-clearing node ("debounce hook"):** a dedicated node before each retry edge that summarizes or selectively clears volatile state keys (error stack traces, prior tool outputs) so the LLM enters the next cycle with a focused prompt instead of its own error backlog. Otherwise context-window fills with prior-failure noise and the model loses focus.
3. **Thread-scoped checkpointing:** LangGraph `thread_id` tied cryptographically to `(case_id, run_uuid)`. Otherwise resumed graphs can inherit state from a different forensic case — cross-case evidence contamination is a fatal forensic-integrity failure.

**Commit rationale:** round-3's 1.5–2-week estimate was generic-velocity padding. At the project's observed Saturday+Sunday pace (15 hours → full Slice 2 + Slice 2.5 + Slice 3 Phase A/B + Phase B last-mile + ATT&CK mapping + Slice 5 runbook), the three primitives re-estimate to **~1 focused day**: plan-hash dedup 1–2 hr, debounce hook 2–3 hr, thread-scoped checkpointer 30–60 min, probes 1–2 hr. Does not force a Q2 / demo / Reference-Dataset cut.

**Where it ships:** Slice 3 Phase C. Folds in alongside the node-wiring close-out and R_06/R_12/R_13.

### Carried item 15 — Fifth MCP tool: Scheduled Tasks XML parser *(COMMITTED 2026-04-20 after velocity-based re-estimate — see Key Decisions row)*

**What:** add a narrowly-focused MCP tool `scheduled_tasks_parse` that extracts + parses XML files from `C:\Windows\System32\Tasks\` via `icat_extract` (pre-existing) followed by a new XML-parser stage. Adds MITRE ATT&CK **T1053.005 (Scheduled Task/Job: Scheduled Task)** to the pipeline's reachable persistence coverage.

**Commit rationale:** re-estimated at observed velocity to ~½–1 day (server function + `xml.etree` parser + PLAN-prompt update + 2–3 ground-truth fixtures on an existing case), not 1 week. T1053.005 is among the three most common Windows persistence techniques alongside T1547.001 Run Keys and T1543.003 Services (both already in scope). Adding it widens TA0003 coverage **without changing the investigation question** — the only scope-expansion type worth doing per round-3 analysis.

**Scope reversal:** this reverses the 2026-04-19 "4-tool scope is deliberate narrowing" decision. See the new Key Decisions row below.

**Where it ships:** Slice 5. The runbook ([slice-5-runbook.md](../runbooks/slice-5-runbook.md)) already integrates the 5th tool — no separate runbook needed.

---

### Round-3 language/emphasis changes (same-day, landed above)

Not carried items — these were language and positioning fixes that went into `vision.md` and this file immediately:

1. **Capability-token messaging reframed** — tokens = application-layer least-privilege routing in our stdio transport, **not** a cryptographic boundary against adversarial-prompt-injection bypass. Dual-channel handler is the adversarial defense. Updated in `vision.md` Slice 5 block + differentiation-axes table. See also the new Key Decisions row below.
2. **Hadi3 promoted from stretch third case → named validation case.** Pitch now mentions it explicitly; success criterion #6 is the negative-case discipline test. The value of the negative case: it's the empirical proof the Critic isn't rubber-stamping LLM positive-finding bias.
3. **Ablation emphasis reordered** — lead with dual-channel (expected dramatic delta), de-emphasize the classification-field validator (may ablate to zero if Sonnet 4.6 faithfully complies with the Pydantic schema anyway, which would turn a heavily-advertised control into a measured no-op). Updated ablation framing in item 6 above.

---

## Next Action

**Slice 2.5 ✅ and Slice 3 Step 0 (Phase A) ✅ both done 2026-04-19.** Post-Step-0 scorecard: **TP=4 / FP=0 / FN=0 / P=1.00 / R=1.00 / Hallucinations=0** across both 2.5 cases. Step 0 = upstream prompt hardening (no agent layer added). Full detail in Current Status above.

**Slice 3 Phase A + Phase B both ✅ done 2026-04-19.** Critic is wired into the LangGraph topology (C4 rebuilt: 6 nodes + conditional edges + corrective_instruction threading on state). All 11 deterministic rules pass on real post-Step-0 findings for both 2.5 cases. All Phase B cells inserted via fail-fast probe (caught a real test-defect bug in Scenario 4's R_11 note + a Pydantic forward-ref bug in PipelineState — both fixed before landing).

**Slice 3 last-mile ✅ done 2026-04-19.** C6 (PLAN) + C9 (INTERPRET) now consume `state.corrective_instruction` / `pipeline_state.corrective_instruction`. The corrective lands as a **second system block** after the cached stable block so Anthropic prompt-caching is preserved on first runs (byte-identical first-run messages; one extra block on retries). Both patches probed in the container venv end-to-end (structural probe + live-exec extraction of patched blocks) before JSON write.

**ATT&CK mapping ✅ done 2026-04-19.** C2 `Finding` schema now carries `attack_id` / `attack_name` / `attack_tactic_id` / `attack_tactic_name`, auto-populated by a Pydantic `model_validator` from the existing `category` field (LLM output for those fields is ignored — category is source of truth). All six persistence categories map 1:1 onto official sub-techniques under **TA0003 (Persistence)**: T1547.001 (Run keys), T1543.003 (Windows Service), T1053.005 (Scheduled Task), T1546.012 (IFEO), T1546.010 (AppInit DLLs), T1037.001 (Logon Script). `NOT_FOUND` serializes `attack_id: null`. No prompt changes, no scope expansion — `findings.json` now speaks ATT&CK without widening agent responsibility. Probed via 6-case unit probe + live-exec of the patched C2 cell.

**What still blocks end-to-end live retry (known gaps, not scope of Phase B):**
- `plan_node` idempotency guard (`if state.tool_plan is not None: skipped`) prevents a re_plan retry from re-firing PLAN. On retry, the guard must be bypassed (e.g., clear `tool_plan` when setting `corrective_instruction`, or gate the skip on `corrective_instruction is None`).
- C9 is still inline at module scope — the graph's `interpret_node` is a stub. For the retry loop to actually trigger C9 from `re_interpret`, C9's body needs to move into `interpret_node` (or be imported in). Same for C6 on `re_plan`.
- These are node-wiring surgeries, not prompt-assembly surgeries; deferring unless the user picks them up. Component-level retry semantics are already validated by C14 scenarios.

**Slice plan reshape 2026-04-19 — collapsed Slice 4 + Slice 6 + L4 narrative into a single merged Slice 6.** The 10–20-case eval harness (old Slice 4) is the same artifact as the Reference Dataset the L4 demo runs against; separating them doubled the ground-truth work without a narrative payoff. Merged slice ships L2-delta measurement + L3 controls + L4 audit loop as one coherent artifact. L4 reframed from "out of scope" to "narrative demonstration" — honest about what longitudinal-calibration telemetry we can't produce in 8 weeks.

**Slice 5 runbook drafted 2026-04-20.** [slice-5-runbook.md](../runbooks/slice-5-runbook.md) ships with round-3 revisions applied in a single pass (capability-token reframe, dual-channel lead, R_06/R_12/R_13 metadata in structured fields, hash-chain stub shape for Slice 6, 5th MCP tool integrated, ablation reordered to lead with dual-channel, tripwires reframed). Ready to execute after Slice 3 Phase C closes out.

**Items 14 + 15 committed 2026-04-20 (velocity re-estimate).** Round-3 critic's 1–2-week estimates were generic-velocity padding. At observed project pace, items 14 + 15 combined are ~1.5 days of focused work, not 3 weeks — doesn't force Q2 / demo / Reference-Dataset cuts. Documented as a reusable Key Decisions row so the same reflex applies to future flagged items.

**Recommended next:**
1. ~~**Slice 3 Phase C**~~ ✅ **closed 2026-04-20.** L3 primitives landed (C-1a/C-2/C-3/C-4); R_12 shipped as minimum-viable pre-Slice-5 rule (`any(exit_code != 0)` proxy); R_13 shipped as SLICE_5_TODO stub (regex-over-stdout evaluated and rejected for FP risk on limited ground-truth); R_06 checklist-coverage enhancement deferred to Slice 5. C6/C8/C9 node-lift bundled with Slice 5 module extraction.
2. **Slice 5** per the drafted runbook: dual-channel handler + capability tokens + 5th MCP tool (`scheduled_tasks_parse`) + **bundled with it: node-lift (C6/C8/C9 → `plan_node`/`execute_node`/`interpret_node`) + module extraction (notebook → `pipeline/*.py`)**. R_06 enhancement + R_13 real body activate here once `expected_paths_covered` / `hive_lastwrite` structured fields land.
3. **Slice 6** merged slice (Reference Dataset + L3 ship + sampled-audit). Biggest remaining slice. Pre-work that should run in parallel (async background): (a) stage additional SRL-2018 E01 downloads per `dataset_manifest.md`; (b) annotate `dmz-ftp` ground truth (third canonical case; we have the E01); (c) NotebookLM ask on sampled-audit framing for non-annotated cases (carried Open Question).

**Parallel cleanup to ride along** (still not blocking): one-line SKILL.md addition referencing `docs/reference/problem-first-lecture-summary.md`; slice-close checkbox template (`[ ] SKILL.md retro` + `[ ] Memory audit`) on existing runbooks.
