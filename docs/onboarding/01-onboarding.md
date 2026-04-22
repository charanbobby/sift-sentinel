# Teammate Onboarding — sift-sentinel

**Last updated:** 2026-04-22
**Audience:** a new teammate joining mid-project. Written with a SOC / detection-engineering / SOAR background in mind — we translate our architecture into vocabulary you already use.
**Target reading time:** 20–30 minutes for this page. Another ~60 minutes for the three linked must-reads at the bottom.

If you're skimming and want a one-liner first: **we're building an autonomous AI agent that does SOC L1 persistence-triage against a Windows dead-disk image, with a deterministic self-correction critic sitting between the LLM's findings and whatever gets committed to the case record.**

---

## 1. What this project is (in your vocabulary)

We're entering the **SANS "Find Evil 2026" hackathon** (submission 2026-06-15), which asks teams to build autonomous AI agents on top of the SIFT Workstation — SANS's DFIR forensic analysis distro. Repo name: **`sift-sentinel`**.

The investigation question our agent answers today:

> *"Given a compromised Windows disk image, autonomously identify the persistence mechanisms the attacker installed."*

Think of it as the **SOC L1 analyst that ingests an E01 disk image instead of a SIEM feed** — and whose L1 triage output is gated by a deterministic rule engine before anything becomes a "finding." Final output is a `findings.json` per case with MITRE ATT&CK mapping (TA0003 Persistence, sub-techniques T1547.001, T1543.003, T1053.005, T1546.012, T1546.010, T1037.001).

### How our components map to the SOC tooling you know

| Our thing | Closest analog in your world | Short description |
|---|---|---|
| **SIFT container** | Your EDR + forensic toolbox in one | Linux sandbox with `tsk`, `RegRipper`, etc. The agent's only hands. |
| **E01 image** | Dead-disk raw evidence (vs. live SIEM log) | Read-only forensic image; our only data source. |
| **MCP server** | The API layer between agent and tools | Typed, schema-validated interface — think SOAR integration module. |
| **LangGraph state machine** | A SOAR playbook | Nodes = playbook actions; edges = conditional routing; retries = your "loopback on partial success." |
| **Critic (13 rules)** | Detection engineering on the agent's own output | Deterministic Sigma-style rules that gate LLM findings before they land. |
| **Capability tokens** | Least-privilege PAM scoping for one session | `(case_id, allowed_tools, allowed_paths, plan_digest, expires_at)`. |
| **Dual-channel handler** | Source-of-truth channel + sanitized analyst view | Raw forensic bytes preserved; LLM sees only structured, de-injection-quarantined fields. |
| **Integrity ledger** | Tamper-evident chain-of-custody log | SHA-256 linear hash chain, each entry refs previous — standard NIST SP 800-86 alignment. |
| **Langfuse traces** | SIEM dashboards for the agent itself | Every LLM call, token, cost, latency. |
| **Autonomy levels (L1→L2→L3)** | Progressive SOAR automation (suggested → approved → exception-based) | L1 = human approves every plan; L3 = only Low-confidence findings pause. |

If you read that table and thought *"this is basically a SOAR playbook with a detection-engineered gate on the agent's output, plus MITRE ATT&CK mapping"* — that's a fair mental model.

---

## 2. What we've actually shipped (honest status, 2026-04-22)

Legend: ✅ shipped • 🟡 in progress • ⬜ defined, not built

| Capability | Status | Where |
|---|---|---|
| Dockerized SIFT + MCP stdio transport | ✅ | [`docker/`](../../docker/) + [`mcp_server/server.py`](../../experiments/slice-2-notebook/mcp_server/server.py) |
| 4 live MCP tools: `fsstat_e01`, `fls_list`, `icat_extract`, `regripper_run` | ✅ | `mcp_server/server.py` |
| End-to-end pipeline: `E01 → EXTRACT → PLAN → [approve] → EXECUTE → INTERPRET → CRITIC → findings.json` | ✅ | [`slice2.ipynb`](../../experiments/slice-2-notebook/slice2.ipynb) C4 (LangGraph topology) |
| **Critic with 11 deterministic rules** (R_01–R_11) + 2 minimum-viable (R_12, R_13 stub) = 13 rule IDs | ✅ 11 / 🟡 2 | `slice2.ipynb` C10, C11 |
| MITRE ATT&CK auto-mapping on every finding | ✅ | `slice2.ipynb` C2 (Pydantic `model_validator`) |
| Mini-eval harness (precision / recall / hallucination count) | ✅ | [`score.py`](../../experiments/slice-2-notebook/score.py) |
| **Validated on 2 DFIR CTF cases: Precision 1.00, Recall 1.00, Hallucinations = 0** | ✅ | `base-wkstn-05` + `dfirmadness-001-desktop` |
| Langfuse tracing (every LLM call) | ✅ | throughout notebook |
| Prompt caching on all Claude calls | ✅ | C5 / C6 / C9 (cached stable block; corrective as secondary system block) |
| L3 primitives: plan-hash dedup, pre-retry debounce, thread-scoped checkpointer | ✅ | `slice2.ipynb` C4 |
| 5th MCP tool `scheduled_tasks_parse` (T1053.005) | ⬜ Slice 5 | |
| **Dual-channel evidence handler** (adversarial-injection defense) | ⬜ Slice 5 | |
| **Capability tokens** enforced server-side | ⬜ Slice 5 | |
| HTTP/SSE MCP transport (drop Docker socket mount) | ⬜ Slice 5 | |
| Integrity ledger + SHA-256 linear hash chain | ⬜ Slice 6 | |
| `verify_chain_of_custody.py` replay tool | ⬜ Slice 6 | |
| Reference Dataset (~5–7 SRL-2018 Windows E01s) + full run | ⬜ Slice 6 | |

**What you can verify for yourself right now:** open [`slice2.ipynb`](../../experiments/slice-2-notebook/slice2.ipynb), look at C4 (the LangGraph topology), C10/C11 (the Critic rules), and `out/runs/<case>/scorecard.json`. That's the live artifact. It's a notebook because we're still in Phase 3 of our [SKILL.md](../../SKILL.md) workflow — the module extraction into `pipeline/*.py` happens as part of Slice 5 (scoped decision, not oversight).

**Scope honesty.** The pipeline is **Windows + NTFS + Registry only** by deliberate choice. Memory forensics (Volatility), network (PCAP), event-log parsing (`.evtx`), non-Windows filesystems, and cloud logs are all **out of scope for submission** and documented as extension points in [vision.md](../planning/vision.md). This is a positioning decision — narrow and deep beats broad and shallow against the ~2000-team field.

---

## 3. The AI components, at a high level

You don't need to become an LLM engineer to contribute. But four concepts carry most of the architecture — if these click, everything else follows.

### 3a. MCP (Model Context Protocol)

An Anthropic-backed open protocol that standardizes the LLM ↔ tools interface. Think of it as **the "generic SOAR connector spec" for LLM agents** — replacing ad-hoc function-calling.

- A **server** exposes typed tools (name + JSON-schema inputs + structured output).
- A **client** (our LangGraph executor) calls them during reasoning.
- Today we use stdio transport (`docker exec`); Slice 5 swaps to HTTP/SSE over an internal Docker bridge for least-privilege reasons (see [PLAN.md "Carried item 16"](../planning/PLAN.md)).

Our MCP server lives at [`mcp_server/server.py`](../../experiments/slice-2-notebook/mcp_server/server.py). Every tool has argv-array exec (no `shell=True`), read-only evidence paths, and — once Slice 5 lands — a capability-token middleware.

### 3b. LangGraph (the pipeline state machine)

A Python library by LangChain for building stateful, graph-shaped agent workflows. You can read it as **"a SOAR playbook engine with first-class conditional loops."**

- **Nodes:** each major stage (`extract`, `plan`, `execute`, `interpret`, `critic`, `re_plan`, `re_interpret`, `human_review`).
- **Edges:** transitions, including conditional edges driven by Critic verdicts.
- **`PipelineState`:** a typed Pydantic object that every node reads/writes — our "shared blackboard."
- **Checkpointer:** persists state per `thread_id`, scoped to `(case_id, run_uuid)` for forensic isolation between cases.

The graph is compiled in [`slice2.ipynb`](../../experiments/slice-2-notebook/slice2.ipynb) C4. LangGraph gives us a free Mermaid/PNG visualization of the running flow — useful for the demo video (Slice 8).

### 3c. The Critic (the detection engineering layer)

The highest-leverage thing in the project and probably the quickest on-ramp for your background.

**What it is:** a pure-Python function that takes the LLM's `findings.json` and runs 13 deterministic rules against it. Any rule failure produces a **structured error** with a **correction template** that gets threaded back into the next LLM attempt as a "corrective instruction" (secondary system-prompt block — cached first block preserved).

**Example rules (abbreviated):**
- **R_05 — Excerpt hallucination:** every `output_excerpt` in the finding must appear verbatim in `tool_calls.jsonl` for this run. If the LLM fabricated a quote, we catch it.
- **R_07 — Tool-category consistency:** a finding classified `attacker_persistence` must cite a tool call whose output-type can evidence persistence. Catches "registry key cited by an `fsstat` call" mismatches.
- **R_10 — Injection flag:** if the dual-channel handler (Slice 5) flagged content, the corresponding finding escalates to human review.
- **R_12 — Evidence-of-absence vs absence-of-evidence:** a `findings: []` result is only accepted if the collection tools actually ran cleanly; a silent tool failure can't masquerade as "no persistence found."
- **R_13 — Temporal consistency:** agent-claimed timestamps must fall within the hive's actual last-modified window (anti-hallucination, per-artifact).

**Why it matters:** this is the submission's **headline engineering claim** — findings pass through a code-level gate, not just a prompt. You'll recognize the shape; it's detection engineering on the agent's output artifact, with retries bounded by a plan-hash dedup loop so we don't infinitely sycophant-retry the same bad plan. Full rule catalog in [architecture-detailed.md §7](../planning/architecture-detailed.md#7-critic-rule-catalog-13-rules-r_01r_13).

### 3d. Prompt caching

An Anthropic feature — mark a stable prefix of the prompt with `cache_control: ephemeral` and subsequent calls hitting the same prefix pay ~10× less for those tokens. We verified 10× on 2026-04-19. We treat it as **on-by-default**; a missing `cache_control` on a Claude call is considered a defect.

Relevant when you touch any LLM call in the notebook — if you add a corrective/dynamic section, it has to come **after** the cached block, not inside it.

---

## 4. The security posture (what's real, what's research-framed)

We are explicit about what our defenses actually defend. This matters a lot for submission positioning — a judge with agentic-threat-modeling fluency will probe it, and we want to be precise, not overclaim.

**Four distinct trust boundaries, each catching a different failure class:**

| Adversary | Defense | Status |
|---|---|---|
| **Prompt injection embedded in evidence** (attacker-authored filenames / registry values / document bodies that read as prompts when tools return them) | **Dual-channel handler** at the MCP boundary — raw bytes to ledger, structured fields to agent, flagged content quarantined and escalated | ⬜ Slice 5 |
| **LLM-internal failure** (sycophancy, hallucinated relationships, silent tool-failure swallowing) | **13-rule Critic + Hadi3 negative-case validation** (Hadi3 = published no-persistence scenario, empirical proof the Critic isn't rubber-stamping positive-finding bias) | ✅ 11 rules + stubs |
| **Accidental agent drift** (proposes a tool or path outside scope) | **Capability tokens** at the MCP boundary (application-layer least-privilege routing) | ⬜ Slice 5 |
| **Post-hoc tampering of recorded evidence** | **SHA-256 linear hash chain** (NIST SP 800-86 alignment) | ⬜ Slice 6 |

**Explicitly out of scope:** local root compromise · supply-chain attacks · network-layer attackers · courtroom admissibility. We describe our mechanisms as **"replayable auditability for a research workflow,"** **not** as proxies for legal admissibility (Protocol SIFT itself is flagged by SANS as experimental; we preserve that distinction).

**The honest stdio caveat (valid until Slice 5 closes).** Right now the notebook container mounts `/var/run/docker.sock` — a hijacked agent could bypass MCP entirely via `docker exec`. This is theoretical under our stated threat model (the LLM returns MCP JSON-RPC, not Python), but it's a visible crack. Slice 5's HTTP-transport swap removes the socket mount and makes capability tokens load-bearing rather than advisory. Full reasoning: [PLAN.md "Carried item 16"](../planning/PLAN.md).

---

## 5. Where your expertise plugs in (concrete asks, not generic "let us know")

Your threat-detection / detection-engineering background has four natural landing zones. These are ordered by **highest-leverage per hour** for our submission:

### 5a. Critic rule review (Slice 3 → Slice 5 bridge)

Read [architecture-detailed.md §7](../planning/architecture-detailed.md#7-critic-rule-catalog-13-rules-r_01r_13) (the 13-rule catalog) and tell us what's missing from a SOC-analyst-reviewing-a-triage-output perspective. Candidate angles:

- Any persistence patterns we're not gating for that you've seen get missed/over-called in UEBA or SIEM detections?
- The "responder-tool cohabitation" FP pattern we hit pre-Step-0 (F-Response, Mnemosyne both looked like attacker persistence to the agent) — does your insider-threat work suggest other categories of legitimate-tool false positives we should pre-harden against?
- R_13 Temporal Consistency is currently a stub; happy to hear how you'd bound the "acceptable skew" window for hive LastWrite vs. claimed persistence-install time.

### 5b. Ground truth for the Reference Dataset (Slice 6)

We have full ground truth on 2 cases, need to annotate **3 more** for the L3 regression baseline (from SRL-2018: `base-dc`, `base-file`, `base-rd-01/02`, `base-wkstn-01`, `dmz-ftp`). This is an obvious fit for your persistence-mechanism knowledge — you'd be pairing with the DFIR Madness answer-key style ([example](../runbooks/slice-2.5-ground-truth-dfirmadness.md)). Velocity is ~2–4 hours per case once the pipeline runs against it.

### 5c. Negative-case stress test (Hadi3)

**Hadi3 = a published no-persistence scenario.** Success criterion #6 is: the pipeline returns `findings: []`, zero hallucinations, any sycophantic over-classification gets caught and retracted. The empirical proof that the Critic isn't rubber-stamping LLM positive-finding bias.

We haven't run it yet. The question we need answered before the submission demo: *does the Critic hold?* If not, **which rule** let the FP through and how do we close it? This is a perfectly scoped adversarial-review task for a detection-engineering mindset.

### 5d. Autonomy-metrics scorecard (Slice 6)

We're extending `score.py` beyond precision/recall to measure the behaviors the judging rubric actually probes (see [PLAN.md Carried item 5](../planning/PLAN.md)):

- Self-correction recovery rate (fraction of Critic retries that end in a correct finding)
- Human intervention rate
- Injection-defense efficacy (TP/FP/FN on seeded adversarial strings)
- Capability-bypass test results
- Run-to-run stability across repeat runs

If you've instrumented SOAR playbook effectiveness before, the design here should feel familiar. Scorecard schema TBD; bias to `scorecard_v2.json` extension, not a rewrite.

---

## 6. Reading order — minimum viable to be effective

**Day 1 (must read):**

1. [`docs/planning/vision.md`](../planning/vision.md) — one page, the submission pitch + differentiation axes + what we will NOT do. If a decision can't be justified against this page, revisit the decision.
2. [`docs/planning/architecture.md`](../planning/architecture.md) — judge-facing architecture reference. Mermaid of the pipeline, trust boundaries, autonomy-climb mapping.
3. **This file**, in full.

**Day 2 (should read):**

4. [`02-walkthrough.md`](02-walkthrough.md) — one concrete pipeline run (DFIR Madness Case 001) end-to-end, stage-by-stage, with linked artifacts. The fastest way to see what "a run" actually produces — read this before the notebook.
5. [`experiments/slice-2-notebook/slice2.ipynb`](../../experiments/slice-2-notebook/slice2.ipynb) cells C1–C11 — the actual pipeline. Skim C2 (schemas), C4 (LangGraph graph), C6 (PLAN), C8 (EXECUTE/MCP), C10 (Critic). Don't try to run it yet.
6. [`docs/planning/architecture-detailed.md`](../planning/architecture-detailed.md) — the 13-rule catalog, data-flow walkthrough, stdio caveat prose.
7. [`docs/runbooks/slice-5-runbook.md`](../runbooks/slice-5-runbook.md) — the next major build (dual-channel + capability tokens + 5th MCP tool + HTTP transport).

**Skip unless curious:**

- `docs/planning/PLAN.md` — 300+ lines of slice-by-slice decision log. Useful when you want *why* a specific decision went the way it did. Not useful as an entry point.
- `docs/learning/*` — forensic-domain primers mostly written for the *other* teammate (who is new to forensics). You won't need these.
- `training/blue-cape-dfir-foundations/*` — same story; background DFIR coursework notes.

---

## 7. Environment setup (the minimum to run anything locally)

**Prerequisites on your machine:** Docker Desktop (Hyper-V / WSL2 backend on Windows, or native on macOS/Linux), ~40 GB free disk, Python 3.11+ (only if you want to run the notebook outside the container — usually you don't).

**To bring the pipeline up:**

1. `git clone` the repo.
2. Follow [`docs/runbooks/slice-1-docker-runbook.md`](../runbooks/slice-1-docker-runbook.md) — Slice 1 bootstrap. This pulls `digitalsleuth/sift-docker:jammy`, builds our patched image (includes an upstream Perl bug fix in `rip.pl` line 75), and wires the bind mount to evidence on a host path.
3. Evidence: we have three cases staged. For first-run sanity you want `base-wkstn-05` (smallest workstation case, fully annotated). The file layout is documented at the top of the Slice 1 runbook.
4. Open `experiments/slice-2-notebook/slice2.ipynb` in VS Code with the Jupyter extension (or JupyterLab inside the container). Run cells top-to-bottom.
5. For a live LLM call you'll need an **Anthropic API key** + an **OpenRouter API key** (we use OpenRouter for Gemini and as a fallback). Drop them in `experiments/slice-2-notebook/.env`. Ask Charan if you need access to the team's shared keys.

**Do NOT** run `uv` from your Windows host against `slice-2-notebook/.venv` — that venv is built inside the Linux container and host-side `uv run` will corrupt it. Always drop into the container first (`docker exec -it sift bash`) and run `uv` there.

**Fail-fast is a project rule.** Before adding any new API call / env var / SDK pattern to the notebook, probe it in isolation first (`d:/tmp/probe_*.py` or a 3-line docker exec). Details in [`SKILL.md` Phase 3](../../SKILL.md#phase-3-notebook-prototype) and the project-root `CLAUDE.md`. Three prior incidents taught us this isn't optional.

---

## 8. Team conventions to know

- **Runbooks, not chat instructions.** Multi-step procedures live in committed `.md` files with checkboxes under `docs/runbooks/`. Chat/Slack is ephemeral.
- **Notebook-first.** We build pipeline logic inline in Jupyter cells first, extract to `pipeline/*.py` only after the cell works. The notebook is the current code home; Slice 5 does the module extraction as a bundled refactor.
- **Honest scope.** Out-of-scope items are documented as "extension points," not left as implicit gaps. If you hit something genuinely out of scope, that's the framing.
- **Prompt caching is a default.** If you touch a Claude call, `cache_control: ephemeral` on the stable block isn't optional.
- **External critiques welcome, tracked.** We've done three rounds of external LLM critique (see [PLAN.md "External Critique Intake"](../planning/PLAN.md)). Feedback lands as numbered "carried items" with explicit commit/defer decisions.

---

## 9. Quick glossary

| Term | Meaning |
|---|---|
| **E01** | EnCase Expert Witness Format — a forensic disk image format. Read-only, hashed. |
| **SIFT** | SANS Investigative Forensic Toolkit — the Linux distro our container is built from. |
| **MCP** | Model Context Protocol — Anthropic-backed open spec for LLM-to-tool integration. |
| **Critic** | Our 13-rule deterministic gate on LLM findings. |
| **Slice** | A demoable increment (Slice 1 = bootstrap; Slice 6 = submission target). See [PLAN.md](../planning/PLAN.md). |
| **L1 / L2 / L3** | Autonomy levels: Assisted / Guarded / Exception-based. Shipped / shipped / submission target. |
| **TA0003** | MITRE ATT&CK Tactic ID for Persistence. |
| **Hadi3** | A public no-persistence DFIR scenario we use as a negative-case stress test. |
| **PipelineState** | The typed Pydantic blackboard every LangGraph node reads/writes. |
| **Langfuse** | Our LLM observability platform — every call, token, cost, span. |
| **OpenRouter** | Our LLM gateway — single API for Claude / Gemini / others, with prompt caching. |

---

## 10. Open questions where your input would genuinely help

These are live; not-yet-decided. No pressure to answer on day 1 — flag whichever you have a strong prior on.

- **Sampled-audit framing for non-annotated cases (Slice 6).** With ground truth on only 3 of ~7 Reference Dataset cases, how do we judge findings on the rest? Options: (a) hand-annotate only the N findings the pipeline surfaces (cheaper than full ground truth); (b) accept "plausibility-review" framing and state the recall-blind-spot explicitly. We're leaning (a); does a security-auditor background change the calculus?
- **Evidence-dispatch at L3.** Once the human stops picking which E01 to feed (L3+), how does the agent pick the next case? Iterate manifest in order? Score-and-rank by "likely initial access vector" heuristic? Run all N in parallel? Open.
- **Critic retry-budget calibration.** Currently 3 attempts before escalating to human review. Does your SOAR experience suggest this is right, too tight, or too loose for a forensic-integrity-sensitive domain?

---

**Welcome aboard.** Start with [vision.md](../planning/vision.md) and [architecture.md](../planning/architecture.md), then poke around the notebook. Questions / gaps in this onboarding doc — flag them; this file should be the first thing we fix when a new teammate trips on something.
