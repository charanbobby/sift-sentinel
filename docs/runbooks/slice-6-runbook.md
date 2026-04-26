# Slice 6 Runbook — Bounded Reference Dataset + L3 Ship + Accuracy Report

**Goal:** Ship the submission. Three named deliverables per [`PLAN.md`](../planning/PLAN.md) row 6:

1. **Bounded Reference Dataset** — stage Windows/NTFS E01s under `HACKATHON-2026/`, but only make scored claims on fully ground-truthed cases. Target 3 full-GT cases for the L2→L3 regression baseline.
2. **L3 controls** — H/M/L confidence rubric with auto-escalation of Low; per-excerpt sha256 provenance linked to `plan_digest`; Critic-disagreement log; token/latency/tool-call audit trail; **append-only integrity ledger** stored separately from case folders (NIST: hashes in the same mutable folder look like self-attestation).
3. **Accuracy Report** — named submission deliverable per `docs/reference/hackathon/rules.md` §4 #5. Lives at `docs/submission/accuracy-report.md`. Assembles scorecard_v2 + ablation data + per-case FP/FN inventory + hallucinated-claim log with Critic catches + evidence-integrity results.

**Why this shape (submission framing):** Slice 5 made the evidence-to-LLM boundary structurally defensible. Slice 6 demonstrates that boundary on multiple real cases and produces an auditable record. L3 "Exception-Based Autonomy" is the autonomy dial we ship. A sampled review of non-GT cases is optional supporting evidence, not a milestone and not a claim of deployment-ready autonomous auditing.

**Submission deadline:** 2026-06-15 (~7 weeks from Slice 5 close on 2026-04-23).

**Pre-gate:** Slice 5 closed. All 111 pytest cases green. 2.5 baselines P=1.00 R=1.00. Dual-channel + capability tokens + INJECTION_QUARANTINE wiring all shipped.

**Canonical record:** tick boxes as you go. Update [PLAN.md](../planning/PLAN.md) Slice 6 status on completion. Keep scope discipline: four deliverables, nothing else. Defer anything that doesn't advance one of the four.

---

## Acceptance Gates (submission tripwires)

| Gate | Bar | If failed |
|---|---|---|
| Reference Dataset staged | ≥5 additional E01s preprocessed + in `/mnt/derived` ready for pipeline | Cut dataset to what's ready; document unstaged as extension point |
| Full GT on 3 cases | Ground-truth markdown + `ground_truth.json` per case | Cut to 2 if a case is ambiguous; annotate reason |
| Pipeline runs clean across all staged cases | Zero crashes, no `capability_denied` unless seeded | Investigate root cause before audit; do not paper over with retries |
| L3 confidence rubric + auto-escalation wired | Low-confidence findings route to `human_review` | Halt L3 claim; document L2.5 ship instead |
| Append-only integrity ledger writes + verifies | `verify_chain_of_custody.py` replay green | Ship stub; document hash-chain as Slice 6.5 scope |
| 4-row ablation rows 2–4 run | scorecard_v2 for each config | Cut to rows 1+3 only (baseline + full Slice 5); mark rows 2+4 deferred |
| Accuracy Report assembled | `docs/submission/accuracy-report.md` complete | Submission blocker — must ship regardless of other scope cuts |

---

## Step 0 — Scope alignment ✅ 2026-04-23

Cost calibration run measured — INTERPRET cost per call is **~$0.09** (21,998 input tok / 1,730 output tok on Sonnet 4.6 against the real `out/evidence.jsonl` from Step 7c). Full-pipeline run ≈ **$0.15 typical, $0.25 worst-case with Critic retry**. That's ~30× lower than the pre-Step-7 incident. Whole-Slice-6 budget revised to **~$5–8**, not the $40–60 I first quoted off the stale figure. Dollar constraint on ablation scope is effectively gone.

**Decisions locked:**

- [x] **Third GT-annotated case**: `base-dc` (Windows domain controller) — gives the most different persistence profile from the two already-annotated workstations, exercises hive paths that wkstn-05 doesn't hit (NETLOGON, AD-related artifacts)
- [x] **Integrity-ledger scope**: linear hash-chain real impl (Slice 6 Step 4). At ~$5 for the whole slice the dollar pressure that would have pushed to a stub is gone; submission narrative is stronger with a real ledger + `verify_chain_of_custody.py` replay tool
- [x] **Ablation scope**: run all 4 rows on **all staged cases**. Rows 2+4 on all 7 cases ≈ $2.80; not worth cutting for pennies. Accuracy Report gets a full 4-row × 7-case matrix + the adversarial demo quarantine% column
- [x] **Optional sampled-review rate**: 3 findings per non-GT case (all findings if the case produced ≤3) + 2 random evidence records per case. Use only as Accuracy Report appendix evidence, not scored recall.
- [x] **Integrity-ledger storage location**: `/var/lib/find-evil/ledger.jsonl` on `sift-sentinel` via a new named Docker volume — survives container restart, lives outside case folders per NIST, not mounted into `sift-mcp` (write-only from the orchestrator)

All five decisions carried into [PLAN.md](../planning/PLAN.md) Key Decisions table.

---

## Step 1 — Preprocess staged E01s to raw NTFS partitions

**Driver:** [`experiments/slice-2-notebook/preprocess_e01.py`](../../experiments/slice-2-notebook/preprocess_e01.py) — per case: `ewfmount` → `mmls` (pick largest NTFS) → `dd` extract → `fsstat` verify → sha256. Parser unit-tested 2026-04-23 against dual-NTFS, single-NTFS, and GPT-no-NTFS mmls samples.

Needs a **privileged sift container** (FUSE required for `ewfmount`); the persistent `sift-mcp` container is non-privileged by design. Spin an ad-hoc one per session:

```bash
docker run --rm -it --privileged --device /dev/fuse \
  -v "D:/Python Applications/Find Evil - Hackathon/HACKATHON-2026:/mnt/hackathon:ro" \
  -v "D:/Python Applications/Find Evil - Hackathon/HACKATHON-2026/derived:/mnt/derived:rw" \
  -v "D:/Python Applications/Find Evil - Hackathon/experiments/slice-2-notebook:/work:ro" \
  find-evil/sift:slice5 bash
# inside:
python3 /work/preprocess_e01.py --case base-dc
python3 /work/preprocess_e01.py --case base-file
python3 /work/preprocess_e01.py --case base-rd-02
python3 /work/preprocess_e01.py --case dmz-ftp
```

Each pass writes `/mnt/derived/<case>.ntfs.dd` + prints size + sha256 (captured now for Step-4 ledger seeding). ~5–15 min wall-clock per case.

Already preprocessed + Slice-2.5 baseline (2 cases): `base-wkstn-05`, `dfirmadness-001-desktop`.

To preprocess (4 cases — E01s already staged on D: drive):

- [x] `base-dc` — Windows domain controller (12 GB E01) → `derived/base-dc.ntfs.dd` 36.11 GB sha256 `58973a4dcf74c3001dc3a769e88cd81609a94b5c529d6ac44e188e7a335f8410` ✅ 2026-04-23
- [x] `base-file` — Windows file server (16 GB E01) → `derived/base-file.ntfs.dd` 31.69 GB sha256 `5f5cba969a29ee4ab5c3caf5a9967ef5b38de6a532b18832d121e308128cb0bc` ✅ 2026-04-23
- [x] `base-rd-02` — Remote desktop server (17 GB E01) → `derived/base-rd-02.ntfs.dd` ✅ 2026-04-23
- [ ] `dmz-ftp` — DMZ FTP server (12 GB E01) — queued

Not downloaded (not blocking — 6 cases satisfies the ≥5 gate): `base-rd-01`, `base-wkstn-01`.

### 1a — Dataset manifest update

- [ ] Update [`docs/reference/hackathon/dataset_manifest.md`](../reference/hackathon/dataset_manifest.md) with status rows for each staged case: `[staged / preprocessed / pipeline-runs-clean / GT-annotated / optional-review-done]`
- [ ] Record each `.ntfs.dd` sha256 (captured at preprocess time) as baseline identity for Step-4 ledger genesis
- [ ] Persistence-profile notes per case: expected Windows roles → expected persistence mechanisms to watch for

---

## Step 2 — Full ground-truth annotation on the 3 target cases

Two cases already have GT (`base-wkstn-05`, `dfirmadness-001-desktop`). Third is a Step-0 decision.

For the new third case (`base-dc`):
- [x] Run the pipeline under the current Slice 5 + Tier-1 wiring → produces `findings.json` + `evidence.jsonl` ✅ 2026-04-24
- [x] Manually audit every finding: TP / FP / UNCLEAR ✅ 2026-04-24
- [x] Manually check for FN by scanning the full evidence for persistence mechanisms the agent missed ✅ 2026-04-24
- [x] Author `ground_truth.md` (narrative) + `ground_truth.json` (machine-readable verdicts) ✅ 2026-04-24
- [x] Record in the case's `out/runs/srl-2018-base-dc/` ✅ 2026-04-24

**Result:** TP=0, FP=0, FN=0. Negative-control case — no attacker persistence. F-Response Subject + Mnemosyne correctly classified as `legitimate_responder_tool` and excluded. Critic R_12 escalated correctly (Winlogon parse_error gap); human reviewer confirms absence claim is correct.

**Why the bar is "3 full-GT cases, not all ~7":** ground-truth annotation is expensive (hours per case) and only needed for the L2→L3 regression claim. Other staged cases can get cheaper sampled review, but they must be labeled recall-limited.

---

## Step 3 — L3 confidence rubric + auto-escalation ✅ 2026-04-24

Today's system uses the Critic's severity (pass/retry/escalate). Slice 6 adds an explicit **finding-level** confidence rubric independent of the rule-failure path.

- [x] Defined H/M/L rubric as `CONFIDENCE_RUBRIC` dict in `pipeline/schemas.py` — deterministic criteria aligned with R_06/R_08/R_12 (for high) and R_15 (for low)
- [x] Wired into `pipeline/critic.py`: any `Low`-confidence finding auto-escalates to `human_review` via **R_15** (LOW_CONFIDENCE_AUTO_ESCALATE in ESCALATE_CODES, no retry template)
- [x] **R_15** added (R_14 still reserved for citation-gate activation). Fires on any finding at `confidence=low`, including NOT_FOUND@low. Registry now has 14 active rules.
- [x] `INTERPRET_SYSTEM_PROMPT` section 5 rewritten to render the rubric verbatim and reference the enforcing rules so the LLM calibrates its confidence labels correctly
- [x] 6 new pytest cases (bad-low-positive, bad-NOT_FOUND@low, good-medium, good-high, orchestrator→escalate, rubric shape)
- [x] Regression baseline: **193/193** green (up from 187)

**Committed as `96897f1` (2026-04-24).**

### 3a — Per-excerpt sha256 provenance ✅ 2026-04-24

- [x] `Evidence.excerpt_sha256` field landed in `pipeline/schemas.py` — Pydantic validator auto-fills from `output_excerpt` after adversarial-control stripping; caller-supplied hashes are tamper-verified at construction
- [x] Mismatch between stored hash and recomputed hash raises `ValidationError` on reload — the tampering tripwire for `findings.json`
- [x] Legacy findings.json without the field reload cleanly (default="" → post-validator fills it)
- [x] 8 pytest cases added (helper, autofill, matching accepted, tampering rejected, JSON round-trip, legacy reload, empty excerpt, post-strip bytes)
- [x] Deep binding to `raw_sha256` across records is **Step 4's** integrity-ledger job; this field is the minimum-viable primitive that Step 4 will hash-chain

**Committed as `a6c2078` (2026-04-24).** Full suite green: **201/201**.

---

## Step 3b — AI-assisted attacker detection (awareness layer) ⬅ added 2026-04-24

**Why this step exists:** Q1 2026 threat reports (CrowdStrike GTR 2026, Mandiant M-Trends 2026, Google GTIG) confirm multiple in-the-wild malware samples that **call LLM APIs from compromised hosts** (PROMPTFLUX → Gemini, PromptSteal/LameHug → Hugging Face, QuietVault → on-host AI CLI, PromptLock → LLM-generated Lua). This is no longer a future-threat projection — it's a present-day TTP. Full threat-landscape evidence review at [`docs/research/ai-assisted-threat-landscape-2026.md`](../research/ai-assisted-threat-landscape-2026.md).

**Scope discipline:** *awareness layer, not a schema rebuild.* Core PersistenceCategory values stay. A Run key is still a Run key. What changes is that the agent **specifically recognizes** when persistence calls out to an LLM / imports an AI SDK / carries prompt-like strings, and flags it as AI-assisted. Avoiding the high-FPR trap of stylometric "was this AI-written?" classifiers — we anchor on concrete artifacts (URLs, imports, keys), not writing style.

### 3b.1 — INTERPRET prompt update

- [ ] Add a new sub-section to `INTERPRET_SYSTEM_PROMPT` (in `pipeline/nodes.py`) documenting AI-attacker signals to look for:
  - LLM API URLs in persistence artifacts: `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `api-inference.huggingface.co`
  - AI-SDK imports in scheduled tasks / services / Run-key payloads: `openai`, `anthropic`, `langchain`, `langgraph`, `google.generativeai`, `transformers`, `huggingface_hub`
  - Env-var references: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `HUGGINGFACE_HUB_TOKEN`
  - Config-folder paths: `%USERPROFILE%\.openai\`, `%USERPROFILE%\.anthropic\`
  - Prompt-like strings embedded in payloads (imperative English, "You are a helpful assistant..." preambles)
- [ ] Prompt instruction: when any of these signals are present on persistence, set `classification = "attacker_persistence_ai_assisted"` and cite the specific signal in `notes` with inline `[ev:<id>]` citation

### 3b.2 — Schema change: new Classification value

- [ ] Add `attacker_persistence_ai_assisted` to the `Classification` literal in `pipeline/schemas.py`
- [ ] Treated as a flavor of `attacker_persistence` by R_08 / R_11 (same primary-tool-evidence and rule-out requirements apply)
- [ ] Update `test_classification_literal` in `tests/test_schemas.py`

### 3b.3 — New Critic rule: R_16 AI-assisted evidence anchor

- [ ] Fires when `classification == "attacker_persistence_ai_assisted"` but the cited evidence does NOT contain at least one of the concrete anchors (LLM URL substring, SDK import name, known API-key env var)
- [ ] Prevents the model from crying wolf on stylistic guesses — the classification must be grounded in a recoverable artifact
- [ ] FailureCode: `AI_ASSIST_ANCHOR_MISSING` — routes to `re_interpret` (model must either find the anchor or downgrade to `attacker_persistence`)
- [ ] pytest: bad case (classified as AI-assisted with no anchor in excerpts) → fires; good case (classified with `openai` import visible in excerpts) → passes

### 3b.4 — Demo staging

- [ ] Add **one PROMPTFLUX-style persistence artifact** to the staged adversary-AI E01: scheduled task running a Python script that imports `openai` and calls `api.openai.com` with a hard-coded key
- [ ] Ground-truth: agent must classify the finding as `attacker_persistence_ai_assisted` and cite the LLM URL in the evidence excerpt
- [ ] This is the "here's what 2026 actually looks like" demo beat for the judges

### 3b.5 — Accuracy Report framing

- [ ] Include a named section in the Accuracy Report: *"Detecting AI-Assisted Persistence — 2026 Threat Landscape"*
- [ ] Cite the 4-5 confirmed in-the-wild samples (PROMPTFLUX, PromptSteal/LameHug, QuietVault, PromptLock, Slopoly)
- [ ] Explicit about the FPR problem: legitimate Copilot/Cursor users on dev machines will trigger surface-level AI-SDK import signals. Our pipeline mitigates this by anchoring on LLM-endpoint URLs + prompt-like strings (which devs don't typically embed in scheduled tasks) rather than stylometry alone
- [ ] Acknowledge: the `machine_role` context (developer vs non-developer) is hard-coded per case for the hackathon; post-hack it would be inferred from AD / OU / hostname

### 3b.6 — Memory-evidence path (added 2026-04-25)

AI-assisted attackers manifest more sharply at runtime in memory than as dormant disk artifacts. PROMPTFLUX's live LLM-API connection, PromptSteal's loaded `transformers` import, QuietVault's command-line invocation are all visible in process state, not on disk. Disk-only AI-assisted detection is the weaker version of the differentiation pitch; memory makes it the stronger version. See [PLAN.md Key Decisions row "Memory analysis folded into Slice 6 Step 3b"](../planning/PLAN.md#L130) for full rationale.

**Tooling: Volatility 2.6.1 (already installed in `sift-mcp`).** No install work required. Coverage envelope: Windows XP through Windows 10 + Server 2008 R2 / Server 2012, which contains all SRL-2018 hosts. Win11 + Server 2022 (e.g., OpenUni22 memory) require Volatility 3 and stay deferred.

**One-time evidence-staging step (operational finding 2026-04-25):** raw memory dumps on the host `D:` bind mount serve the SIFT container at ~1.5 MB/s sustained, making direct vol.py runs unusably slow. Each dump is staged once into a fast container-local volume before pipeline runs. This mirrors the existing `E01 → .ntfs.dd` preprocessing pattern.

#### 3b.6.1 — `volatility_run` MCP tool

- [ ] Add `@mcp.tool()` `volatility_run(capability_token, plan_digest, case_id, image_path, profile, plugin)` in [`mcp_server/server.py`](../../experiments/slice-2-notebook/mcp_server/server.py); pattern-match against `regripper_run`
- [ ] Plugin allowlist: `{pslist, cmdline, netscan, dlllist, malfind}` only. Anything else raises before subprocess
- [ ] Profile parameter accepted as input (do not auto-detect with `imageinfo`; ~15 min wall clock per dump). Per-host profile mapping documented in case manifest
- [ ] Path allowlist: image_path must live under `/var/lib/find-evil/memory/` (named volume) or the case's `analysis/extracted/` directory
- [ ] Subprocess: `vol.py -f <image> --profile=<profile> <plugin>`; same `_run_subprocess` helper as existing tools; same 64 KB stdout cap
- [ ] Capability-token enforcement same as other tools

#### 3b.6.2 — Memory-evidence schemas

- [ ] Add `VolatilityProcessEntry`, `VolatilityNetworkEntry`, `VolatilityMalfindEntry`, `VolatilityDllEntry` to [`pipeline/schemas.py`](../../experiments/slice-2-notebook/pipeline/schemas.py)
- [ ] Add `VolatilityResult` (discriminated union by `plugin_name`)
- [ ] Add new `Classification` literals: `process_injection`, `c2_beacon`, `attacker_persistence_ai_assisted_runtime`
- [ ] Add `evidence_type: Literal["disk", "memory"]` field on `EvidenceRecord` if not already present; default `"disk"` for existing records
- [ ] Update `__all__` exports
- [ ] Apply existing `strip_adversarial_controls` validator + `Field(max_length=N)` bounds to all string fields (Tier-1 polish #3 carries forward)

#### 3b.6.3 — PLAN prompt: memory-evidence dispatch

- [ ] Edit `PLAN_SYSTEM_PROMPT` in [`pipeline/nodes.py`](../../experiments/slice-2-notebook/pipeline/nodes.py): advertise `volatility_run` alongside the existing 5 disk tools; document the 5-plugin allowlist + profile-required parameter
- [ ] Add memory-pivot guidance: "if `evidence_type=memory`, plan a sweep of `pslist` → `cmdline` → `netscan` → `dlllist` → `malfind` against the staged image; do not chain icat/regripper for memory inputs"
- [ ] Structural invariant addition: every `volatility_run` step requires a `profile` value present in the case manifest

#### 3b.6.4 — INTERPRET prompt: memory taxonomy + AI-assisted runtime anchors

- [ ] Edit `INTERPRET_SYSTEM_PROMPT` in [`pipeline/nodes.py`](../../experiments/slice-2-notebook/pipeline/nodes.py): add "Memory-evidence semantics" section with the new Classification values
- [ ] Add memory-specific AI-assisted anchors (extends 3b.1 disk-side anchor list):
  - LLM-endpoint connections in `netscan` rows: any TCP destination matching `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `api-inference.huggingface.co`, `api.cohere.ai`
  - AI-SDK module names in `cmdline` (Python `-m openai`, `python ... import anthropic`, `from langchain ...`)
  - API-key env-var references in process command-line (`OPENAI_API_KEY=`, `ANTHROPIC_API_KEY=`)
  - Inference-process pairings (`python.exe` parent of network connection to LLM endpoint)
- [ ] Hard rule: classify as `attacker_persistence_ai_assisted_runtime` only when a memory anchor is recoverable in cited evidence excerpts; otherwise downgrade to nearest non-AI classification

#### 3b.6.5 — R_16 verification on memory artifacts

- [ ] Confirm R_16 anchor logic in [`pipeline/critic.py`](../../experiments/slice-2-notebook/pipeline/critic.py) treats memory anchors (LLM URLs in `netscan`, SDK imports in `cmdline`) as valid anchors
- [ ] Only add a memory-specific Critic rule if probing reveals an FP / FN class R_16 misses; default is "no new rule"

#### 3b.6.6 — Demo + ground truth on `base-wkstn-05` memory

- [ ] Stage `base-wkstn-05-memory.img` to `/var/lib/find-evil/memory/` (named volume). Document profile in case manifest
- [ ] Run end-to-end dual-evidence pipeline: disk + memory inputs, single PLAN, single INTERPRET
- [ ] Annotate memory findings into `ground_truth.json` for `srl-2018-wkstn-05` (extend existing record); per-finding verdict markdown updates `slice-2.5-ground-truth.md`
- [ ] Acceptance: pipeline classifies any memory-resident persistence cleanly; no regression on the existing 3 disk-only GT-annotated cases (wkstn-05, dfirmadness, base-dc)

#### 3b.6.7 — pytest coverage

- [ ] `tests/test_volatility_tool.py` — argv construction, plugin-allowlist enforcement, profile required, capability-token denial paths, parser per plugin
- [ ] Extend `tests/test_schemas.py` — new Classification literals, VolatilityResult validation, evidence_type field defaults
- [ ] Extend `tests/test_critic.py` — R_16 fires on memory finding without anchor; passes on memory finding with anchor

**Acceptance:** pipeline runs clean on the demo case with the AI-assisted artifact AND on `base-wkstn-05` dual-evidence; agent correctly classifies disk + memory findings; Critic R_16 passes on both classes; no regression on the existing 3 GT-annotated cases (wkstn-05, dfirmadness, base-dc); full pytest suite green.

**Scope tradeoff acknowledged:** combined disk-side AI-assisted (3b.1-3b.5) + memory-evidence path (3b.6) is ~5 working days inside the 7-week submission runway. Cost calibration: Volatility 2 already installed (no install work), raw `.img` already extracted (no decompression tax), MCP tool wrapper pattern-matches `regripper_run` (no architectural new work), schema/prompt edits are line edits not redesigns. **Hard fail-fast cutoff:** if Vol2 cannot bind a profile to the first staged dump after I/O staging, fall back to disk-only AI-assisted (3b.1-3b.5 only) and document memory as Slice 6.5 / extension.

---

## Step 4 — Append-only integrity ledger (linear hash-chain)

Per carried item 9 in PLAN.md: **linear hash-chained** ledger, not plain append-only.

- [ ] Ledger schema: each entry has `(sequence_no, prev_entry_sha256, entry_payload, entry_sha256)` — tampering with any entry breaks the chain
- [ ] Entry payload: `{event_type, timestamp, case_id, plan_digest, tool_call_id?, finding_index?, critic_rule?, ...}`
- [ ] Events to record: plan approval, each tool call + result sha256, finding commit, critic disagreement, human_review decision, session close
- [ ] Storage: **separate from case folders** (NIST — hashes in the same mutable folder look like self-attestation). Candidate path: `/var/lib/find-evil/ledger.jsonl` or similar
- [ ] `verify_chain_of_custody.py` — replay tool that validates the full chain from genesis to current
- [ ] Fail-fast probe: tamper with one entry → verifier detects the break
- [ ] pytest: `tests/test_ledger.py` — write chain, tamper, verify detects

---

## Step 5 — Pipeline runs across all staged cases

- [ ] Run the full Slice 5 pipeline against each of the ~7 staged cases
- [ ] For each: capture `findings.json`, `scorecard.json`, `scorecard_v2.json`, `evidence.jsonl`, `critic_disagreements.jsonl`
- [ ] Record per-case: total LLM cost, wall-clock, token usage, tool-call count (for the Accuracy Report)
- [ ] Any case that crashes → investigate root cause; do not paper over

**Cost envelope (measured 2026-04-23):** full pipeline run ≈ **$0.15 typical / $0.25 worst-case with retry** (INTERPRET $0.09 + PLAN $0.05 + EXTRACT Gemini-flash-lite ~$0.001). For 7 cases: **~$1.40** baseline run. Ablation rows 2+4 on all 7 cases: **~$2.80**. Contingency: ~$2. **Whole-Slice-6 LLM budget: ~$5–8.** (Pre-Step-7 incident cost was $2.70/run — we're 30× down, not 10×, because the bundle trim also killed retry-loop triggers.)

---

## Step 6 — Optional sampled-review protocol ✅ 2026-04-26

For the 3 Slice-5 cases without full GT (`srl-2018-base-file`, `srl-2018-base-rd-02`, `srl-2018-dmz-ftp`) — applied lightweight post-hoc reviewer audit.

- [x] Sampling rate (Step 0 decision): all findings per case (each had ≤3) + 2 random evidence records (Python `random.seed(20260426)`)
- [x] Audit template: reviewer marks each sampled finding as "plausible / suspicious / known wrong", verifies cited tool_call_id resolves in `04_execute_evidence.jsonl`, spot-checks excerpts against structured fields
- [x] Per-case optional-review report: `out/runs/<case>/sampled_review.md` for each of the 3 cases
- [x] Aggregate optional-review notes: [docs/submission/sampled-review-aggregate.md](../submission/sampled-review-aggregate.md) — feeds the Accuracy Report appendix

**Headline:** 6/6 sampled findings plausible, 6/6 cited tool_call_ids resolved, 6/6 random evidence records clean. All 3 cases terminated HUMAN_REVIEW under the now-fixed R_05 normalize bug (commit `90d4ffd`); regression-gate re-run will confirm post-fix terminals.

**Framing:** research artifact, not a deployment-readiness claim. The Accuracy Report must be explicit about recall-blind-spot — we don't know FNs on non-GT cases.

---

## Step 7 — 4-row ablation runs (rows 2 + 4 if committed in Step 0)

Rows 1 + 3 are already implicit (row 1 = Slice 2.5 baseline; row 3 = full Slice 5). Step 0 committed to running rows 2 + 4 on all staged cases.

### Row 2 — capability-token verification disabled

**Status:** code prep ✅ 2026-04-26 (branch `ablation/row-2-no-cap-tokens`, commit `8f084a1`); runs deferred until memory-channel work in `pipeline/nodes.py` lands on main (concurrent edits would collide).

**What changed:** A single `SKIP_CAPABILITY_VERIFY` env var on `mcp_server/server.py`. When set to `true`, `_enforce_capability` still parses the JSON token (so `token.token_id` continues to flow into audit records) but skips all six scope checks in `verify_token` (signature, expiry, case_id, tool, path, plan_digest). Structured-field extraction and the injection scanner remain operational. Default unset → identical behavior to main.

**Probe:** `d:/tmp/probe_skip_capability_verify.py` (PASS — default mode denies a deliberate scope mismatch; ablation mode permits the same call).

**To run (do NOT do this while the memory-channel session is using the containers):**

```bash
# 1. Switch the MCP server onto the ablation branch
git checkout ablation/row-2-no-cap-tokens

# 2. Restart sift-mcp with the bypass env var set
SKIP_CAPABILITY_VERIFY=true docker compose -f docker/docker-compose.yaml up -d --force-recreate sift-mcp

# 3. Sanity-check the env var landed
docker exec sift-mcp env | grep SKIP_CAPABILITY_VERIFY

# 4. Re-run the staged cases (one at a time; numbered run IDs auto-increment)
for case in srl-2018-base-dc srl-2018-base-file srl-2018-base-rd-02 srl-2018-dmz-ftp srl-2018-wkstn-05 dfirmadness-001-desktop; do
  echo "=== Row 2 ablation: $case ==="
  MSYS_NO_PATHCONV=1 docker exec sift-sentinel \
    /workspace/.venv/bin/python /workspace/run_case.py \
    --case "$case" --e01 <case-specific-E01-path>
done

# 5. Restore main + re-deploy MCP without the bypass
git checkout main
docker compose -f docker/docker-compose.yaml up -d --force-recreate sift-mcp
```

Run outputs land at `out/runs/<case>/<case>-NNN/` and are tagged in the run banner with the active env vars. Annotate the resulting run folders with `ABLATION_ROW=2` in their respective `_resume.md`-style notes so the scoreboard collator can find them.

### Row 4 — `classification` field removed from `Finding` schema

**Status:** code prep ✅ 2026-04-26 (branch `ablation/row-4-no-classification`, commit `12d2dd9`); runs deferred until memory-channel work lands on main (the row-4 branch was cut from current main and does NOT carry the parallel session's `nodes.py` skip-vs-halt WIP — re-running ablation against a more recent main is a re-cut, not a rebase, and is the cleaner path).

**What changed:** `classification: Classification` field deleted from `Finding`; `_tag_attack` validator simplified to drop the classification-driven tactic-override branch (memory-class findings fall back to TA0003 Persistence — that's part of what the ablation measures); R_11 and R_16 stubbed to `return None` and removed from `CRITIC_RULES`; per-classification scorecard tallies dropped from interpret_node Langfuse metadata; classification omitted from the integrity-ledger `finding_committed` event. The INTERPRET prompt is intentionally NOT modified — Pydantic V2 default `extra="ignore"` silently drops the LLM's `classification` field from JSON output, so we measure the structural-validation contribution of the gate without confounding it with a prompt change.

**Test impact:** 10 R_11 / R_16 tests deleted on this branch; registry test now expects 13 rules instead of 15; pytest 237/237 green on the branch (excluding the parallel session's untracked `test_nodes_executor.py` which depends on their WIP).

**To run (do NOT do this while the memory-channel session is using the containers):**

```bash
# 1. Switch onto the ablation branch
git checkout ablation/row-4-no-classification

# 2. Re-deploy sift-mcp from this branch's code (no env var needed for row 4)
docker compose -f docker/docker-compose.yaml up -d --force-recreate sift-mcp

# 3. Re-run the staged cases
for case in srl-2018-base-dc srl-2018-base-file srl-2018-base-rd-02 srl-2018-dmz-ftp srl-2018-wkstn-05 dfirmadness-001-desktop; do
  echo "=== Row 4 ablation: $case ==="
  MSYS_NO_PATHCONV=1 docker exec sift-sentinel \
    /workspace/.venv/bin/python /workspace/run_case.py \
    --case "$case" --e01 <case-specific-E01-path>
done

# 4. Restore main + re-deploy
git checkout main
docker compose -f docker/docker-compose.yaml up -d --force-recreate sift-mcp
```

Tag the resulting run folders with `ABLATION_ROW=4` for the scoreboard collator.

### Scoring

- [ ] Run rows 2 + 4 on all staged cases (both branches now exist; runs blocked only on shared-container availability)
- [ ] Compare rows 1/2/3/4 scorecard_v2 across the 2.5 cases + adversarial demo
- [ ] Table lands in the Accuracy Report

---

## Step 8 — Accuracy Report (named deliverable)

Lives at [`docs/submission/accuracy-report.md`](../submission/accuracy-report.md). Required by `docs/reference/hackathon/rules.md` §4 #5.

Structure:
- [ ] **Executive summary** — the submission in 200 words: what we built, headline accuracy numbers, where the system shines / fails
- [ ] **Methodology** — Reference Dataset composition, GT protocol, optional sampled-review protocol, ablation design, tool + model stack
- [ ] **Per-case results** — for each case: scorecard_v2, per-finding verdict table, FP / FN inventory with notes
- [ ] **Ablation table** — 4 rows × (2.5 cases + adversarial demo) with precision/recall/quarantine%
- [ ] **Hallucinated-claim log** — every hallucination the Critic caught (from `critic_disagreements.jsonl` across all runs), categorized by failure code
- [ ] **Known limitations** — Windows-disk only, 5-tool MCP scope, FN blind spot on non-GT cases, container-boundary caveat
- [ ] **Extension points** — seccomp / eBPF / microVM for true adversarial bypass; Volatility 3 for Win11 / Server 2022 memory (Vol2 covers the SRL-2018 envelope, included in scope per Step 3b.6); Linux disk profile

---

## Step 9 — Submission package

Per `docs/reference/hackathon/rules.md` §4 component checklist (6 components):

- [ ] Component 1: code repository — clean up `README.md`, add submission-specific `docs/submission/README.md`
- [ ] Component 2: Accuracy Report (Step 8 above)
- [ ] Component 3: demo video — 5-minute screen recording walking the pipeline from PLAN approval through finding commit + adversarial demo
- [ ] Component 4: architecture diagram — `docs/submission/architecture.md` or `.png` (existing `architecture.html` may need update post-Slice-5)
- [ ] Component 5: autonomy-dial write-up — adapt `docs/planning/autonomy-dial.md`
- [ ] Component 6: ________ (verify from rules.md; may be threat model or license)

- [ ] Final `pytest -q` run green
- [ ] All docs cross-linked
- [ ] No secrets in the repo (run `git secrets` scan or manual grep)

---

## Step 10 — Wrap + submission

- [ ] PLAN.md Slice 6 row → ✅
- [ ] `_resume.md` final state: "Submitted YYYY-MM-DD; post-submission cleanup / portfolio polish open"
- [ ] SKILL.md Slice 6 retro
- [ ] Memory audit
- [ ] Tag commit: `git tag -a submission-v1 -m "SANS hackathon submission 2026-06-15"`
- [ ] Submit per the hackathon submission instructions in `docs/reference/hackathon/rules.md`

---

## Deferred to Slice 6.5 / Slice 7 (explicit)

Keeps scope tight. These are good ideas that won't make the submission:

- Real adversarial E01 builder (`make_adversarial_e01.py`) — Slice 5 Option C demo is sufficient for the submission's adversarial story
- Full-stack UI (Next.js findings viewer) — originally Slice 7; still stretch-only
- Volatility 3 (Win11 / Server 2022 memory) + Linux disk profile — documented as extension points in the Accuracy Report. **Note:** Volatility 2 memory coverage for SRL-2018 hosts is now in scope per Step 3b.6 (added 2026-04-25).
- MCP-over-WAN capability-token upgrade to Ed25519 — HMAC is sufficient for the current trust boundary
- SSHub.dev portfolio demo — explicitly post-submission per PLAN.md Open Questions

---

## Tripwires (per round-3 emphasis, Slice-6-specific)

| Trigger | Action |
|---|---|
| Pipeline regression on any 2.5 baseline case during Slice 6 changes | **Halt Slice 6 merge.** Restore the pipeline to green on 2.5 cases before any Slice-6-specific work lands on top |
| L3 confidence rubric can't land in time | Ship L2.5 instead — explicit Low-confidence tagging without auto-escalation; document the auto-escalation as Slice 6.5 |
| Integrity-ledger implementation runs over budget | Ship stub + `verify_chain_of_custody.py` skeleton; document hash-chain as Slice 6.5 |
| Cost overrun on full-dataset runs | Cut ablation rows 2 + 4; cut non-GT cases if needed; always keep GT-annotated cases in the run |
| Third GT case ambiguous | Cut to 2 GT-annotated cases; document reason in Accuracy Report |
| Submission deadline slipping | Cut in order: rows 2+4 ablation → non-GT cases → third GT case → ledger (ship stub only). Never cut: Accuracy Report, scorecard_v2 on 2.5 cases, adversarial demo |
| Vol2 cannot bind a profile to a staged memory dump (Step 3b.6 fail-fast) | Fall back to disk-only AI-assisted (3b.1-3b.5 only); document memory analysis as Slice 6.5 / extension; do not sink-cost on profile hunting |
| Memory plugin output bloats the INTERPRET bundle past safe-cost envelope | Apply same bundle-trim discipline as the Step-7 fls_list fix: strip plugin output rows that don't carry forensic content (e.g., system processes in `pslist` matching a known-safe set); cap per-plugin output rows in the bundle builder |

---

## Reference — paths quick card

| What | Where |
|---|---|
| Staged evidence | `HACKATHON-2026/<case>/` |
| Preprocessed partitions | `/mnt/derived/<case>/` |
| Per-case pipeline output | `experiments/slice-2-notebook/out/runs/<case>/` |
| Integrity ledger | `/var/lib/find-evil/ledger.jsonl` (target — confirm at Step 4) |
| Accuracy Report | `docs/submission/accuracy-report.md` |
| Submission package | `docs/submission/` |
| pytest suite | `experiments/slice-2-notebook/tests/` |

---

## Open design questions

*(Promote to Step 0 discussion. Don't code past Step 0 until these are decided.)*

1. **Confidence rubric definition** — what specific signals determine H/M/L? Needs a decision before Step 3 can begin.
2. **Third full-GT case** — which of `base-dc` / `base-file` / `base-rd-0{1,2}` / `base-wkstn-01` makes the best regression baseline? Candidate criteria: cleanest persistence mechanism, diversity from wkstn-05 + dfirmadness.
3. **Optional sampled-review sampling rate** — 3 findings per non-GT case? All findings? Random evidence records too?
4. **Integrity-ledger storage location** — `/var/lib/find-evil/ledger.jsonl` on the sift-sentinel container vs the host FS vs an external DB?
5. **Ablation scope** — rows 2 + 4 add ~$18 in LLM spend. Worth it for the headline number, or cut?
