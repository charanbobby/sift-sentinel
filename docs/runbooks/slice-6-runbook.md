# Slice 6 Runbook — Reference Dataset + L3 Ship + Sampled-Audit + Accuracy Report

**Goal:** Ship the submission. Four named deliverables per [`PLAN.md`](../planning/PLAN.md) row 6:

1. **Reference Dataset** — stage ~5–7 SRL-2018 Windows/NTFS E01s under `HACKATHON-2026/`. Full ground-truth annotation on 3 cases (L2→L3 regression baseline); sampled post-hoc audit on the rest.
2. **L3 controls** — H/M/L confidence rubric with auto-escalation of Low; per-excerpt sha256 provenance linked to `plan_digest`; Critic-disagreement log; token/latency/tool-call audit trail; **append-only integrity ledger** stored separately from case folders (NIST: hashes in the same mutable folder look like self-attestation).
3. **Sampled-audit research artifact** — autonomous run across the full Reference Dataset with post-hoc reviewer audit on sampled findings. Scoped as a research artifact, **not** a claim of deployment-ready forensic-auditor operation.
4. **Accuracy Report** — named submission deliverable per `docs/reference/hackathon/rules.md` §4 #5. Lives at `docs/submission/accuracy-report.md`. Assembles scorecard_v2 + 4-row ablation + per-case FP/FN inventory + hallucinated-claim log with Critic catches.

**Why this shape (submission framing):** Slice 5 made the evidence-to-LLM boundary structurally defensible. Slice 6 demonstrates that boundary **scales across a real dataset** and produces an **auditable record** — the two things a judge needs to believe the system would hold up in practice. L3 "Exception-Based Autonomy" is the autonomy dial we ship; the sampled-audit artifact documents one justified next step (we don't headline aspirational levels).

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
- [x] **Sampled-audit rate**: 3 findings per non-GT case (all findings if the case produced ≤3) + 2 random evidence records per case. Cheap in reviewer-time, catches the dominant FP / hallucination class
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

- [ ] Update [`docs/reference/hackathon/dataset_manifest.md`](../reference/hackathon/dataset_manifest.md) with status rows for each staged case: `[staged / preprocessed / pipeline-runs-clean / GT-annotated / sampled-audit-done]`
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

**Why the bar is "3 full-GT cases, not all ~7":** ground-truth annotation is expensive (hours per case) and only needed for the L2→L3 regression claim. The other 4 cases get the cheaper sampled-audit treatment.

---

## Step 3 — L3 confidence rubric + auto-escalation

Today's system uses the Critic's severity (pass/retry/escalate). Slice 6 adds an explicit **finding-level** confidence rubric independent of the rule-failure path.

- [ ] Define the H/M/L rubric in `pipeline/schemas.py`: when does a finding get High, Medium, or Low?
  - Candidate criteria: number of corroborating evidence records, presence of timestamp grounding, classification certainty, count of ruled-out alternatives, Critic-rule pass rate
- [ ] Wire in `pipeline/critic.py`: any `Low`-confidence finding auto-escalates to `human_review` regardless of Critic rule outcomes
- [ ] Add a new `CRITIC_RULE` or orchestrator-layer check: `R_14_LOW_CONFIDENCE_AUTO_ESCALATE` (consider: is this a Rule, or a separate mechanism?)
- [ ] Fail-fast probe + pytest: synthetic Low-confidence finding → forces escalate; High-confidence finding → passes
- [ ] Re-run 2.5 baseline; confirm no regression (P=1.00 R=1.00 still)

### 3a — Per-excerpt sha256 provenance

- [ ] Every `Evidence` record carries the sha256 of the structured_fields it cites (not just the raw bytes sha256)
- [ ] Linked to `plan_digest` so an excerpt can be traced to the exact approved plan version that produced it
- [ ] schemas.py change + migration note
- [ ] Fail-fast probe: tamper with cited structured_fields post-hoc → provenance-verifier detects

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

## Step 6 — Sampled-audit protocol

For the ~4 cases without full GT, apply a lightweight post-hoc reviewer audit.

- [ ] Sampling rate (Step 0 decision): e.g., audit N findings per case + M random evidence records
- [ ] Audit template: reviewer marks each sampled finding as "plausible / suspicious / known wrong" + cross-references cited structured_fields
- [ ] Per-case sampled-audit report: `out/runs/<case>/sampled_audit.md`
- [ ] Aggregate sampled-audit stats for the Accuracy Report

**Framing:** this is a *research artifact*, not a deployment-readiness claim. The Accuracy Report must be explicit about recall-blind-spot: we don't know FNs on non-GT cases.

---

## Step 7 — 4-row ablation runs (rows 2 + 4 if committed in Step 0)

Rows 1 + 3 are already implicit (row 1 = Slice 2.5 baseline; row 3 = full Slice 5). If Step 0 committed to rows 2 + 4:

- [ ] Row 2: dual-channel only (no capability tokens). Disable capability-token verification in the MCP server, keep structured-field extraction + injection scanner. Re-run on all staged cases.
- [ ] Row 4: full Slice 5 with `classification` field removed from the `Finding` schema. Re-run.

- [ ] Compare rows 1/2/3/4 scorecard_v2 across 2.5 cases + adversarial demo
- [ ] Table lands in the Accuracy Report

---

## Step 8 — Accuracy Report (named deliverable)

Lives at [`docs/submission/accuracy-report.md`](../submission/accuracy-report.md). Required by `docs/reference/hackathon/rules.md` §4 #5.

Structure:
- [ ] **Executive summary** — the submission in 200 words: what we built, headline accuracy numbers, where the system shines / fails
- [ ] **Methodology** — Reference Dataset composition, GT protocol, sampled-audit protocol, ablation design, tool + model stack
- [ ] **Per-case results** — for each case: scorecard_v2, per-finding verdict table, FP / FN inventory with notes
- [ ] **Ablation table** — 4 rows × (2.5 cases + adversarial demo) with precision/recall/quarantine%
- [ ] **Hallucinated-claim log** — every hallucination the Critic caught (from `critic_disagreements.jsonl` across all runs), categorized by failure code
- [ ] **Known limitations** — Windows-disk only, 4-tool MCP scope, FN blind spot on non-GT cases, stdio-transport caveat (now HTTP — update)
- [ ] **Extension points** — seccomp / eBPF / microVM for true adversarial bypass, memory analysis (Volatility), Linux disk profile

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
- Memory analysis (Volatility) + Linux disk profile — documented as extension points in the Accuracy Report
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
3. **Sampled-audit sampling rate** — 3 findings per non-GT case? All findings? Random evidence records too?
4. **Integrity-ledger storage location** — `/var/lib/find-evil/ledger.jsonl` on the sift-sentinel container vs the host FS vs an external DB?
5. **Ablation scope** — rows 2 + 4 add ~$18 in LLM spend. Worth it for the headline number, or cut?
