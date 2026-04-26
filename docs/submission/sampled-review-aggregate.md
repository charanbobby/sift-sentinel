# Sampled-review aggregate (3 non-GT cases)

**Reviewer:** charan.bobby@gmail.com (with Claude Opus 4.7)
**Reviewed at:** 2026-04-26
**Slice 6 / Step 6 deliverable.** Intended as an appendix to the forthcoming Accuracy Report at `docs/submission/accuracy-report.md`.

## Scope

Three Slice-5 disk-only cases that lack full ground truth: `srl-2018-base-file`, `srl-2018-base-rd-02`, `srl-2018-dmz-ftp`. For each, we sampled all findings (≤3 per case) plus 2 random evidence records (Python `random.seed(20260426)`) and asked: are the findings plausible, do citations resolve, do random evidence records hold up?

This is a research artifact, not a deployment-readiness claim. Without a ground-truth corpus on these cases we cannot compute precision or recall here. Per-case write-ups live next to each run at `out/runs/<case>/sampled_review.md`.

## Headline numbers

| Case | Findings | Verdict (plausibility) | Cited tool_call_ids resolved | Random records clean | Terminal |
|---|---|---|---|---|---|
| srl-2018-base-file | 1 | 1 PLAUSIBLE | 1/1 | 2/2 | HUMAN_REVIEW (R_05 artifact) |
| srl-2018-base-rd-02 | 3 | 3 PLAUSIBLE | 3/3 | 2/2 | HUMAN_REVIEW (R_05 artifact) + 1 INJECTION_QUARANTINE (defense fired correctly) |
| srl-2018-dmz-ftp | 2 | 2 PLAUSIBLE | 2/2 | 2/2 | HUMAN_REVIEW (R_05 artifact) |
| **Total** | **6** | **6/6 plausible** | **6/6 resolved** | **6/6 clean** | All HUMAN_REVIEW pre-fix |

## Cross-cutting observations

1. **All 6 sampled findings were plausible to a human reviewer.** No "known wrong" or "suspicious" verdicts. This is a small sample and must not be over-read, but it is consistent with the Slice 4 + 5 GT scorecards (precision 1.00 on the GT-annotated cases).

2. **R_05 was the dominant escalation cause across all 3 cases.** All 3 runs terminated at HUMAN_REVIEW, and in every case the only critic failure was R_05 `EXCERPT_HALLUCINATION` — the now-fixed normalize bug (commit `90d4ffd`) that was over-strict on whitespace/quote drift. The cited excerpts are real text from the structured fields in every case sampled. The regression-gate re-run (Slice 6 Step 5 follow-up) will confirm that the patched code commits the high-confidence findings auto and only escalates the genuinely-ambiguous ones.

3. **`requires_disambiguation` is being used correctly.** Five of six findings (LARIAT Run key, LARIAT service, PSEXESVC, IFEO Debugger, plus Microsoft Advanced API 64 in two cases) test the model's discipline around dual-use binaries. The model reaches for `requires_disambiguation` when honest, and only commits to `attacker_persistence` when the masquerade pattern is unambiguous. No findings showed the failure mode where the LLM forces a verdict to look decisive.

4. **The injection scanner caught a real registry-binary blob containing a literal MITRE technique ID (`T1033`) in `srl-2018-base-rd-02`.** Quarantined record `c46bb35b` was correctly excluded from the LLM bundle; none of the surfaced findings cite it. This is exactly the defense-layer behavior the dual-channel architecture was built for.

5. **One genuine plan-level gap surfaced (srl-2018-dmz-ftp finding 2).** The IFEO Debugger=cmd.exe entry is the classic sticky-keys backdoor pattern, but resolving TP vs FP requires the *child key name* (e.g., `sethc.exe` vs `Image File Execution Options\debugger.exe`), which the regripper `imagefile` plugin's structured fields don't expose. The model honestly flagged the gap. Recommended follow-up (post-hackathon): harden the IFEO plugin or add a custom plugin that walks IFEO subkeys.

6. **Cross-host TTP overlap is visible in the dataset.** The same `Microsoft Advanced API 64` masquerading service appears in both `srl-2018-base-file` and `srl-2018-base-rd-02`. This is itself an analytic finding — single attacker toolkit deployed across multiple hosts on the same incident. No cross-case correlation logic exists yet; today this is only visible to a human reading both reports. Possible future capability.

## What this means for the submission narrative

- The pipeline's classification *content* on non-GT cases looks sound to manual review (6/6 plausible, 0/6 known wrong).
- The HUMAN_REVIEW terminals on all 3 cases were a known critic bug, now patched. Headline accuracy numbers should be reported on post-fix runs, not these pre-fix runs.
- The Accuracy Report (Step 8) must explicitly call out the recall-blind-spot: we don't know false negatives on these 3 cases — only that surfaced findings hold up. A finding the model *missed* would not appear here.
- Defense layers (injection scanner, R_05 even with bug) routed correctly. The system fails safe under the patterns we tested.

## Methodology notes (for reproducibility)

- Sampling rate per Step 0 decision: all findings if ≤3, else 3 random; 2 random evidence records per case.
- Evidence-record seed: Python `random.sample(range(N), 2)` after `random.seed(20260426)` where N is the per-case evidence-record count (19 / 16 / 20).
- Resolved tool_call_ids by `grep -c "\"tool_call_id\":\"<id>\""` against `04_execute_evidence.jsonl`.
- Excerpt cross-references were spot-checked manually; the patched R_05 normalize logic is the systematic check and will be the headline data point in the Accuracy Report once Step 5 follow-up has re-run all baselines.
- Per-case files: [srl-2018-base-file](../../experiments/slice-2-notebook/out/runs/srl-2018-base-file/sampled_review.md), [srl-2018-base-rd-02](../../experiments/slice-2-notebook/out/runs/srl-2018-base-rd-02/sampled_review.md), [srl-2018-dmz-ftp](../../experiments/slice-2-notebook/out/runs/srl-2018-dmz-ftp/sampled_review.md).
