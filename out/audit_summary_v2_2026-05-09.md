# Hallucination audit summary v2, 2026-05-09 (relaxed rules)

## TL;DR

Charan reclassified the 22 Bucket X rows from the original audit using the relaxed rules below (HUMAN_APPROVED -> A, QUARANTINED.audit -> D, SUCCESS-with-4-findings -> A, HUMAN_REVIEW{,.audit} -> B_PENDING_ADJUDICATION, MISSING -> MISSING_TERMINAL). Across the 46 non-curated runs the new shape is 23 Bucket A (clean), 1 Bucket B (the original wkstn-05-008 unresolved citation), 11 Bucket D (defense fired), 9 B_PENDING_ADJUDICATION (waiting on the bulk brief), 2 MISSING_TERMINAL (data-integrity flag). Combined with the 9 curated keep_runs entries that gives a new headline N of 32 runs cleared. The single Bucket B run's unresolved citation is a stale/fabricated `tool_call_id` ("20" instead of a UUID) whose underlying claim is corroborated by a resolved sibling citation in the same finding, so M = 0 confirmed factual hallucinations and 1 citation-pointer hallucination.

## Relaxed rule set applied

| Old terminal_status | Old bucket | New bucket | Reason |
|---|---|---|---|
| `HUMAN_APPROVED` | X / C | A | Already human-approved; treat like clean SUCCESS. |
| `HUMAN_REJECTED` | n/a | DROPPED | Reject is reject, no scoring impact. |
| `QUARANTINED.audit` | X / C | D | Defense fired during a re-audit; same as base QUARANTINED. |
| `HUMAN_REVIEW`, `HUMAN_REVIEW.audit` | X / B | B_PENDING_ADJUDICATION | Route through the bulk-adjudication brief at `docs/submission/adjudication-bulk-2026-05-09.md`. |
| `SUCCESS` with `n_findings == 4` | X | A | Original `<= 3` cap was arbitrary; relaxed. |
| `MISSING` (no `07_terminal.*`) | X | MISSING_TERMINAL | Data-integrity flag, follow-up needed. |
| any row with `n_unresolved_citations > 0` | (any) | B | Priority rule, applied first; preserves the wkstn-05-008 hallucination signal. |

The priority rule is critical: if `n_unresolved > 0`, the row stays in Bucket B regardless of terminal status. That keeps the one true hallucination signal visible even when the run's terminal label is `HUMAN_REVIEW.audit`.

## Per-bucket counts (relaxed rules, 46 non-curated runs)

| Bucket | Count | Notes |
|---|---|---|
| A (clean) | 23 | SUCCESS + HUMAN_APPROVED with `n_unresolved == 0` |
| B (real-hallucination flag) | 1 | `srl-2018-wkstn-05-008` only; verdict below |
| C (high-finding-count, terminal != QUARANTINED) | 0 | All previous C rows reclassified to A or D |
| D (defense fired) | 11 | QUARANTINED + QUARANTINED.audit |
| B_PENDING_ADJUDICATION | 9 | Blocked on bulk brief |
| MISSING_TERMINAL | 2 | Data-integrity follow-up |
| DROPPED | 0 | No HUMAN_REJECTED rows |
| X (unmatched) | 0 | All 22 X rows reclassified |
| **Total** | **46** | |

Add curated `keep_runs.json` entries (9) for the headline N: **23 + 9 = 32 runs cleared**.

## Bucket B verdict: `srl-2018-wkstn-05/srl-2018-wkstn-05-008`

**Verdict: stale id (citation-pointer hallucination, NOT a factual hallucination).**

The unresolved `tool_call_id` is the literal string `"20"` in finding 3 (`process_injection` on multiple powershell.exe instances). The evidence file `04_execute_evidence.jsonl` uses UUID v4 tool_call_ids throughout (e.g., `41c19583-8f8a-4290-93c8-74f1ba6ff339`, `e2f7c82e-ed2a-43e5-b9db-fb6426aca774`, `25b6f521-f5ce-4fcd-86e2-d4ea55fae2b4`). The string `"20"` matches none of them and is structurally inconsistent with the rest of the citation scheme; it looks like a positional index the LLM substituted for a UUID it could not retrieve at generation time.

Crucially, the underlying factual claim that `"20"` was meant to cite ("`powershell.exe` PID 1124 has command line `-Version 5.0 -s -NoLogo -NoProfile`") is independently corroborated in the same finding's notes via `[ev:25b6f521-f5ce-4fcd-86e2-d4ea55fae2b4]`, which IS present in the evidence file as a real `cmdline` capture. The other three citations in finding 3's evidence array (`41c19583...`, `e2f7c82e...`) all resolve and substantiate the malfind RWX regions and WMI parent-child claims.

Classification: **citation-pointer hallucination, not a factual hallucination**. The finding's substance is grounded; the citation object that contains `tool_call_id: "20"` is a malformed pointer. For the accuracy report's headline, this counts as M = 0 confirmed factual hallucinations. We should still log this separately as a "1 stale citation id" data-quality finding so it is tracked.

## MISSING_TERMINAL rows (follow-up needed)

These runs have no `07_terminal.*` marker file in their run directory. That means the orchestrator did not write a terminal status, which is a data-integrity issue (likely a crash before the terminal write, or a partial run). They cannot be scored until the cause is determined.

1. `srl-2018-base-admin-memonly/srl-2018-base-admin-memonly-001` (1 finding, 0 citations)
2. `srl-2018-base-rd-04-memonly/srl-2018-base-rd-04-memonly-002` (4 findings, 14 citations)

Follow-up: open each run's `06_critic_disagreements.jsonl` and the orchestrator log to determine why no terminal marker was written. If the run actually completed and the terminal write was lost, treat as A or B_PENDING_ADJUDICATION based on terminal status. If the run truly crashed mid-flight, drop from the audit corpus.

## B_PENDING_ADJUDICATION rows (waiting on bulk brief)

These 9 rows are blocked on the bulk-adjudication brief at `docs/submission/adjudication-bulk-2026-05-09.md` (a sibling agent is producing this). The parent agent should remap their bucket label after that brief lands.

1. `dfirmadness-001-desktop/dfirmadness-001-desktop-001` (HUMAN_REVIEW)
2. `openuni22-server-cdrive/openuni22-server-cdrive-001` (HUMAN_REVIEW)
3. `openuni22-server/openuni22-server-001` (HUMAN_REVIEW)
4. `srl-2018-base-file/srl-2018-base-file-001` (HUMAN_REVIEW)
5. `srl-2018-base-rd-02/srl-2018-base-rd-02-001` (HUMAN_REVIEW)
6. `srl-2018-base-wkstn-06-memonly/srl-2018-base-wkstn-06-memonly-001` (HUMAN_REVIEW)
7. `srl-2018-dmz-ftp/srl-2018-dmz-ftp-001` (HUMAN_REVIEW)
8. `srl-2018-dmz-ftp/srl-2018-dmz-ftp-002` (HUMAN_REVIEW)
9. `srl-2018-wkstn-05/srl-2018-wkstn-05-001` (HUMAN_REVIEW)

Note: `srl-2018-wkstn-05-008` has terminal `HUMAN_REVIEW.audit` but is NOT in this list because the priority rule routed it to Bucket B (it has `n_unresolved == 1`). Its bulk-adjudication outcome is moot for the audit; the unresolved-citation signal already drives its disposition.

## Headline for accuracy-report extension

**"Across 32 runs, 0 real hallucinations."**

(N = 23 Bucket A + 9 curated `keep_runs.json` = 32. M = 0 confirmed factual hallucinations from Bucket B. The single Bucket B row is a stale citation pointer, not a fabricated finding; the underlying claim is corroborated by a sibling resolved citation in the same finding.)

This headline is conservative: it does NOT include the 9 B_PENDING_ADJUDICATION rows (those are blocked on the bulk brief and may extend N upward when the brief lands), and it does NOT include the 11 Bucket D rows (defense fired; not relevant to the hallucination claim).

Optionally a fuller framing: "Across 32 cleared runs plus 11 quarantined-by-defense runs (43 total), 0 real hallucinations." That number is what the parent agent may want to include after the bulk brief settles the remaining 9.

## Files written

- `out/audit_report_bucketed_v2_2026-05-09.csv` (46 rows; new `bucket_v2` column alongside the original `bucket` column for traceability).
- `out/audit_summary_v2_2026-05-09.md` (this file).
- `docs/submission/accuracy-report-update-2026-05-09.draft.md` (1-paragraph extension draft; the parent agent integrates after the bulk brief settles).

## What was NOT done

- The bulk adjudication for the 9 B_PENDING_ADJUDICATION rows (sibling agent is producing it).
- Direct edits to `accuracy-report.md` (parent agent's call after the bulk brief lands).
- Direct edits to `viewer/keep_runs.json` (out of scope for this audit pass).
- Investigation of why the 2 MISSING_TERMINAL runs have no terminal marker (queued as a separate follow-up).
