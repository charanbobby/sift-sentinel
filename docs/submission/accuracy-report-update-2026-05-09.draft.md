# Accuracy report update draft, 2026-05-09 (extends the "0 hallucinations across 7 runs" claim)

**Status:** DRAFT for parent agent integration into `accuracy-report.md`. Not committed automatically; the parent agent integrates after the bulk-adjudication brief at `docs/submission/adjudication-bulk-2026-05-09.md` settles the remaining 9 HUMAN_REVIEW rows.

**Source:** `out/audit_summary_v2_2026-05-09.md` and `out/audit_report_bucketed_v2_2026-05-09.csv` (relaxed-rule reclassification of the 22 original Bucket X rows).

---

## Suggested addition to Section 1 (Executive summary), under the headline-numbers table

**Update to the "Hallucinations across 7 runs" row, plus a follow-up row.** As of 2026-05-09 the cheap-check audit has been extended from the 7 hand-picked runs documented above to the full corpus of `out/runs/` non-curated runs reclassified under Charan's relaxed bucket rules (HUMAN_APPROVED treated as clean SUCCESS, QUARANTINED.audit treated as QUARANTINED, SUCCESS-with-4-findings cap relaxed). Across 32 cleared runs (23 Bucket A non-curated + 9 curated `keep_runs.json` entries), 0 real factual hallucinations were observed. The only run that produced an unresolved citation (`srl-2018-wkstn-05-008`) cited a stale `tool_call_id` ("20" instead of a UUID) whose underlying claim is independently corroborated by a resolved sibling citation in the same finding; this is classified as a citation-pointer artifact, not a fabricated finding. 11 additional runs ended in QUARANTINED (defense layer fired as designed; out of scope for the hallucination claim) and 9 runs are pending the bulk-adjudication brief at `docs/submission/adjudication-bulk-2026-05-09.md` and may extend the cleared-N number further when that brief lands. 2 runs have no terminal marker file and are flagged for data-integrity follow-up; they are excluded from the headline N.

**Suggested replacement row in the Section 1 table:**

| Hallucinations across 32 cleared runs (23 Bucket A + 9 curated) | 0 | Cheap-check audit 2026-05-09 (`out/audit_report_bucketed_v2_2026-05-09.csv`); 1 stale citation pointer logged separately as a data-quality finding |

**Suggested new follow-up row (parenthetical, after the bulk brief lands):**

| Pending bulk-adjudication runs | 9 | Listed in `out/audit_summary_v2_2026-05-09.md`; will be remapped to A or D after `docs/submission/adjudication-bulk-2026-05-09.md` is produced |

---

## Suggested addition to Section 5 (Hallucinated-claim log)

After the existing "Real hallucinations confirmed by human review: 0" row, add:

| `STALE_CITATION_ID` | 1 | No (citation-pointer artifact) | `srl-2018-wkstn-05-008` finding 3 (process_injection on powershell.exe) cited `tool_call_id: "20"` against an evidence file that uses UUID v4 ids exclusively. The unresolved id is a malformed pointer; the underlying factual claim (that `powershell.exe` PID 1124 ran with `-Version 5.0 -s -NoLogo -NoProfile`) is corroborated in the same finding's notes via `[ev:25b6f521-f5ce-4fcd-86e2-d4ea55fae2b4]`, which IS present in the evidence file. Categorised as data-quality, not factual hallucination. Follow-up: tighten the INTERPRET prompt or schema validator to reject non-UUID `tool_call_id` values before write. |

---

## Notes for the parent agent

1. The headline number (0 across 32) is conservative. After the bulk brief lands, if all 9 HUMAN_REVIEW rows turn out clean, the headline becomes **0 across up to 41 cleared runs** (23 + 9 + up-to-9). The parent agent should re-issue the headline once the bulk brief settles.
2. The 11 Bucket D rows are deliberately excluded from N. Defense-fired runs are not in scope for the hallucination claim; they are scored under the "defense layer caught it" track elsewhere in the report.
3. The 2 MISSING_TERMINAL rows are excluded from N. They are a data-integrity follow-up, not a hallucination signal.
4. The single citation-pointer artifact is worth a one-line note in the report even though it is not a factual hallucination, because the SANS rubric values "system catches its own mistakes." Acknowledging it strengthens rather than weakens the claim.
5. Do NOT modify `viewer/keep_runs.json` based on this audit. The 23 Bucket A non-curated rows are not promoted to curated; they are simply confirmed as not hallucinating. Promoting any to curated is a separate decision that requires per-run sampled review.
