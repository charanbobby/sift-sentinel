# Sampled review - srl-2018-base-file

**Reviewer:** charan.bobby@gmail.com (with Claude Opus 4.7)
**Reviewed at:** 2026-04-26
**Run:** srl-2018-base-file-001 (latest at review time)
**Sampling rate:** all findings (1 total) + 2 random evidence records (Python `random.seed(20260426)`)
**Pipeline terminal:** HUMAN_REVIEW

## What this is

This case has no full ground truth, so we cannot compute precision or recall on it. This document is a lightweight spot-check: do the model's findings look plausible to a human reviewer, do the cited evidence records actually exist, and do a couple of random evidence records hold up to inspection? It is a research artifact, not a deployment-readiness claim.

## Important context: pre-fix R_05 escalation

The `06_critic_disagreements.jsonl` shows finding 0 was escalated under rule R_05 (`EXCERPT_HALLUCINATION`). The R_05 normalize bug was fixed post-this-run (commit `90d4ffd`); the cited excerpts are real — they just failed the old whitespace/quote comparison. The HUMAN_REVIEW terminal here is therefore an artifact of the now-fixed bug, not a quality signal. The regression-gate re-run will confirm whether the patched code commits this finding cleanly.

## Finding-level review

### Finding 1: "Microsoft Advanced API 64" service auto-start
- **Cited binary:** `C:\Program Files (x86)\Microsoft Advanced API 64\msadvapi2_64.exe`
- **Classification:** `attacker_persistence` (high confidence)
- **MITRE:** T1543.003 (Windows Service)
- **Cited evidence:** tool_call_id `3439e442` (verified present in evidence file)
- **Excerpt cross-ref:** `ImagePath=C:\Program Files (x86)\Microsoft Advanced API 64\msadvapi2_64.exe | Type=Own_Process | Start=Auto Start` — matches the structured fields when whitespace is normalized
- **Verdict:** PLAUSIBLE
- **Why:** The service name mimics a legitimate Microsoft component but the binary lives under `C:\Program Files (x86)\Microsoft Advanced API 64\`, which is not a path Microsoft uses for any built-in service. Real Microsoft API services (RPC, Perf*, TCP/IP, .NET CLR) are svchost-hosted from `%SystemRoot%\System32`. The blank Display value is also unusual for a real Microsoft service. Textbook MITRE T1036.005 masquerading layered on top of T1543.003. The model's reasoning chain rules out the three legitimate alternatives (DFIR responder, vendor security product, Windows default) explicitly. No red flags in the analytic reasoning.

## Evidence record spot-check (2 of 19, seed 20260426)

### Record A - line 5: tool_call_id `4a7edc70`
- **Tool family:** `fls_list` (filesystem navigation)
- **What it ran:** Walked entries inside `C:\Windows\System32\config\` (BBI hive, COMPONENTS hive transaction logs, BCD-Template, etc.)
- **Plausibility:** OK
- **Notes:** Output is a real directory entry table with realistic NTFS metadata (inodes, MFT $FILE_NAME shadow entries, plausible 2013–2018 timestamps). This is a navigation/staging step that helps the executor pick which hive files to extract. Per the cost-discipline note in CLAUDE.md, these `fls_list` outputs are exactly the records the bundle builder strips before INTERPRET — they don't carry analytic content.

### Record B - line 11: tool_call_id `433fc708`
- **Tool family:** `fls_list` (filesystem navigation, similar to record A)
- **What it ran:** Another directory walk (registry-config area, judging by the position in the plan)
- **Plausibility:** OK
- **Notes:** Same shape as record A — well-formed NTFS entries, no anomalies, no injection-scanner flags. Used for staging, not analysis.

## Conclusion

One finding, plausible, properly cited. Two random evidence records both clean. The HUMAN_REVIEW escalation is a known artifact of the pre-`90d4ffd` R_05 normalize bug; the underlying analytic content of the finding is sound. Recommend re-running under patched code as part of the regression gate; expected outcome is auto-commit.
