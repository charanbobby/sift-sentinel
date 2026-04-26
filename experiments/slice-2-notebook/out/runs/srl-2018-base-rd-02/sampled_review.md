# Sampled review - srl-2018-base-rd-02

**Reviewer:** charan.bobby@gmail.com (with Claude Opus 4.7)
**Reviewed at:** 2026-04-26
**Run:** srl-2018-base-rd-02-001 (latest at review time)
**Sampling rate:** all findings (3 total) + 2 random evidence records (Python `random.seed(20260426)`)
**Pipeline terminal:** HUMAN_REVIEW

## What this is

This case has no full ground truth, so we cannot compute precision or recall on it. This document is a lightweight spot-check: do the model's findings look plausible, do the cited evidence records exist, and do a couple of random evidence records hold up to inspection? Research artifact, not a deployment-readiness claim.

## Important context: pre-fix R_05 escalation + injection quarantine

Two pieces of context the reader should hold while reading:

1. **R_05 escalation:** `06_critic_disagreements.jsonl` shows all 3 findings escalated under R_05 (`EXCERPT_HALLUCINATION`). This was the pre-`90d4ffd` normalize bug — the excerpts are real, the old comparison was over-strict on whitespace and quotes. The HUMAN_REVIEW terminal is an artifact, not a quality signal. The regression-gate re-run will confirm.

2. **Injection quarantine fired (correctly):** Step also shows an `INJECTION_QUARANTINE` event for tool_call_id `c46bb35b` with pattern `INJ_ATTCK_EMIT` (the excerpt contained the literal string `T1033` embedded in raw registry hive bytes). The injection scanner correctly suppressed that record from the LLM bundle. This is not a finding, this is the defense layer doing its job. None of the 3 surfaced findings cite the quarantined record.

## Finding-level review

### Finding 1: "Microsoft Advanced API 64" service auto-start (same as base-file)
- **Cited binary:** `C:\Program Files (x86)\Microsoft Advanced API 64\msadvapi2_64.exe`
- **Classification:** `attacker_persistence` (high confidence)
- **MITRE:** T1543.003 (Windows Service)
- **Cited evidence:** tool_call_id `3950875e` (verified present)
- **Verdict:** PLAUSIBLE
- **Why:** Identical TTP to srl-2018-base-file finding 1, on the same incident timeline. The fact that the same masquerading service appears on two separate hosts is itself a corroborating signal — consistent with a single attacker toolkit deployed across the environment. Same plausibility argument as the base-file review.

### Finding 2: "LARIAT Actuator" Run key
- **Cited binary:** `C:\Program Files (x86)\Lincoln\LARIAT\tools\lariat.cmd`
- **Classification:** `requires_disambiguation` (medium confidence)
- **MITRE:** T1547.001 (Registry Run Keys / Startup Folder)
- **Cited evidence:** tool_call_id `a1950b2a` (verified present)
- **Verdict:** PLAUSIBLE classification choice
- **Why:** "LARIAT" under "Lincoln" is consistent with MIT Lincoln Laboratory's LARIAT (Lincoln Adaptable Real-time Information Assurance Testbed), a legitimate cyber-range tool used in DoD-funded exercises. It can also be repurposed by attackers, which is why `requires_disambiguation` (rather than `attacker_persistence` or `legitimate_vendor_product`) is the right call without installer logs or threat-intel context. The model correctly named the ambiguity instead of guessing. Good behavior.

### Finding 3: LARIAT service via prunsrv.exe (corroborates finding 2)
- **Cited binary:** `"C:\Program Files (x86)\Lincoln\LARIAT\tools\prunsrv.exe" //RS//LARIAT`
- **Classification:** `requires_disambiguation` (medium confidence)
- **MITRE:** T1543.003
- **Cited evidence:** tool_call_id `3950875e` (same record as finding 1, verified present)
- **Verdict:** PLAUSIBLE
- **Why:** prunsrv.exe is a legitimate Apache Commons Daemon binary, frequently used to wrap Java apps as Windows services. The dual-persistence pattern (Run key + Auto Start service) is suggestive but, as with finding 2, not dispositive. Same disambiguation rationale.

## Evidence record spot-check (2 of 16, seed 20260426)

### Record A - line 4: tool_call_id `1d56c980`
- **Tool family:** `fls_list` (filesystem navigation)
- **What it ran:** Walked a localized resources directory (`0409`, `20180815`, `20180907` entries; `@*ToastIcon.png`, `@bitlockertoastimage.png`, `@edptoastimage.png` files — Windows toast notification icons)
- **Plausibility:** OK
- **Notes:** Plain Windows resource files. Two interesting timestamp clusters (`20180815`, `20180907`) align with the incident window; the navigation is presumably feeding a downstream extraction step. No injection flags. Stripped from INTERPRET bundle by design.

### Record B - line 9: tool_call_id `9e32fd1c`
- **Tool family:** `fls_list` (filesystem navigation)
- **What it ran:** Another directory walk (likely registry-config or user-profile area based on plan position)
- **Plausibility:** OK
- **Notes:** Same shape as record A — well-formed NTFS entries, no anomalies. Used for staging.

## Conclusion

Three findings, all plausible: 1 high-confidence attacker-persistence (cross-host TTP shared with base-file) + 2 properly-flagged `requires_disambiguation` cases for the LARIAT/Lincoln stack. The model's choice to punt rather than commit on the LARIAT entries is exactly the discipline we want. Two random evidence records both clean. The HUMAN_REVIEW terminal is an R_05 artifact; the injection quarantine is a feature, not a defect. Re-run under patched R_05 expected to commit findings 1 (high) and surface 2/3 to the human as ambiguous.
