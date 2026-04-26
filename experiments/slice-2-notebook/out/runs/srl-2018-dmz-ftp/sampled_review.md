# Sampled review - srl-2018-dmz-ftp

**Reviewer:** charan.bobby@gmail.com (with Claude Opus 4.7)
**Reviewed at:** 2026-04-26
**Run:** srl-2018-dmz-ftp-001 (latest at review time)
**Sampling rate:** all findings (2 total) + 2 random evidence records (Python `random.seed(20260426)`)
**Pipeline terminal:** HUMAN_REVIEW

## What this is

This case has no full ground truth, so we cannot compute precision or recall. This document is a lightweight spot-check: are the findings plausible, do the cited evidence records exist, do a couple of random evidence records hold up? Research artifact, not a deployment-readiness claim.

## Important context: pre-fix R_05 escalation

`06_critic_disagreements.jsonl` shows both findings escalated under R_05 (`EXCERPT_HALLUCINATION`). This was the pre-`90d4ffd` normalize bug — the excerpts are real, the old comparison was over-strict on whitespace and quotes. The HUMAN_REVIEW terminal is an artifact, not a quality signal. The regression-gate re-run will confirm.

## Finding-level review

### Finding 1: PSEXESVC service residue
- **Cited binary:** `%SystemRoot%\PSEXESVC.exe`, Manual start, Own_Process
- **Classification:** `requires_disambiguation` (medium confidence)
- **MITRE:** T1543.003
- **Cited evidence:** tool_call_id `81f1a4c5` (verified present)
- **Verdict:** PLAUSIBLE classification choice
- **Why:** `PSEXESVC` is the service Sysinternals PsExec installs on the target host when it runs. PsExec is dual-use — the same binary appears in both red-team toolkits (lateral movement, remote command execution) and blue-team triage (KAPE/F-Response deployment, ad-hoc remote shell). On a DMZ FTP server under active compromise investigation, both stories are plausible without timeline correlation. The model correctly raises both alternatives and refuses to commit. The `Manual` start type (does not self-persist across reboots) and 2018-09-04 last-write date (post-compromise window) are correctly noted as additional signals. Good honest reasoning.

### Finding 2: IFEO Debugger value set to cmd.exe
- **Cited value:** `C:\Windows\System32\cmd.exe` under `Image File Execution Options`
- **Classification:** `requires_disambiguation` (medium confidence)
- **MITRE:** T1546.012 (IFEO Injection)
- **Cited evidence:** tool_call_id `b3ff0257` (verified present — and matches one of our random samples below)
- **Verdict:** PLAUSIBLE classification choice, with a recoverable gap
- **Why:** A `Debugger=cmd.exe` IFEO entry is the exact pattern of the classic sticky-keys / utilman backdoor (T1546.008/T1546.012). Whether it's malicious depends entirely on the *child key name* (i.e., which target executable is being hijacked). The structured fields here only carry the parent IFEO key path, not the child key. The model honestly flags that gap and refuses to commit to TP. Recommended follow-up: re-run regripper with deeper recursion or run a custom plugin to dump the full IFEO subkey tree. This is a genuine plan-level limitation worth feeding back to PLAN's prompt.

## Evidence record spot-check (2 of 20, seed 20260426)

### Record A - line 11: tool_call_id `cb7115f6`
- **Tool family:** `regripper_run` (plugin: `appinitdlls`)
- **What it ran:** Dumped the AppInit_DLLs registry subtree from the Software hive
- **Plausibility:** OK
- **Result:** Clean — `AppInit_DLLs` is blank, `LoadAppInit_DLLs=0`, `RequireSignedAppInit_DLLs=1`. No AppInit hijack present. `injection_flags=[]`.
- **Notes:** This is a *negative finding* — the model correctly did not surface anything from this record. Good behavior: the executor ran the check, the output was clean, the analyst stayed silent. (A common LLM failure mode is to "find something to say" about every tool output; this record demonstrates the discipline holds.)

### Record B - line 12: tool_call_id `b3ff0257`
- **Tool family:** `regripper_run` (plugin: `imagefile`)
- **What it ran:** Dumped IFEO entries from the Software hive
- **Plausibility:** OK
- **Result:** Found `Debugger=cmd.exe` under the IFEO parent key (this is the record cited by finding 2 above)
- **Notes:** Cross-reference confirms — the citation in finding 2 is real and traceable. The structured field carries `last_write: null` and only the parent key path, which is exactly the gap finding 2 calls out.

## Conclusion

Two findings, both correctly classified as `requires_disambiguation`. Model handled the dual-use ambiguity (PsExec, IFEO) honestly rather than committing to TPs it could not defend. Two random evidence records both clean: one is a negative-finding case (model correctly stayed silent), the other corroborates finding 2's citation chain. The HUMAN_REVIEW terminal is an R_05 artifact. Re-run under patched R_05 expected to surface both findings to the human as ambiguous (which is the correct end-state for both). Independent follow-up: harden regripper IFEO plugin to enumerate child keys so finding 2 can resolve to TP/FP in future runs.
