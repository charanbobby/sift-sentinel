---
created: 2026-05-09
adjudicator: Claude under SOC delegation per memory/feedback_soc_authority.md
status: closed
hosts: srl-2015-xp-tdungan, srl-2015-win7-32-nromanoff, srl-2015-win7-64-nfury, srl-2015-win2008R2-dc, hadi3-win81-challenge3
---

# SRL-2015 + Hadi3 bulk adjudication brief, 2026-05-09

## TL;DR

Three of four SRL-2015 hosts produced findings consistent with a single attacker intrusion across the network. The XP host (tdungan), Win7 32-bit host (nromanoff), and the Win2008R2 domain controller all flag malicious persistence; XP and Win7-32 share the EXACT same Run key value (`c:\windows\system32\dllhost\svchost.exe`), and the DC has an anonymous time-trigger scheduled task running `cmd /c c:\windows\system32\spinlock.exe`. All three are TP under the masquerading + metadata-anomaly counter rules. Hadi3 negative-case results pending. Two QUARANTINED terminals were caused by the same `INJ_ATTCK_EMIT` injection-scanner false positive (regf binary bytes accidentally matching `t\d{4}` ATT&CK ID pattern).

## Per-host verdicts

### srl-2015-xp-tdungan-001

- Verdict: TP, HUMAN_APPROVED.
- Finding: registry_run_key `c:\windows\system32\dllhost\svchost.exe` (T1547.001).
- Cost: $0.28.
- Notes: textbook masquerading. The legitimate svchost.exe is at System32 root, not under a fabricated dllhost subdirectory. Other Run entries (McAfee, Adobe, VMware Tools, Java, Skype) are clean. Detail in `docs/submission/adjudication-srl-2015-xp-tdungan-001.md`.
- Critic: 17/17 deterministic rules passed. INJECTION_QUARANTINE on `INJ_ATTCK_EMIT` was a false positive on raw regf hive bytes; not a finding-level issue.
- Planner OS-version drift: PLAN used Win7+ paths (System32\Tasks, Users\Administrator) on XP. Pipeline still recovered via the Run-key check. Logged as a planner-tuning candidate.

### srl-2015-win7-32-nromanoff-001

- Verdict: TP, terminal already SUCCESS.
- Finding: registry_run_key `c:\windows\system32\dllhost\svchost.exe` (T1547.001).
- Cost: $0.34.
- Notes: same masquerading value as the XP host. This is strong cross-host corroboration: same attacker artifact appearing on two Windows hosts in the same SRL-2015 network. All other persistence vectors checked clean (IFEO empty, AppInit blank, scheduled tasks clean, user Run only Skype).
- Critic: clean, no injection flags this time. Plan reached step 33 of 35 before halting at the inetpub inode (Win7-32 has no IIS).

### srl-2015-win7-64-nfury-001

- Verdict: TP, HUMAN_APPROVED.
- Findings (3): one HIGH and two MEDIUM, all TP.
  - HIGH registry_run_key `c:\windows\system32\dllhost\svchost.exe` (T1547.001): the SAME masquerade value as XP and Win7-32. Three-host corroboration of the same attacker-planted Run key.
  - MEDIUM scheduled_task `cmd /c c:\windows\system32\dllhost\svchost.exe` (T1053.005): redundant persistence pointing at the SAME masqueraded binary as Run key finding above. Designed to survive partial remediation.
  - MEDIUM scheduled_task `cmd /c c:\windows\system32\spinlock.exe` (T1053.005): SAME spinlock binary as the DC (Win2008R2). Cross-host artifact #2 in the SRL-2015 intrusion.
- Cost: $0.70 (one debounce/plan iteration; pipeline retried after the first plan halted at inetpub).
- Critic: 17/17 rules passed on all 3 findings. Terminal HUMAN_REVIEW was the auto-escalate triggered by the 3-finding count, not by any rule fail.
- Notes: this host carries both attacker artifacts found elsewhere in the network (the masqueraded svchost from XP/Win7-32 AND the spinlock task from the DC). Strongest single-host evidence in the dataset.

### srl-2015-win2008R2-dc-001

- Verdict: TP, HUMAN_APPROVED (renamed from QUARANTINED).
- Finding: scheduled_task `cmd /c c:\windows\system32\spinlock.exe` (T1053.005).
- Cost: $0.34.
- Notes: anonymous task (no author or description metadata, atypical for legitimate Windows or vendor tasks; all benchmark-legitimate tasks parsed in steps 17 to 25 carry `$(@%systemRoot%\\...dll,-NNNN)` author strings) with a TimeTrigger and enabled state. The binary `spinlock.exe` is not in any documented Windows binary inventory. Reasonable concerns: Sysinternals previously distributed a `Spinlock` debugger sample, but Sysinternals binaries are signed and would not be invoked anonymously via cmd /c from a domain controller's scheduled task surface.
- Critic: 17/17 rules passed. Same `INJ_ATTCK_EMIT` injection scanner FP as XP. Renamed terminal marker accordingly.

### hadi3-win81-challenge3-001

- Verdict: APPROVED as a successful negative-case validation.
- Finding: 1 medium NOT_FOUND (the pipeline ran clean and emitted "no persistence found" rather than manufacturing false positives).
- Cost: $0.32.
- Notes: Hadi3 is the published no-persistence Windows 8.1 challenge case (success criterion #6 in `docs/submission/known-limitations.md`: "the Critic isn't rubber-stamping LLM positive-finding bias"). Pipeline behaved correctly: 30 evidence records, 0 false-positive findings, terminal SUCCESS. No QUARANTINED, no INJECTION_FLAGGED. The masquerading counter-rule, IFEO check, AppInit check, scheduled-task surface check, and user-Run-key check all came back clean; the agent did not invent a finding to satisfy a positive-result bias.
- Negative-case discipline confirmed.

## Cross-cutting notes

### INJ_ATTCK_EMIT injection scanner false positive (R_14 candidate)

The injection scanner pattern `INJ_ATTCK_EMIT` is intended to catch adversarial content that emits MITRE ATT&CK technique IDs in tool output (a known prompt-injection trick). The pattern matches `t\d{4}` substrings. On the SRL-2015 hosts this triggered on raw NTFS regf hive bytes where binary noise happened to contain `t1004` and similar substrings. Two QUARANTINED terminals (XP and DC) were caused by this single false-positive class.

Refinement options:
- Require the match in narrative-shaped fields (`notes`, `description`, `comment`), not in `raw` byte arrays.
- Require word boundaries plus surrounding ASCII context.
- Restrict the search to fields whose content type is documented as text (use the EvidenceRecord schema's content-type tag).

This is a candidate for Critic rule R_14 in the post-Slice-6 backlog.

### Cross-host attacker artifact corroboration

Two SRL-2015 hosts (XP and Win7-32) carry the IDENTICAL Run key `svchost -> c:\windows\system32\dllhost\svchost.exe`. This is meaningful: it suggests the attacker pushed the same persistence to multiple endpoints, consistent with a network-wide intrusion (the SRL-2015 case background notes a multi-host breach across the 10.3.58.x subnet). The DC's `spinlock.exe` is a different artifact, possibly post-domain-foothold lateral expansion.

### Planner OS-version drift

XP halted on `inode_by_name(Tasks)` (XP uses WINDOWS\Tasks, not System32\Tasks) and `inode_by_name(Administrator)` (XP uses Documents and Settings\Administrator). Win7-32 halted on `inode_by_name(inetpub)` (no IIS on a workstation). Win2008R2 also halted on `inode_by_name(Administrator)`. The pipeline produced findings anyway because the Registry Run-key + scheduled-task surface succeeded earlier in the plan. Worth a planner-prompt patch: branch on detected OS major version and on detected role (workstation vs server) before proposing IIS or Administrator-profile probes.

## keep_runs.json updates (proposed; deferred until synthetic agent finishes editing)

- `srl-2015-xp-tdungan` -> `["srl-2015-xp-tdungan-001"]`
- `srl-2015-win7-32-nromanoff` -> `["srl-2015-win7-32-nromanoff-001"]`
- `srl-2015-win7-64-nfury` -> pending verdict
- `srl-2015-win2008R2-dc` -> `["srl-2015-win2008R2-dc-001"]`
- `hadi3-win81-challenge3` -> pending verdict (likely add only if findings count is 0 confirming the negative-case discipline)
