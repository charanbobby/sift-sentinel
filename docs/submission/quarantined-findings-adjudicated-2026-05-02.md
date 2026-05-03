---
created: 2026-05-02
purpose: Human adjudication record for dual-channel runs whose terminal status was QUARANTINED due to a false-positive injection-scanner trip on the literal MITRE token "T1033" present in raw SOFTWARE registry hive bytes. The findings underneath those runs are sound; the critic agreed with them (passed all 17 rules in most cases). This document records the adjudication so the submission can rely on them.
human_adjudicated_by: charan.bobby
human_adjudicated_at: 2026-05-02
---

# Quarantined-but-real findings, adjudicated

## Why this document exists

Three dual-channel runs from the 2026-05-02 dual sweep ended with `07_terminal.QUARANTINED`. The cause was the injection scanner pattern `INJ_ATTCK_EMIT` matching the literal byte sequence `T1033` inside the raw SOFTWARE registry hive content. `T1033` is a legitimate MITRE ATT&CK technique ID (System Owner / User Discovery) and naturally appears as registry data in some hive structures (regripper plugin banners, internal Microsoft product strings, etc.). The scanner treated it as if the attacker-controlled data was trying to inject a MITRE technique label into the analysis LLM output.

The recalibration plan from 2026-04-26 (`INJ_BASE64_LONG` decode-then-scan, full edge-case taxonomy, probe gates) is the real fix. It is not yet shipped. Until it is, runs that touch the SOFTWARE hive on hosts where these byte sequences appear will keep tripping the gate.

The findings inside the quarantined runs were:

- Reviewed by the LangGraph critic node and tagged `severity=escalate` with `strategy=human_review`.
- Cite specific evidence anchors (excerpt sha256s, tool_call_ids).
- Passed all 17 critic rules in the rd-02 cases; passed all rules except R_03 / R_08 tool-mismatch in one rd-01 case (a critic-rule gap, not a finding problem).

This document is the human-adjudication step. Each finding below is recorded as `human_adjudicated=true` with its evidence anchor and the reason the quarantine should not block its inclusion in the submission.

## rd-01 (case `srl-2018-base-rd-01-dual`, run `srl-2018-base-rd-01-dual-003`)

Source: `experiments/slice-2-notebook/out/runs/srl-2018-base-rd-01-dual/srl-2018-base-rd-01-dual-003/`

### Finding 1: process_injection in c:\windows\temp\perfmon\p.exe

- value: `c:\windows\temp\perfmon\p.exe (PID 8260), PAGE_EXECUTE_READWRITE with cmd.exe spawn chain`
- classification: `process_injection` (memory-channel finding, NOT_FOUND category per schema)
- confidence: high
- attack: T1055 (Process Injection) / TA0005 (Defense Evasion)
- evidence anchors:
  - tool_call_id `e43e7b2c-aedc-43cb-9c1b-7ec67c6af2ee`, malfind hit at PID 8260 address 0x2be0000, vad_tag VadS, protection PAGE_EXECUTE_READWRITE
  - tool_call_id `29f31719-0145-4ce4-88cd-c99abe7f2f96`, pslist showing cmd.exe (PID 5948) spawn `cmd.exe /C c:\windows\temp\perfmon\p.exe`
  - tool_call_id `29f31719-0145-4ce4-88cd-c99abe7f2f96`, pslist showing p.exe (PID 8260) running
- excerpt sha256: `49dacf2db63a39e0d9d775f310088d516292f2e80aa8a6f613b3d8c9cdf35d53`, `a0452126913e62bc50fc5ffce6a19216aadf0913666362c34af43c1c7b93b39a`, `f09c92c9b06eedcdd96bdf341e98a649c5fd0c3d3cf9fe1f74d720dc3f952bef`
- critic outcome: passed all 17 rules; `severity=escalate` because the run's terminal was QUARANTINED
- adjudication: ACCEPT. The binary name `p.exe` in a subdirectory `perfmon` under Windows Temp is a documented masquerading pattern. p.exe is not a JIT runtime, so the PAGE_EXECUTE_READWRITE allocation is not legitimate JIT compilation. Spawn chain via cmd.exe confirms execution. No vendor signature.

### Finding 2: scheduled_task at C:\Windows\Temp\1.bat

- value: `C:\Windows\Temp\1.bat`
- classification: `attacker_persistence` / `scheduled_task`
- confidence: high
- attack: T1053.005 (Scheduled Task) / TA0003 (Persistence)
- evidence anchors:
  - tool_call_id `ce4c3c22-601e-452f-ba9b-b1a24685e60d`, scheduled_tasks_parse output: task_name `\Collect Background Statistics`, author `shieldbase\spsql`, trigger TimeTrigger, action_command `C:\Windows\Temp\1.bat`
- excerpt sha256: `2f97ab28d35f7ba30b561b4f4e6f29f3db1d6da1a8304da50b249254a0af26b6`
- critic outcome: failed R_03 (`TOOL_MISMATCH`: scheduled_task category requires fls_list / icat_extract) and R_08 (`CONF_OVERSTATED`: high-confidence finding does not cite a primary tool); passed the other 15 rules
- adjudication: ACCEPT. The R_03 / R_08 failure is a critic-rule gap. `scheduled_tasks_parse` is the canonical primary tool for scheduled-task evidence and chains icat + parse server-side; the rule predates that tool's introduction. The finding's substance (SQL service account authoring a batch file in Windows Temp under a legit-looking task name) is solid attacker-persistence evidence on its merits.
- followup task: update critic R_03 to recognize `scheduled_tasks_parse` as a primary tool for `scheduled_task` category. Tracked separately.

## rd-02 (case `srl-2018-base-rd-02-dual`)

Two runs, same findings:
- `srl-2018-base-rd-02-dual-001/`
- `srl-2018-base-rd-02-dual-002/`

The duplication confirms reproducibility across runs.

### Finding 3: service "Microsoft Advanced API 32"

- value: `C:\Program Files (x86)\Microsoft Advanced API 32\msadvapi2_32.exe`
- classification: `attacker_persistence` / `service`
- confidence: high
- attack: T1543.003 (Windows Service) / TA0003 (Persistence)
- evidence anchors (from rd-02-dual-002):
  - tool_call_id `3f7dcb35-8b1b-4222-9aca-e8631047f8f5`, regripper services output: `ControlSet001\Services\Microsoft Advanced API 32`, ImagePath `C:\Program Files (x86)\Microsoft Advanced API 32\msadvapi2_32.exe`, Type Own_Process, Start Auto Start
  - tool_call_id `79f5484f-9a1c-419d-b640-e065199c71ee`, pslist showing msadvapi2_32.e (PID 2292) running with command line matching the ImagePath
- excerpt sha256: `dc2387a57e904b1d04f82bbb1b7de9424d1648f5f9622409d69d8d4ed0525eb7`, `e6d79235f0baa5602adc560b219dc5bd5f72eb579a8850badfb0808aa4ae00ab`
- critic outcome: passed all 17 rules; `severity=escalate` due to QUARANTINED run terminal
- adjudication: ACCEPT. Service name mimics Microsoft branding but no Microsoft service named "Microsoft Advanced API" exists. Path is non-standard. Auto-Start. Confirmed running in memory. Masquerading counter-rule applies.

### Finding 4: service "Microsoft Advanced API 64"

- value: `C:\Program Files (x86)\Microsoft Advanced API 64\msadvapi2_64.exe`
- classification: `attacker_persistence` / `service`
- confidence: high
- attack: T1543.003 / TA0003
- evidence anchors (from rd-02-dual-002):
  - tool_call_id `3f7dcb35-8b1b-4222-9aca-e8631047f8f5`, regripper services output: `ControlSet001\Services\Microsoft Advanced API 64`, ImagePath `C:\Program Files (x86)\Microsoft Advanced API 64\msadvapi2_64.exe`, Type Own_Process, Start Auto Start
  - tool_call_id `79f5484f-9a1c-419d-b640-e065199c71ee`, pslist showing msadvapi2_64.e (PID 2328) running
- excerpt sha256: `2effe947c00ba0f4a03ef616c64f94665218edd3741da6d3e05385f44abf376f`, `80522482fb566e0e7cad3f7c7d725ff5bcd47ca226e353eb35c549d24ad2ab09`
- critic outcome: passed all 17 rules; `severity=escalate` due to QUARANTINED run terminal
- adjudication: ACCEPT. Companion to Finding 3. Internal contradiction (64-bit binary under `Program Files (x86)`) further indicates attacker-crafted naming. Dual 32/64 architecture pair is consistent with a backdoor or C2 agent designed to run on both arch sets.

## What this means for the submission

These four findings should be cited in the submission alongside the SUCCESS-terminal findings from the same sweep. Cross-host context:

- rd-01 and rd-02 are both classified compromised with high-confidence anchors.
- The "Microsoft Advanced API" 32 / 64 pair on rd-02 matches the file-server findings cited in `docs/submission/cross-host-escalations-2026-05-02.md` (same family / same campaign).
- The p.exe perfmon-masquerade on rd-01 matches the `perfmon_masquerading` baseline finding the daily-loop regression confirms.

## What this document does NOT do

It does NOT bypass the QUARANTINED terminal marker on the run dirs themselves. The marker stays in place as the audit-trail record that the injection scanner fired. The findings are adjudicated as human-validated additions on top of that audit trail. The integrity ledger for those runs is unchanged.

## Rescan-after-approval results

After this document was drafted, `scripts/rescan_after_approval.py` was added to the repo and run on all three quarantined dirs. It sets `HUMAN_APPROVED_QUARANTINE_OVERRIDE=1`, rebuilds the INTERPRET bundle with the previously-stripped evidence promoted back to visible, and re-runs INTERPRET once. Output goes to `05b_interpret_findings_post_approval.json` next to the original quarantined run dir, and a `07_terminal.HUMAN_APPROVED` marker is written. The original `07_terminal.QUARANTINED` marker stays in place.

### What the LLM surfaced once it could see the full evidence

**rd-01-dual-003 rescan** (4 findings, $0.42 cost):
- `attacker_persistence` / `scheduled_task` :: `C:\Windows\Temp\1.bat` (HIGH)
- `process_injection` / `NOT_FOUND` :: `powershell.exe PID 8712`, multiple PAGE_EXECUTE_READWRITE regions (HIGH)
- `c2_beacon` / `NOT_FOUND` :: ESTABLISHED TCP from `172.16.6.11` to `172.16.4.10:8080` (MEDIUM). Matches the cross-host C2 pattern documented in `cross-host-escalations-2026-05-02.md`.
- `requires_disambiguation` / `NOT_FOUND` :: OUTLOOK.EXE PID 8128 PAGE_EXECUTE_READWRITE (MEDIUM, JIT vs. injection)

The rescan reinterpreted the process injection finding from p.exe PID 8260 (the original critic_disagreement record) to powershell.exe PID 8712 because the larger bundle gave the LLM more competing signals to weigh. The p.exe-perfmon-masquerading anchor still stands as a distinct artifact and should be cited from the original critic_disagreements record.

**rd-02-dual-001 rescan** (5 findings, $0.42 cost):
- `attacker_persistence` / `service` :: Microsoft Advanced API 32 (HIGH, matches Finding 3 above)
- `attacker_persistence` / `service` :: Microsoft Advanced API 64 (HIGH, matches Finding 4 above)
- `legitimate_responder_tool` / `NOT_FOUND` :: `Mnemosyne.sys` (correctly classified as DFIR)
- `legitimate_responder_tool` / `NOT_FOUND` :: F-Response (`subject_srv.exe -s base-hunt.shieldbase.lan:5682`, correctly classified as DFIR)
- `process_injection` / `NOT_FOUND` :: `powershell.exe PID 6524`, shellcode at `0x77d0000`, PEB-walk / ROR-0xd hash pattern (HIGH). This is a documented Cobalt Strike / Metasploit shellcode signature. **Was hidden by the quarantine.**

**rd-02-dual-002 rescan** (3 findings, $0.39 cost):
- Same Microsoft Advanced API 32/64 pair (HIGH).
- Same `powershell.exe PID 6524` shellcode finding as rd-02-dual-001 (HIGH). Reproduced across two independent runs of the same case, which strengthens confidence.

### Summary of rescan-recovered findings

The rescans surfaced these findings that the quarantine had hidden from the LLM:
1. PowerShell PID 6524 shellcode with PEB-walk / ROR-0xd hash pattern on rd-02 (Cobalt Strike / Metasploit signature). Reproduced across rd-02-dual-001 and rd-02-dual-002.
2. PowerShell PID 8712 multiple PAGE_EXECUTE_READWRITE regions on rd-01.
3. C2 beacon from rd-01 (172.16.6.11) to 172.16.4.10:8080. Matches the dc / file / wkstn cross-host pattern, makes rd-01 a 4th host with the same C2 anchor.
4. Outlook.exe PID 8128 anomaly on rd-01 (medium, requires_disambiguation).
5. Two DFIR tools (Mnemosyne, F-Response) correctly classified as legitimate on rd-02 (false-positive suppression).

Total rescan cost: $1.20 across 3 runs. Per-host budget ceiling never tripped.

## Followup (tracked separately, not blocking submission)

1. Land the injection-guard recalibration so future runs do not quarantine on raw hive bytes containing technique-ID literals.
2. Update critic rule R_03 / R_08 to recognize `scheduled_tasks_parse` as a primary tool for `scheduled_task` category.
3. Investigate why rd-01-dual-003 rescan reinterpreted the process_injection from p.exe to powershell.exe. Both anchors are real; consider whether INTERPRET should emit both as separate findings on the same host.

End of adjudication.
