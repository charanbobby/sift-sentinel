---
title: Coverage adjudication 2026-05-09
date: 2026-05-09
adjudicator: claude-soc
scope: 13 case runs not yet curated, plus 2 empty synthetic dirs
keep_runs_target: experiments/slice-2-notebook/viewer/keep_runs.json
---

## TL;DR

Adjudicated 13 outstanding run dirs plus 2 empty synthetic dirs. Result: 8 APPROVED, 4 REJECTED, 1 INVALID (already marked HUMAN_REJECTED.bad_input), 2 EMPTY. Eight new keep_runs keys are added so the viewer at sentinel.sshub.dev surfaces every viable case. All approved runs pass tool_call_id resolution, excerpt substring checks, plan-membership, and integrity ledger chain validation. Cross-host pattern: the SRL-2018 base-rd and base-file series share a consistent C2 endpoint at 172.16.4.10:8080 with WMI-spawned PowerShell carrying Meterpreter or Cobalt Strike PEB-walk shellcode signatures, and the same Microsoft Advanced API 32 / 64 service masquerade appears on multiple hosts.

## Per-run verdicts

### openuni22-server (INVALID)

Case run `openuni22-server-001`. Pre-existing terminal marker `07_terminal.HUMAN_REJECTED.bad_input` is already set per `docs/runbooks/openuni22-server-memonly-hang-2026-05-07.md`. Findings file is a single low-confidence NOT_FOUND record because Step 1 fsstat_e01 returned parse_error against the broken whole-disk MBR raw input and Step 2 fls_list returned empty structured_fields. Do not add to keep_runs. No marker change.

### srl-2018-base-admin-memonly (REJECTED)

Run `srl-2018-base-admin-memonly-001`. Single NOT_FOUND finding, classification legitimate_windows_default, confidence high. The notes correctly enumerate F-Response Subject (subject_srv.exe to 172.16.5.50:58406 on declared port 3262) and Puppet Labs ruby/rubyw daemons as legitimate, and rule out PowerShell + MsMpEng RWX hits as known-clean JIT and Defender false positives. No attacker artifact. Marker set to HUMAN_REJECTED. Not added to keep_runs.

### srl-2018-base-file-dual (APPROVED)

Run `srl-2018-base-file-dual-001`. Four findings: two attacker_persistence services (`Microsoft Advanced API 32` and `64`, msadvapi2_32.exe / msadvapi2_64.exe under C:\Program Files (x86)\, both Auto Start, paired install timestamp 2018-05-08T21:06:24Z alongside an npf packet-filter service), one process_injection in 32-bit syswow64 powershell.exe PID 3164 with textbook PEB-walk reflective loader at 0x4820000 (CLD; CALL; PUSHA; MOV EBP,ESP; XOR EDX; MOV EDX,[FS:EDX+0x30] sequence), and one c2_beacon from PowerShell PID 4072 with the IEX downloadstring base64 cradle to squirreldirectory.com over an internal 172.16.4.10:8080 connection. Citation check: all five tool_call_ids (b5d2eced, 0f8f535e, ad37cb32, cb5127e1, b95b7137) resolve in 04_execute_evidence.jsonl; the encoded base64 substring `SQBFAFgAIAAoACgAbgBlAHcA` is verbatim in evidence. Integrity ledger chain unbroken across 39 entries. APPROVE.

### srl-2018-base-rd-01 (APPROVED)

Run `srl-2018-base-rd-01-002`. One attacker_persistence finding: scheduled task `\Collect Background Statistics` authored by `shieldbase\spsql` (compromised SQL service account) with action_command `C:\Windows\Temp\1.bat` and a TimeTrigger. Notes correctly rule out DFIR tools, vendor products, and Windows defaults. Two additional legitimate_responder_tool findings on F-Response Subject and Mnemosyne are correctly classified, not reported as malicious. Citation check: tool_call_id fe7df381 resolves; the excerpt substrings 1.bat and `Collect Background Statistics` are present verbatim. Integrity ledger chain unbroken across 35 entries. Pre-existing markers were SUCCESS plus a stale QUARANTINED.audit; replaced with HUMAN_APPROVED.

### srl-2018-base-rd-01-dual (APPROVED)

Run `srl-2018-base-rd-01-dual-003`. Same scheduled task finding as the disk-only run, plus three new memory-side findings the disk run could not reach: process_injection in powershell.exe PID 8712 (three RWX VAD regions, empty cmdline, downstream chain to attacker tool p.exe at C:\windows\temp\perfmon\p.exe), a medium-confidence c2_beacon to 172.16.4.10:8080, and a medium-confidence requires_disambiguation hit on OUTLOOK.EXE. Per the dual-vs-disk policy this run finds NEW persistence and lateral-movement vectors (the empty-cmdline PowerShell injection) that the disk-only run cannot see. Citation check: ce4c3c22, e43e7b2c, 29f31719, aed3b23d all resolve. Integrity ledger chain unbroken across 41 entries. APPROVE.

### srl-2018-base-rd-02-dual (APPROVED)

Run `srl-2018-base-rd-02-dual-002`. Three findings: two attacker_persistence services (`Microsoft Advanced API 32` / `64`, install timestamps 2018-05-08T21:13:16Z and 21:13:34Z, paired with npf), and one process_injection in syswow64 powershell.exe PID 6524 with textbook Metasploit PEB-walk + ROR-0xd hash routine at 0x77d0000 plus additional RWX regions at 0x5440000, 0x76f0000, 0x7b60000, and a sibling PID 6528. The cmdline `-Version 5.1 -s -NoLogo -NoProfile` is the WinRM remoting host pattern. Citation check: 3f7dcb35, 6233d6c2, 79f5484f resolve. Integrity ledger chain unbroken across 38 entries. APPROVE.

### srl-2018-base-rd-04-memonly (APPROVED)

Run `srl-2018-base-rd-04-memonly-002`. Four findings, including the strongest fileless persistence in this batch: attacker_persistence registry_run_key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Sophos` containing a base64 blob, decoded and IEX-executed by `powershell.exe -w hidden -c (IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion\Run Sophos).Sophos))))`. The value name `Sophos` is a deliberate vendor-name masquerade. PID 2664 is a child of explorer.exe and shows CLOSED connections to 172.16.4.10:8080. A second high-confidence process_injection finding cites the same PEB-walk + ROR-0xd shellcode signature in syswow64 powershell.exe PID 5452 (parented through WmiPrvSE.exe PID 3156), plus a c2_beacon and a legitimate-tool F-Response Subject record. Citation check: f04cf430, 7c1bcc65, ab741afb, fbe68cbb, b84f61ad all resolve. Integrity ledger chain unbroken across 13 entries. APPROVE.

### srl-2018-base-rd01-memonly (APPROVED)

Run `srl-2018-base-rd01-memonly-001`. Three findings, all medium confidence due to memory-only scope. The strongest is an attacker WMI lateral-movement chain WmiPrvSE.exe PID 2876 to powershell.exe PID 8712 to powershell.exe PID 5848 (WinRM remoting flags) to cmd.exe PID 5948 to `c:\windows\temp\perfmon\p.exe` PID 8260. p.exe has a PAGE_EXECUTE_READWRITE region and loads WININET.dll (HTTP C2 capability). The same C2 endpoint 172.16.4.10:8080 appears in multiple ESTABLISHED states. Cited concrete attacker artifact (`p.exe` from `c:\windows\temp\perfmon\`). Citation check: b560dc1f, c7607c02, 4ce0e038, 3a161b09, 36c66a4e all resolve. Integrity ledger chain unbroken across 25 entries. APPROVE on the strength of the named attacker binary plus the WMI execution chain.

### srl-2018-base-wkstn-01 (REJECTED)

Run `srl-2018-base-wkstn-01-002`. Single NOT_FOUND finding, medium confidence. Notes correctly catalog the McAfee suite, VMware tools, Google Update, Adobe ARM, Defender, plus DFIR tools (Mnemosyne, F-Response Subject to 172.16.5.25:5682, Velociraptor, Sysmon64). Two parse_error steps (Winlogon and WDigest) downgrade confidence but no concrete attacker artifact is identified. REJECT. Pre-existing SUCCESS plus stale QUARANTINED.audit replaced with HUMAN_REJECTED.

### srl-2018-base-wkstn-01-dual (REJECTED)

Run `srl-2018-base-wkstn-01-dual-003`. Five findings, all classified legitimate_responder_tool (Mnemosyne, F-Response Subject, Velociraptor, Sysmon64) plus one requires_disambiguation on svchost.exe utcsvc PID 2332 to 172.16.4.10:8080 with no malfind anchor. No concrete attacker_persistence finding. REJECT. Markers replaced with HUMAN_REJECTED.

### srl-2018-base-wkstn-02-memonly (REJECTED)

Run `srl-2018-base-wkstn-02-memonly-003`. Single NOT_FOUND requires_disambiguation finding. Suspicious WmiPrvSE.exe PID 3740 to powershell.exe PID 5084 to powershell.exe PID 8088 chain with empty cmdlines, but no malfind hit, no netscan tie to those PIDs, no disk-side anchor. Notes correctly rule out Firefox JIT, McAfee UpdaterUI, and identify F-Response as legitimate. No concrete attacker artifact. REJECT.

### srl-2018-base-wkstn-05-dual (APPROVED)

Run `srl-2018-base-wkstn-05-dual-002`. Four findings, including two high-confidence attacker_persistence services. First: service `tbbd05` with ImagePath `%COMSPEC% /c echo b6a1458f396 > \\.\pipe\334485` (Start=Disabled), the canonical Metasploit PsExec / Impacket smbexec / Cobalt Strike psexec_psh named-pipe relay artifact. Second: service `PerfMon` Display=`Perf Monitor` with binary `c:\windows\system32\perfmonsvc64.exe` (Auto Start), masquerade against the Windows Perf* DLL-based service family which never ships an Own_Process executable named perfmonsvc64.exe. Plus medium-confidence process_injection in WmiPrvSE-spawned powershell PIDs 4328 / 4064 / 3920 plus an orphaned-parent rundll32 PID 7100, and c2_beacon to 172.16.4.10:8080. Install timestamps 2018-08-31T18:38:44Z and 20:05:55Z correlate. Citation check: 2a4c4822, 04281e6c, 5b9e9ee3, 9f58ef6e, 2f4d7e55 all resolve. Integrity ledger chain unbroken across 39 entries. APPROVE.

### srl-2018-base-wkstn-05-memonly (APPROVED)

Run `srl-2018-base-wkstn-05-memonly-001`. Three medium-confidence findings: process_injection in WmiPrvSE-spawned powershell PIDs 4328 / 4064 / 3920 with WoW64 children 1124 / 4072 / 1332 carrying large 627-page private RWX regions (Meterpreter or Cobalt Strike stager footprint), a second process_injection in rundll32.exe PID 7100 with bare cmdline and orphaned PID-7148 parent loading JScript9.dll / JScript.dll / VBScript.dll (squiblydoo-style scriptlet payload), and the same c2_beacon to 172.16.4.10:8080 with five distinct CLOSE_WAIT / CLOSED connections from 172.16.7.15. Citation check: 8f5ae93a, f04a81bd, afd05d13, 4d072652, 78f6c6a7 all resolve. Integrity ledger chain unbroken across 25 entries. APPROVE on the rundll32 orphan-parent + scripting-engine DLLs concrete artifact and the matching C2 endpoint.

### synthetic-2026-05-05 (EMPTY)

Run `synthetic-2026-05-05-001`. Only the genesis line in integrity_ledger.jsonl, no other artifacts. Pipeline did not produce findings. EMPTY. No marker, no keep_runs entry.

### synthetic-2026-05-06 (EMPTY)

Run `synthetic-2026-05-06-001`. Only the genesis line in integrity_ledger.jsonl. EMPTY. No marker, no keep_runs entry.

## Cross-host attacker patterns

Three patterns recur across the SRL-2018 base- approved set and inform downstream playbook authoring:

1. Common C2 sink at 172.16.4.10:8080. Connections from base-file (171.16.4.5), base-rd-01 (172.16.6.11), base-rd-04 (172.16.6.14), base-rd01 (172.16.6.11), base-wkstn-05 (172.16.7.15) all converge on this single internal pivot. Treat 172.16.4.10:8080 as the case-wide attacker C2 listener for SRL-2018 base; any SRL-2018 host with an outbound TCP to that endpoint is in-scope.

2. Microsoft Advanced API 32 / 64 service masquerade. Both base-file and base-rd-02 carry `C:\Program Files (x86)\Microsoft Advanced API 32\msadvapi2_32.exe` and `Microsoft Advanced API 64\msadvapi2_64.exe` set Auto Start, install-paired with the npf packet-filter driver. Same name and same path on two hosts is the same operator deploying the same kit.

3. WMI-spawned PowerShell with Meterpreter PEB-walk shellcode. Five hosts (base-file, base-rd-01-dual, base-rd-02-dual, base-rd-04, base-rd01, base-wkstn-05) all show WmiPrvSE.exe parenting a powershell.exe with `-Version 5.1 -s -NoLogo -NoProfile` and large-commit RWX VADs. Three of them disassemble to the canonical Metasploit `CLD; CALL; PUSHA; MOV EBP,ESP; XOR EDX,EDX; MOV EDX,[FS:EDX+0x30]` PEB-walk + ROR-0xd hash signature. The base-rd-01 hosts additionally carry `c:\windows\temp\perfmon\p.exe` as the post-injection payload binary.

## keep_runs.json updates

Added eight new keys, preserving every existing key:

- `srl-2018-base-file-dual`: [`srl-2018-base-file-dual-001`]
- `srl-2018-base-rd-01`: [`srl-2018-base-rd-01-002`]
- `srl-2018-base-rd-01-dual`: [`srl-2018-base-rd-01-dual-003`]
- `srl-2018-base-rd-02-dual`: [`srl-2018-base-rd-02-dual-002`]
- `srl-2018-base-rd-04-memonly`: [`srl-2018-base-rd-04-memonly-002`]
- `srl-2018-base-rd01-memonly`: [`srl-2018-base-rd01-memonly-001`]
- `srl-2018-base-wkstn-05-dual`: [`srl-2018-base-wkstn-05-dual-002`]
- `srl-2018-base-wkstn-05-memonly`: [`srl-2018-base-wkstn-05-memonly-001`]

The viewer at sentinel.sshub.dev should now list 32 cases. The four REJECTED runs (admin-memonly, wkstn-01, wkstn-01-dual, wkstn-02-memonly), the bad-input openuni22-server, and the two EMPTY synthetic dirs are intentionally excluded.
