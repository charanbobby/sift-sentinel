---
created: 2026-05-02
purpose: Cross-LLM sanity check. Paste this whole document into another LLM (Claude, GPT, Gemini) and ask it to review our findings, classifications, and cross-host inferences.
---

# Second-opinion brief: SRL-2018 dual-channel sweep findings

## Section 0: Question for the reviewing LLM

You are reviewing the output of an autonomous DFIR triage agent that ran across 7 Windows host images from the SANS 2018 hackathon dataset. Each run pulled disk and (where available) memory evidence, and produced a list of findings classified by mechanism (attacker_persistence, process_injection, c2_beacon, legitimate_responder_tool, requires_disambiguation, legitimate_windows_default).

**Specifically, we want your opinion on these five questions:**

1. **Are the classifications correct?** For each finding below, does the classification (attacker_persistence vs requires_disambiguation vs legitimate, etc) match what an experienced incident responder would call it given the evidence shown?
2. **Are the confidence levels calibrated?** Anything we marked HIGH that should be MEDIUM, or vice versa?
3. **Are there cross-host inferences we missed?** Below we surface that four hosts beacon to `172.16.4.10:8080`. Are there other shared indicators across the 7 hosts that should produce a sweep-level finding?
4. **Are there findings we did NOT emit but should have?** Look at the per-host evidence and tell us what an incident responder would also call out that we did not.
5. **Are there false positives?** Anything we flagged that you would un-flag, with reason?

Optional: rank the hosts by likelihood of compromise based on the evidence. We want to compare against our own ranking.

## Section 1: What the system did (one paragraph)

Each run is a four-phase agent pipeline. EXTRACT enumerates candidate forensic artifact locations on a Windows host (registry hives, scheduled tasks, services, file drops, plus memory artifacts when a RAM image is staged). PLAN turns those into a sequence of MCP tool calls (FLS / icat_extract / regripper plugins on disk, Volatility 2 plugins on memory) that follow strict argument-templating rules. EXECUTE runs the plan against an MCP server that owns the disk image and memory dump; each tool call returns an EvidenceRecord with structured fields. INTERPRET reads the structured fields and emits findings against a fixed schema (category, classification, confidence, mechanism, value, evidence, attack_tactic_id, attack_id). A CRITIC pass checks the findings against 16 rules and either accepts, escalates to human review, or asks for a re-plan.

The findings schema permits `category=NOT_FOUND` for memory-class evidence (process injection, C2 beacons) so the agent can surface those even though they are not literally "persistence" in the strict T1547 / T1543 sense. The MITRE tactic field carries the correct tactic (TA0005 / TA0011) when category is NOT_FOUND with a memory classification.

## Section 2: The dataset

SANS 2018 hackathon lab. The lab simulates an enterprise compromise. We have 7 hosts scanned so far:

| Case ID | Role | Local IP | Channels scanned |
|---|---|---|---|
| srl-2018-base-dc-dual | Domain Controller | 172.16.4.4 | disk + memory |
| srl-2018-base-file-dual | File Server | 172.16.4.5 | disk + memory |
| srl-2018-base-rd-01-dual | RDP Gateway / RDS | 172.16.6.11 | disk + memory |
| srl-2018-base-rd-02-dual | RDP Gateway / RDS | 172.16.6.12 | disk + memory |
| srl-2018-base-wkstn-01-dual | Workstation | 172.16.7.11 | disk + memory |
| srl-2018-base-wkstn-05-dual | Workstation | 172.16.7.15 | disk + memory |
| srl-2018-base-wkstn-05-memonly | Workstation (memory-only smoke test) | 172.16.7.15 | memory only |

Outside-confirmed ground truth we have:
- The lab is compromised. At least one host is owned. (Specifically wkstn-01 was confirmed compromised by the dataset owner.)
- We do not have an authoritative finding-by-finding answer key.

## Section 3: Per-host findings, with evidence

For each finding, we list classification, confidence, mechanism, the concrete `value` field (path / IP / PID / cmdline), and the MITRE tactic + technique IDs.

### Host 1: srl-2018-base-dc-dual (Domain Controller, 172.16.4.4)

3 findings. Terminal SUCCESS.

1. `legitimate_responder_tool` (HIGH). Mech: Windows service auto-start (DFIR memory acquisition driver). Value: `\??\C:\windows\Mnemosyne.sys`. MITRE: TA0003 / T1543.003.
2. `legitimate_responder_tool` (HIGH). Mech: Windows service auto-start (DFIR remote forensic agent). Value: `C:\windows\subject_srv.exe -s "base-hunt.shieldbase.lan:5682" -l 3262 -v "F-Response Subject" -k "155522845"`. MITRE: TA0003 / T1543.003.
3. `legitimate_windows_default` (MEDIUM, NOT_FOUND). No attacker persistence on disk.

**Note for reviewer:** Both flagged services are known DFIR (incident response) tools used by the responders, not the attacker. The agent correctly classified them as `legitimate_responder_tool`. The DC is reported clean of attacker persistence by the agent.

### Host 2: srl-2018-base-file-dual (File Server, 172.16.4.5)

4 findings. Terminal SUCCESS.

1. `attacker_persistence` (HIGH). Mech: Windows service auto-start, masquerading as Microsoft API. Value: `C:\Program Files (x86)\Microsoft Advanced API 32\msadvapi2_32.exe`. MITRE: TA0003 / T1543.003.
2. `attacker_persistence` (HIGH). Mech: Windows service auto-start, 64-bit variant of the same masquerade. Value: `C:\Program Files (x86)\Microsoft Advanced API 64\msadvapi2_64.exe`. MITRE: TA0003 / T1543.003.
3. `process_injection` (HIGH, NOT_FOUND). Value: `powershell.exe PID 3164, PAGE_EXECUTE_READWRITE shellcode at 0x4820000 and 0x4a80000`. MITRE: TA0005 / T1055.
4. `c2_beacon` (HIGH, NOT_FOUND). Value: `powershell.exe PID 4072 to 172.16.4.10:8080 (encoded download cradle to squirreldirectory.com)`. MITRE: TA0011 / T1071.

### Host 3: srl-2018-base-rd-01-dual (RDS, 172.16.6.11)

4 findings. Terminal QUARANTINED (an injection-guard rule fired on a tool output containing the literal token `T1033`; this typically appears in regripper banners and is a known false-positive class).

1. `attacker_persistence` (HIGH). Mech: Scheduled task executing batch file from Windows Temp. Value: `C:\Windows\Temp\1.bat`. MITRE: TA0003 / T1053.005.
2. `process_injection` (HIGH, NOT_FOUND). Value: `c:\windows\temp\perfmon\p.exe (PID 8260), PAGE_EXECUTE_READWRITE with cmd.exe spawn chain`. MITRE: TA0005 / T1055.
3. `process_injection` (MEDIUM, NOT_FOUND). Value: `powershell.exe (PID 8712), multiple PAGE_EXECUTE_READWRITE regions, hidden cmdline`. MITRE: TA0005 / T1055.
4. `c2_beacon` (MEDIUM, NOT_FOUND). Value: `172.16.6.11 to 172.16.4.10:8080 (multiple ESTABLISHED/CLOSE_WAIT connections, no named process owner)`. MITRE: TA0011 / T1071.

### Host 4: srl-2018-base-rd-02-dual (RDS, 172.16.6.12)

3 findings. Terminal QUARANTINED (same false-positive class as rd-01).

1. `attacker_persistence` (HIGH). Mech: Windows service auto-start with fake Microsoft name. Value: `C:\Program Files (x86)\Microsoft Advanced API 32\msadvapi2_32.exe`. MITRE: TA0003 / T1543.003.
2. `attacker_persistence` (HIGH). Mech: Windows service auto-start with fake Microsoft name. Value: `C:\Program Files (x86)\Microsoft Advanced API 64\msadvapi2_64.exe`. MITRE: TA0003 / T1543.003.
3. `process_injection` (HIGH, NOT_FOUND). Value: `powershell.exe PID 6524, PAGE_EXECUTE_READWRITE shellcode region at 0x77d0000 (PEB-walking pattern)`. MITRE: TA0005 / T1055.

**Note for reviewer:** Our cross-host aggregator detected that rd-02 has 1 CLOSED netscan record to `172.16.4.10:8080` but did NOT emit a `c2_beacon` finding. This was flagged as a potential FN (see Section 4 below). The local agent appears to have under-prioritized the netscan signal here.

### Host 5: srl-2018-base-wkstn-01-dual (Workstation, 172.16.7.11)

2 findings. Terminal QUARANTINED.

1. `legitimate_windows_default` (MEDIUM, NOT_FOUND). Mech: none. Value: empty. The agent reports disk persistence as clean (no Run keys / services / scheduled tasks of attacker origin).
2. `requires_disambiguation` (MEDIUM, NOT_FOUND). Mech: Suspicious outbound ESTABLISHED connection from svchost.exe (DiagTrack) to internal host on port 8080. Value: `172.16.7.11:51892 to 172.16.4.10:8080 ESTABLISHED (PID 2332, svchost.exe -k utcsvc -p)`. MITRE: TA0003 / Persistence (note: tactic appears mis-set here; would be TA0011 if classification escalated to c2_beacon).

**Note for reviewer:** Owner-confirmed compromised host. Agent missed the persistence on disk and only mentioned the C2 connection at MEDIUM confidence with `requires_disambiguation` instead of HIGH `c2_beacon`. Three sibling hosts (file, rd-01, wkstn-05) explicitly classified the same destination as `c2_beacon`. We treat this as a known FN: the agent had the smoking gun and under-graded it. Two registry plugins (`winlogon_tln`, `securityproviders`) returned `parse_error` because our parser does not understand the regripper TLN format; the raw output for `winlogon_tln` did contain ALERT rows about Shell registry value being non-default, but the same alerts fired identically on rd-02 (which is compromised differently), suggesting a Win10 regripper false positive on REG_MULTI_SZ Shell values rather than real Shell hijack.

### Host 6: srl-2018-base-wkstn-05-dual (Workstation, 172.16.7.15)

4 findings. Terminal SUCCESS.

1. `attacker_persistence` (HIGH). Mech: Named-pipe beacon service (Metasploit / Impacket / Cobalt Strike psexec pattern). Value: `%COMSPEC% /c echo b6a1458f396 > \\.\pipe\334485`. MITRE: TA0003 / T1543.003.
2. `attacker_persistence` (HIGH). Mech: Masquerading service auto-start (fake PerfMon binary). Value: `c:\windows\system32\perfmonsvc64.exe`. MITRE: TA0003 / T1543.003.
3. `process_injection` (MEDIUM, NOT_FOUND). Value: `powershell.exe (PIDs 4328, 4064, 3920, 1124, 4072, 1332), PAGE_EXECUTE_READWRITE regions; rundll32.exe (PID 7100), PAGE_EXECUTE_READWRITE region with orphaned parent`. MITRE: TA0005 / T1055.
4. `c2_beacon` (MEDIUM, NOT_FOUND). Value: `172.16.7.15 to 172.16.4.10:8080 (5 connections, CLOSE_WAIT/CLOSED)`. MITRE: TA0011 / T1071.

### Host 7: srl-2018-base-wkstn-05-memonly (Workstation, 172.16.7.15, MEMORY ONLY)

Same physical host as Host 6 but scanned with memory channel only (no disk image), as a smoke test of our memory-only mode. 3 findings. Terminal SUCCESS.

1. `process_injection` (MEDIUM, NOT_FOUND). Value: `powershell.exe (PIDs 4328, 1124, 4064, 4072, 3920, 1332), multiple PAGE_EXECUTE_READWRITE regions; parent WmiPrvSE.exe (PID 2676)`. MITRE: TA0005 / T1055.
2. `process_injection` (MEDIUM, NOT_FOUND). Mech: process_injection into rundll32.exe with scripting-engine payload. Value: `rundll32.exe PID 7100, PAGE_EXECUTE_READWRITE region 0x1bb0000 (CommitCharge 627 pages); loaded JScript9.dll, JScript.dll, VBScript.dll`. MITRE: TA0005 / T1055.
3. `c2_beacon` (MEDIUM, NOT_FOUND). Value: `172.16.7.15 to 172.16.4.10:8080 (multiple CLOSE_WAIT/CLOSED TCP connections)`. MITRE: TA0011 / T1071.

## Section 4: Cross-host inference: 172.16.4.10:8080 is the C2 server

Four out of seven runs explicitly classified the destination `172.16.4.10:8080` as `c2_beacon`: file, rd-01, wkstn-05 (dual), wkstn-05 (memory-only). Their netscan TCP records:

| Host | Captured host IP | Records to 172.16.4.10:8080 | States observed |
|---|---|---|---|
| wkstn-01 | 172.16.7.11 | 3 | 1 ESTABLISHED, 2 CLOSED |
| wkstn-05 | 172.16.7.15 | 6 | 4 CLOSE_WAIT, 2 CLOSED |
| file | 172.16.4.5 | 4 | 1 CLOSE_WAIT, 3 CLOSED |
| rd-01 | 172.16.6.11 | many | ESTABLISHED + CLOSE_WAIT |
| rd-02 | 172.16.6.12 | 2 | 2 CLOSED |
| dc | 172.16.4.4 | 1 to port 80 (DIFFERENT port) | CLOSED |

wkstn-01 has an ESTABLISHED connection at capture time (the implant was alive when the dump was taken). The other hosts show classic detached-implant patterns (CLOSED with `pid=-1`, repeated callbacks). dc only made a one-off port-80 HTTP contact, which is consistent with normal traffic.

**Cross-host aggregator escalations** (FNs the per-host agent missed):
- wkstn-01 to 172.16.4.10:8080: agent classified `requires_disambiguation`, should be `c2_beacon` HIGH given three sibling hosts confirmed C2.
- rd-02 to 172.16.4.10:8080: agent emitted no finding, should be `c2_beacon`.

## Section 5: Cross-host inference: shared persistence services

Two hosts have the same `Microsoft Advanced API` masquerade services:
- file: msadvapi2_32.exe and msadvapi2_64.exe
- rd-02: msadvapi2_32.exe and msadvapi2_64.exe

Same paths, same names. Strong indicator of a shared deployment script or replay.

wkstn-05 has a different masquerade service (`perfmonsvc64.exe`) plus the named-pipe beacon (psexec lateral movement signature). Different victim profile.

rd-01 has a Windows Temp scheduled task (`1.bat`) plus on-disk `c:\windows\temp\perfmon\p.exe` (note: shares the "perfmon" subdir name with wkstn-05's `perfmonsvc64.exe`, possibly the same toolkit).

## Section 6: Known limitations / caveats the reviewer should consider

1. **Three runs ended in `terminal=QUARANTINED`** (rd-01, rd-02, wkstn-01). The cause is an injection-scanner counter-rule firing on raw bytes containing the literal token `T1033`. We have inspected one such case (wkstn-01) and confirmed the byte pattern came from the extracted SOFTWARE hive itself (the file starts with the `regf` magic and contains many ATT&CK-style strings as part of normal Windows registry data). This is a known false-positive class of our injection guard, NOT attacker output. Findings produced before quarantine are still considered valid.
2. **Wording variance.** When the same finding is re-emitted by INTERPRET on a different run, the `mechanism` prose can vary (e.g. "PsExec" vs "psexec", "Microsoft-masquerading" vs "fake Microsoft") even though the underlying `value` is identical. We compare findings by `value` field for stability.
3. **Win10 regripper false positives.** The `winlogon_tln` plugin emits "Shell value not explorer.exe: 0" / "...sihost.exe" alerts on multiple Win10 hosts (wkstn-01, rd-02). Same alerts on hosts that are compromised differently strongly suggest these are regripper false positives on the multi-string `Shell` registry value, not real Shell hijack.
4. **Memory-only mode is fresh.** wkstn-05-memonly is the first end-to-end memory-only run. It produced sensible findings but has not yet been compared against ground truth at scale.
5. **`category=NOT_FOUND` plus a memory-class classification** is the current mechanism for surfacing memory-only findings within a persistence-focused schema. The MITRE tactic is sometimes mis-set to TA0003 (Persistence) instead of TA0005 / TA0011 in those records, which is a schema mismatch we have not yet tightened.
6. **dc came back essentially clean.** Only 2 legitimate DFIR tools and 1 NOT_FOUND. A Domain Controller in a compromised lab usually shows attacker tradecraft. Either a true negative (the attacker did not establish persistence on the DC) or a false negative we missed; we have not done a manual review yet.

## Section 7: Specific things we want a fresh LLM to check

In addition to the five questions in Section 0, consider:

- **rd-01's `c:\windows\temp\perfmon\p.exe` and wkstn-05's `c:\windows\system32\perfmonsvc64.exe`.** Same toolkit? Different stages of the same intrusion? Worth surfacing as a sweep-level "perfmon-themed implant" finding?
- **The named-pipe beacon** on wkstn-05 with command `%COMSPEC% /c echo b6a1458f396 > \\.\pipe\334485`. Is the hex value (`b6a1458f396`) a Metasploit / Cobalt Strike pipe-handshake token, or a general RCE artifact? Does that change the confidence?
- **The wkstn-01 ESTABLISHED to 172.16.4.10:8080 from svchost.exe -k utcsvc -p (DiagTrack)**. This service group hosts the Connected User Experiences and Telemetry (DiagTrack) service which normally beacons to Microsoft endpoints. An ESTABLISHED connection to an internal RFC1918 address on port 8080 is anomalous on its face. We graded this MEDIUM `requires_disambiguation`. Is HIGH `c2_beacon` justified?
- **dc's silence**. Domain Controller is the keys-to-the-kingdom target. Three findings (two are DFIR tools, one is NOT_FOUND) is suspicious by absence. What additional artifacts should we look for on a compromised DC that the agent did not enumerate?

## Section 8: Output format we want from the reviewer

For each of Sections 0 questions 1-5, give:
- A short verdict (agree / disagree / partial)
- A bulleted list of specific findings you flagged for change, with the new classification or confidence and one-sentence reason
- A confidence rating on your own answer (high / medium / low) so we know how much to trust it

If you spot patterns we did not surface as cross-host findings, list them in a "missed cross-host inferences" section at the end.

End of brief.
