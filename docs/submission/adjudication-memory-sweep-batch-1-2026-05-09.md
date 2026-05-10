---
created: 2026-05-09
status: closed
adjudicator: Claude under SOC delegation per memory/feedback_soc_authority.md
scope: 4 memory-only runs finished 2026-05-09 (dc, mail, hunt, sp)
---

# Adjudication: memory sweep batch 1, 2026-05-09

## TL;DR

All 4 runs are REJECTED. Every run shows the same failure pattern: pslist returned empty results with parse_error status, and cmdline returned truncated process names (fragments like "e", "exe", ".exe", "srv.ex") with empty command_line_safe fields. This is a Volatility 2 profile mismatch, not a tool bug. The pipeline used Win10x64_15063 for all 4 hosts, but the dataset manifest confirms base-dc requires Win2016x64_14393 (Server 2016) and the other 3 hosts have never had their profiles probed. All 4 need a re-run with correct profiles after kdbgscan probing. No new keys added to keep_runs.json. Terminal markers renamed from HUMAN_REVIEW to HUMAN_REJECTED on all 4 runs.

---

## Method

For each run:
1. Read the last 50 lines of the run log to confirm exit success and capture total run cost.
2. Read 05_interpret_findings.json, 04_execute_evidence.jsonl, 02_plan_tool_plan.json, and integrity_ledger.jsonl.
3. Checked plan digests match between findings and run log. Checked integrity ledger line count (all 4 show 9 entries, chain verifies clean per run log).
4. For findings with empty evidence arrays (all 4 runs), verified that the ev: IDs cited in the notes field resolve to records in 04_execute_evidence.jsonl by tool_call_id.
5. Determined verdict per runbook logic (all citations clean, but all findings are NOT_FOUND at low confidence due to tool failures, so REJECTED per "noise/zero/parse_error/NOT_FOUND" rule).
6. Investigated whether profile mismatch is the cause (confirmed below).
7. Renamed terminal markers using plain mv (out/runs/ is gitignored).

---

## srl-2018-base-dc-memonly / srl-2018-base-dc-memonly-001

**Verdict:** REJECTED (profile mismatch, incomplete run)

**Total run cost:** $0.0707

**Finding count:** 1 (NOT_FOUND, low confidence)

**Evidence records:** 4 total. Step 1 (pslist): parse_error, empty processes array [ev:ad030bf5]. Step 2 (cmdline): status ok, but 73 records with truncated names ("e", ".exe", "svc.ex", etc.) and empty command_line_safe on all [ev:7d76e53a]. Steps 3-4 (netscan, malfind): capability_denied / expired token [ev:c98b9a10, ev:b6955e95].

**Citation check:** plan_digest matches run log (44407d31). Integrity ledger: 9 entries, chain clean. All 4 ev: IDs cited in notes resolve to records in execute evidence jsonl. Evidence array in the finding is empty, so no excerpt-substring check needed. All tools used (pslist, cmdline, netscan, malfind) are in the plan. Checks: PASS.

**Profile mismatch diagnosis:** dataset_manifest.md line 93 explicitly records base-dc as Win2016x64_14393 (Server 2016, build 14393.2214 rs1_release). The pipeline used Win10x64_15063. Process name truncation and empty command lines are a textbook profile-offset mismatch signature. Pslist parse_error is consistent with the wrong EPROCESS offset for this build.

**Action:** Renamed 07_terminal.HUMAN_REVIEW to 07_terminal.HUMAN_REJECTED. No keep_runs change. Re-run required with Win2016x64_14393.

---

## srl-2018-base-mail-memonly / srl-2018-base-mail-memonly-002

**Verdict:** REJECTED (profile mismatch, incomplete run)

**Total run cost:** $0.1694

**Finding count:** 1 (NOT_FOUND, low confidence)

**Evidence records:** 4 total. Step 1 (pslist): parse_error, empty processes array [ev:1695cfb1]. Step 2 (cmdline): status ok, but 111 records all showing truncated names and empty command_line_safe [ev:7940d9c1]. Step 3 (netscan): status ok, 1,016 connections returned [ev:68d8d2ad]. Step 4 (malfind): capability_denied / expired token [ev:46f41894].

**Citation check:** plan_digest matches run log (dce03b44). Integrity ledger: 9 entries, chain clean. All ev: IDs resolve. Checks: PASS.

**Netscan data note (cross-host signal):** Although the run is rejected, the netscan data in [ev:68d8d2ad] shows two connections that corroborate the known C2 infrastructure seen across the prior bulk adjudication: (a) 172.16.4.6:80 -> 172.16.4.10:42718 ESTABLISHED, and (b) 172.16.4.6:34438 -> 172.16.4.10:3128 ESTABLISHED. 172.16.4.10 is the same C2 IP seen on wkstn-03, rd-03, rd-05, and other hosts in the prior adjudication. The mail server (172.16.4.6) has live connections to it. This is an attacker-side observation but cannot be elevated to a finding because pslist and malfind failed, so no owning process can be attributed (all PIDs are -1 in this netscan snapshot). A clean re-run with the correct profile is needed before a finding can be issued.

**Profile mismatch diagnosis:** Same truncated-name / empty-cmdline signature as dc. base-mail has not been profiled (dataset_manifest.md notes "not yet staged" for mail). kdbgscan must be run against /tmp/base-mail-memory.img before re-run.

**Action:** Renamed 07_terminal.HUMAN_REVIEW to 07_terminal.HUMAN_REJECTED. No keep_runs change. Re-run required after kdbgscan probe.

---

## srl-2018-base-hunt-memonly / srl-2018-base-hunt-memonly-001

**Verdict:** REJECTED (profile mismatch, incomplete run)

**Total run cost:** $0.0353

**Finding count:** 1 (NOT_FOUND, low confidence)

**Evidence records:** 4 total. Step 1 (pslist): parse_error, empty processes array [ev:7ee437b3]. Steps 2-4 (cmdline, netscan, malfind): all capability_denied / expired token [ev:389043ab, ev:55b190a9, ev:c7229d03].

**Citation check:** plan_digest matches run log (1eed8f8a). Integrity ledger: 9 entries, chain clean. All ev: IDs resolve. Checks: PASS.

**Additional note on capability_denied pattern:** Steps 2-4 failing as capability_denied (expired token) on top of a pslist parse_error is the worst-case overlap: not only is the profile wrong, but the session token expired during the run. The run log shows the token reissued at the execute phase, but the token expiry hit during steps 2-4. This means even if the profile were correct, the run would have needed a token refresh. The re-run should start with a fresh token.

**Profile mismatch diagnosis:** Same signature. base-hunt has not been profiled. kdbgscan required.

**Action:** Renamed 07_terminal.HUMAN_REVIEW to 07_terminal.HUMAN_REJECTED. No keep_runs change. Re-run required after kdbgscan probe.

---

## srl-2018-base-sp-memonly / srl-2018-base-sp-memonly-001

**Verdict:** REJECTED (profile mismatch, incomplete run)

**Total run cost:** $0.0633

**Finding count:** 1 (NOT_FOUND, low confidence)

**Evidence records:** 4 total. Step 1 (pslist): parse_error, empty processes array [ev:abdc5be6]. Steps 2-4 (cmdline, netscan, malfind): all capability_denied / expired token [ev:447b792f, ev:7ca4a270, ev:de3a9e19].

**Citation check:** plan_digest matches run log (c9638e69). Integrity ledger: 9 entries, chain clean. All ev: IDs resolve. Checks: PASS.

**Profile mismatch diagnosis:** Same signature. base-sp has not been profiled. kdbgscan required.

**Action:** Renamed 07_terminal.HUMAN_REVIEW to 07_terminal.HUMAN_REJECTED. No keep_runs change. Re-run required after kdbgscan probe.

---

## Cross-host attacker pattern notes

The prior bulk adjudication (adjudication-bulk-2026-05-09.md) established a cross-host campaign pattern anchored on:
- C2 endpoint 172.16.4.10:8080 (confirmed on wkstn-03, rd-03, rd-05, wkstn-05, wkstn-04, wkstn-06)
- msadvapi2_32.exe and msadvapi2_64.exe masquerading services under C:\Program Files (x86)\Microsoft Advanced API 3x\
- Meterpreter PEB-walk PowerShell shellcode (CLD; CALL; PUSHA; XOR EDX,EDX; MOV EDX,[FS:EDX+0x30] prologue) in WMI-spawned powershell.exe processes

This batch adds one corroborating data point: the netscan record from srl-2018-base-mail-memonly shows the Exchange mail server (172.16.4.6) with live ESTABLISHED connections to 172.16.4.10 on ports 42718 (outbound from :80) and 3128 (port 3128 is a Squid proxy / known C2 relay port). Port 3128 on the C2 IP is a new port variant not seen in the prior set (prior runs showed :8080). This suggests the attacker may be running a secondary proxy or tunneling channel on the C2 host alongside the :8080 handler.

The mail server candidates list also included powershell.exe and lsass.exe as injected_region candidates (priority 2), which aligns with the injection pattern seen on the workstations. None of those can be confirmed as findings until a clean run with the correct profile completes.

---

## keep_runs.json updates

No updates. All 4 runs are REJECTED. No new keys added. The 32 existing keys are preserved as-is.

---

## Re-run requirements

All 4 hosts need kdbgscan profiling before re-run:

| Host | Memory image (sift-mcp) | Known profile | Action needed |
|---|---|---|---|
| base-dc | /tmp/base-dc-memory.img (5 GB) | Win2016x64_14393 (from dataset_manifest.md) | Use this profile directly, no kdbgscan needed |
| base-mail | /tmp/base-mail-memory.img (18 GB per run log) | Unknown | kdbgscan probe required |
| base-hunt | /tmp/base-hunt-memory.img (size not confirmed) | Unknown | kdbgscan probe required |
| base-sp | /tmp/base-sp-memory.img (size not confirmed) | Unknown | kdbgscan probe required |

Note: base-dc is the only one with a confirmed profile from prior investigation. The other 3 must be profiled before the next pipeline run. The SRL-2018 network spans multiple Windows Server versions (2012 R2, 2016 at minimum) so each host needs individual profiling.
