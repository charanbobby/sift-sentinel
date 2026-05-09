---
created: 2026-05-09
status: closed
adjudicator: Claude under SOC delegation per memory/feedback_soc_authority.md
scope: 14 HUMAN_REVIEW runs from the 2026-05-04 viewer revamp pass
---

# Bulk adjudication, 2026-05-09

## TL;DR

Adjudicated 14 HUMAN_REVIEW runs in one pass. 6 APPROVED (added to keep_runs.json), 7 REJECTED as superseded by a later curated run for the same case, 1 INVALID for bad input image (openuni22-server whole-disk MBR, never partition-extracted). All citation checks (tool_call_id resolves in evidence, excerpt substring present in cited record, tool present in plan, integrity ledger chain unbroken) passed cleanly on every approved run. One rationale-hallucination flagged on openuni22-server-cdrive-001 (carry-over from the prior single-case brief, not a new finding).

## Method

For each HUMAN_REVIEW run:

1. If the same case has a later run already in `viewer/keep_runs.json`, default to REJECTED (superseded). The later curated run is the canonical artifact for the case; the older HUMAN_REVIEW marker is stale.
2. Otherwise, read `05_interpret_findings.json`, `04_execute_evidence.jsonl`, `02_plan_tool_plan.json`, and `integrity_ledger.jsonl`. For each finding, verify (a) cited tool_call_id resolves in the evidence jsonl, (b) excerpt substring appears in the cited record's structured_fields, (c) the tool used is in the original plan, (d) the ledger chain is unbroken end to end. If checks pass and the finding is a concrete attacker artifact, APPROVE. Otherwise REJECT.
3. Special cases follow the runbook overrides documented in `docs/submission/adjudication-openuni22-cdrive-001.md` (TP, promote) and `docs/runbooks/openuni22-server-memonly-hang-2026-05-07.md` (bad input image, INVALID).

Citation checks were probed inside a python:3.12-slim container against the actual files on disk (probe script at `D:/tmp/audit_check.py`). Excerpt-substring matching uses raw substring + whitespace-collapse + key-value pair decomposition; remaining mismatches were verified by Grep against the raw evidence jsonl (all are escaping artifacts, not absences).

---

## dfirmadness-001-desktop/dfirmadness-001-desktop-001

- **Verdict:** REJECTED (superseded)
- **Rationale:** A later curated run (`dfirmadness-001-desktop-002`) for the same case already lives in keep_runs.json. The 001 run is a stale earlier attempt that was kept open for human review when 002 had not yet been adjudicated. With 002 in the curated set, this older run is no longer the canonical artifact for the case and should be marked rejected to clear the HUMAN_REVIEW backlog.
- **Citation-check results:** not performed (superseded path).
- **Action taken:** renamed `07_terminal.HUMAN_REVIEW` to `07_terminal.HUMAN_REJECTED`. No keep_runs change.

## openuni22-server/openuni22-server-001

- **Verdict:** INVALID (bad input)
- **Rationale:** Per Track 3 diagnosis at `docs/runbooks/openuni22-server-memonly-hang-2026-05-07.md`, the staged image `/mnt/derived/openuni22-server.raw` is a 50 GB whole-disk DOS/MBR image, not a partition-extracted single-FS NTFS dump like the SRL-2018 `base-*.ntfs.dd` files. Step 2 (`fls_list` at byte 0) returned zero bytes (raw_sha256 = SHA-256 of empty string) and the resolver correctly refused to chain `inode_by_name(...)` against an empty upstream, blocking 30 of the 32 plan steps. The pipeline did the right thing; the run is unsalvageable because the input file is wrong, and a partition-extracted peer file `/mnt/derived/openuni22-server-cdrive.raw` was added later (and is the basis of the openuni22-server-cdrive case below).
- **Citation-check results:** not applicable, no findings to cite.
- **Action taken:** renamed `07_terminal.HUMAN_REVIEW` to `07_terminal.HUMAN_REJECTED.bad_input`. No keep_runs change. The companion `openuni22-server-cdrive` case is the live one for OpenUni22.

## openuni22-server-cdrive/openuni22-server-cdrive-001

- **Verdict:** APPROVED (TP)
- **Rationale:** Carry-over from the single-case brief at `docs/submission/adjudication-openuni22-cdrive-001.md`. The cited evidence record (tool_call_id `49b3b420-3e39-4209-ba09-fd60ac485be5`, scheduled_tasks_parse against `task_xml_1.xml`) really does contain the malicious PsExec scheduled task `\Enterpries backup` (typo of "Enterprises") that pushes `C:\Users\admin\Desktop\rename.exe` to six branch-office desktops with `-u admin -p letmein`. That artifact is unambiguously attacker tradecraft and matches the OpenUni22 Red Petya scenario (RDP-foothold operator pushes a file-rename binary across a flat office subnet with hard-coded local-admin creds). Confidence in the verdict is medium-high (artifact is real, scenario fit is strong, but ground truth has not been requested from the dataset author).
- **Citation-check results:** all clean. tool_call_id present in evidence (1 of 31 records), excerpt verbatim, tool `scheduled_tasks_parse` is plan steps 17 through 26, ledger 69 entries with chain unbroken.
- **Rationale-hallucination flag:** the interpret rationale claims the primary scheduled-task tools (`fls_list`, `icat_extract`) "returned null structured_fields for the Tasks directory listing", which is wrong; record `259c5d48-d1cf-40ee-b151-21f2a484a2ec` (fls against the Tasks inode) has 496 entries populated and includes the `Enterpries backup` filename. This is rationale-hallucination class, not finding-hallucination, so the verdict stands per the adjudication policy. The hallucination is logged for the interpret-LLM rationale-hallucination metric.
- **Action taken:** renamed `07_terminal.HUMAN_REVIEW` to `07_terminal.HUMAN_APPROVED`. Added `"openuni22-server-cdrive": ["openuni22-server-cdrive-001"]` to keep_runs.json.

## srl-2018-base-file/srl-2018-base-file-001

- **Verdict:** REJECTED (superseded)
- **Rationale:** A later curated run (`srl-2018-base-file-005`) for the same case already lives in keep_runs.json. The 001 run is a stale earlier attempt and 005 is the canonical artifact for this case.
- **Citation-check results:** not performed (superseded path).
- **Action taken:** renamed `07_terminal.HUMAN_REVIEW` to `07_terminal.HUMAN_REJECTED`. No keep_runs change.

## srl-2018-base-rd-02/srl-2018-base-rd-02-001

- **Verdict:** REJECTED (superseded)
- **Rationale:** A later curated run (`srl-2018-base-rd-02-004`) for the same case already lives in keep_runs.json. The 001 run is a stale earlier attempt and 004 is the canonical artifact for this case.
- **Citation-check results:** not performed (superseded path).
- **Action taken:** renamed `07_terminal.HUMAN_REVIEW` to `07_terminal.HUMAN_REJECTED`. No keep_runs change.

## srl-2018-base-rd-03-memonly/srl-2018-base-rd-03-memonly-004

- **Verdict:** APPROVED
- **Rationale:** Memory-only run with three findings, all citing `volatility_run` evidence (pslist, cmdline). The two `msadvapi2_32.exe` and `msadvapi2_64.exe` service-process findings are part of the cross-host masquerading-service campaign signature already independently confirmed on rd-05, wkstn-03, wkstn-04, and wkstn-06; the parent is services.exe (PPID 764) and the install paths under `C:\Program Files (x86)\Microsoft Advanced API 32` and `\Microsoft Advanced API 64` do not correspond to any real Microsoft product. The third finding (`prunsrv.exe` running `//RS//LARIAT` from `C:\Program Files (x86)\Lincoln\LARIAT\tools\`) is correctly flagged as `requires_disambiguation` because LARIAT is a known red-team automation framework and the case ID `base-rd-03` itself signals red-team scenario context. Both 32-bit and 64-bit service variants were already approved by the human reviewer on 2026-05-03 (`human_approval.json` is present), but the run was never added to keep_runs.json and the `07_terminal.HUMAN_REVIEW` marker was left in place alongside the `07_terminal.HUMAN_APPROVED` marker. This adjudication closes both gaps.
- **Citation-check results:** 2 cited tool_call_ids, both resolve. cmdline (b59c588f) and pslist (ebf5fa78), both `tool_execution_status: ok`. Cited plugins {cmdline, pslist} are within plan plugins {cmdline, dlllist, malfind, netscan, pslist}. Excerpts present in raw evidence jsonl (verified via Grep). Ledger 25 entries, chain unbroken.
- **Action taken:** removed stale `07_terminal.HUMAN_REVIEW` (the `07_terminal.HUMAN_APPROVED` already exists from the 2026-05-03 reviewer pass). Added `srl-2018-base-rd-03-memonly` key to keep_runs.json with `["srl-2018-base-rd-03-memonly-004"]`.

## srl-2018-base-rd-05-memonly/srl-2018-base-rd-05-memonly-003

- **Verdict:** APPROVED
- **Rationale:** Memory-only run with four findings, all citing `volatility_run` evidence across pslist, cmdline, dlllist, malfind, and netscan. The headline finding is the `msadvapi2_32.exe` / `msadvapi2_64.exe` service-process pair with the 32-bit variant loading `SimpleAmqpClient.2.dll`, `rabbitmq.4.dll`, `wpcap.dll`, and `packet.dll` from its own install directory, which is a custom C2 implant signature using AMQP messaging plus on-host packet capture. The Metasploit reflective-loader shellcode in two powershell.exe processes (PIDs 17144 and 20780, both with the canonical `CLD; CALL; PUSHA; XOR EDX,EDX; MOV EDX,[FS:EDX+0x30]` PEB-walk prologue) is corroborated by a WMI-spawned PowerShell parent chain. F-Response Subject (subject_srv.exe) is correctly classified as `legitimate_responder_tool`. Already approved by human reviewer on 2026-05-03 (note: cross-host masquerading-service campaign signature confirmed across 3 hosts).
- **Citation-check results:** 5 cited tool_call_ids, all resolve, all `tool_execution_status: ok`. Cited plugins {cmdline, dlllist, malfind, netscan, pslist} match plan exactly. Excerpts (Windows paths and shellcode-disassembly multi-line strings) present in raw evidence (verified via Grep, mismatches in earlier probe pass were string-escape artifacts). Ledger 16 entries, chain unbroken.
- **Action taken:** removed stale `07_terminal.HUMAN_REVIEW`. `07_terminal.HUMAN_APPROVED` already in place. Added `srl-2018-base-rd-05-memonly` key to keep_runs.json with `["srl-2018-base-rd-05-memonly-003"]`.

## srl-2018-base-wkstn-03-memonly/srl-2018-base-wkstn-03-memonly-001

- **Verdict:** APPROVED
- **Rationale:** Memory-only run with seven findings: rundll32.exe (PID 5376) PAGE_EXECUTE_READWRITE injection with a CLOSE_WAIT to 172.16.4.10:8080, the same C2 endpoint contacted by a WmiPrvSE-spawned powershell.exe chain (PID 3380 to PID 196 to PID 7796, with PID 7796 running the standard `-Version 5.1 -s -NoLogo -NoProfile` C2 flag set), the cross-host `msadvapi2_32` / `msadvapi2_64` masquerading-service pair under services.exe (PPID 708), a SearchUI.exe disambiguation case correctly classified as `requires_disambiguation`, and the F-Response responder tool. The rundll32 anomaly is particularly strong (bare command line with no DLL argument plus injected memory plus the same C2 IP as the WMI chain). Already approved on 2026-05-03 as part of the cross-host campaign signature.
- **Citation-check results:** 4 cited tool_call_ids, all resolve, all `tool_execution_status: ok`. Cited plugins {cmdline, malfind, netscan, pslist} match plan exactly. Excerpts present in raw evidence (verified via Grep). Ledger 40 entries, chain unbroken.
- **Action taken:** removed stale `07_terminal.HUMAN_REVIEW`. `07_terminal.HUMAN_APPROVED` already in place. Added `srl-2018-base-wkstn-03-memonly` key to keep_runs.json with `["srl-2018-base-wkstn-03-memonly-001"]`.

## srl-2018-base-wkstn-04-memonly/srl-2018-base-wkstn-04-memonly-001

- **Verdict:** APPROVED
- **Rationale:** Memory-only run with four findings. The headline is process injection in 32-bit powershell.exe (PID 1288, syswow64) with two PAGE_EXECUTE_READWRITE regions containing the canonical Metasploit shellcode prologue (CLD; CALL +0x89; PUSHA; XOR EDX,EDX; MOV EDX,[FS:EDX+0x30]), parent chain WmiPrvSE.exe (PID 3308) to powershell.exe (PID 4340) to powershell.exe (PID 1288). PID 4340's empty cmdline is a credible argument-spoofing indicator. The cross-host masquerading-service pair (`msadvapi2_32.exe` PID 2240 and `msadvapi2_64.exe` PID 2248 under services.exe PPID 736) is consistent with rd-03/rd-05/wkstn-03/wkstn-06. F-Response Subject is correctly classified as `legitimate_responder_tool`. Already approved 2026-05-03.
- **Citation-check results:** 4 cited tool_call_ids, all resolve, all `tool_execution_status: ok`. Cited plugins {cmdline, malfind, netscan, pslist} are within plan plugins {cmdline, dlllist, malfind, netscan, pslist}. Excerpts (including multi-line shellcode disassembly) present in raw evidence. Ledger 29 entries, chain unbroken.
- **Action taken:** removed stale `07_terminal.HUMAN_REVIEW`. `07_terminal.HUMAN_APPROVED` already in place. Added `srl-2018-base-wkstn-04-memonly` key to keep_runs.json with `["srl-2018-base-wkstn-04-memonly-001"]`.

## srl-2018-base-wkstn-06-memonly/srl-2018-base-wkstn-06-memonly-001

- **Verdict:** REJECTED (failed checks)
- **Rationale:** All five Volatility plugin steps (pslist, cmdline, netscan, malfind, dlllist) returned `tool_execution_status: parse_error` with empty structured_fields. The interpret pass correctly produced a single low-confidence NOT_FOUND finding noting the systemic tool failure and recommending re-acquisition or profile re-identification. The run is functionally a wash; there is no evidence surface to adjudicate against. The follow-up run `srl-2018-base-wkstn-06-memonly-002` reused the same memory image with a different (working) profile and produced the actual findings. This older 001 run is superseded by 002 in spirit even though 002 is itself only being added now. Per policy, mark this 001 run rejected to clear the HUMAN_REVIEW marker.
- **Citation-check results:** 0 cited tool_call_ids (no findings to cite). Plan {volatility_run, plugins pslist/cmdline/netscan/malfind/dlllist}, all 5 evidence records present but `parse_error`. Ledger 10 entries, chain unbroken.
- **Action taken:** renamed `07_terminal.HUMAN_REVIEW` to `07_terminal.HUMAN_REJECTED`. No keep_runs change.

## srl-2018-base-wkstn-06-memonly/srl-2018-base-wkstn-06-memonly-002

- **Verdict:** APPROVED
- **Rationale:** Memory-only re-run after the 001 attempt failed with parse_errors across all plugins. Three findings: the cross-host `msadvapi2_32.exe` (PID 1340) and `msadvapi2_64.exe` (PID 1436) masquerading-service pair under services.exe (PPID 668), and an explorer.exe (PID 4496) injection with a PAGE_EXECUTE_READWRITE region containing a structured trampoline pattern at 0x3d70000 plus a second region at 0x3e10000. explorer.exe is not a JIT process, so the executable+writable private memory is not legitimately explained. The masquerading-service pair is the same campaign signature already corroborated across rd-03, rd-05, wkstn-03, wkstn-04, and now wkstn-06. Already approved 2026-05-03.
- **Citation-check results:** 4 cited tool_call_ids, all resolve, all `tool_execution_status: ok`. Cited plugins {cmdline, dlllist, malfind, pslist} are within plan plugins {cmdline, dlllist, malfind, netscan, pslist}. Excerpts present in raw evidence. Ledger 25 entries, chain unbroken.
- **Action taken:** removed stale `07_terminal.HUMAN_REVIEW`. `07_terminal.HUMAN_APPROVED` already in place. Added `srl-2018-base-wkstn-06-memonly` key to keep_runs.json with `["srl-2018-base-wkstn-06-memonly-002"]`.

## srl-2018-dmz-ftp/srl-2018-dmz-ftp-001

- **Verdict:** REJECTED (superseded)
- **Rationale:** A later curated run (`srl-2018-dmz-ftp-004`) for the same case already lives in keep_runs.json. 001 is a stale earlier attempt; 004 is the canonical artifact for this case.
- **Citation-check results:** not performed (superseded path).
- **Action taken:** renamed `07_terminal.HUMAN_REVIEW` to `07_terminal.HUMAN_REJECTED`. No keep_runs change.

## srl-2018-dmz-ftp/srl-2018-dmz-ftp-002

- **Verdict:** REJECTED (superseded)
- **Rationale:** Same as 001. `srl-2018-dmz-ftp-004` is curated for this case; 002 is a stale earlier attempt.
- **Citation-check results:** not performed (superseded path).
- **Action taken:** renamed `07_terminal.HUMAN_REVIEW` to `07_terminal.HUMAN_REJECTED`. No keep_runs change.

## srl-2018-wkstn-05/srl-2018-wkstn-05-001

- **Verdict:** REJECTED (superseded)
- **Rationale:** Three later curated runs (`srl-2018-wkstn-05-005`, `-006`, `-007`) for the same case already live in keep_runs.json. 001 is a stale earlier attempt and the 005-to-007 trio covers the canonical findings for this case.
- **Citation-check results:** not performed (superseded path).
- **Action taken:** renamed `07_terminal.HUMAN_REVIEW` to `07_terminal.HUMAN_REJECTED`. No keep_runs change.

---

## keep_runs.json updates

The following keys are added (alphabetical insertion preserving existing keys):

```
"openuni22-server-cdrive":      ["openuni22-server-cdrive-001"]
"srl-2018-base-rd-03-memonly":  ["srl-2018-base-rd-03-memonly-004"]
"srl-2018-base-rd-05-memonly":  ["srl-2018-base-rd-05-memonly-003"]
"srl-2018-base-wkstn-03-memonly": ["srl-2018-base-wkstn-03-memonly-001"]
"srl-2018-base-wkstn-04-memonly": ["srl-2018-base-wkstn-04-memonly-001"]
"srl-2018-base-wkstn-06-memonly": ["srl-2018-base-wkstn-06-memonly-002"]
```

No existing keys are removed or modified.

## Outcome counts

- APPROVED: 6 (openuni22-server-cdrive-001, srl-2018-base-rd-03-memonly-004, srl-2018-base-rd-05-memonly-003, srl-2018-base-wkstn-03-memonly-001, srl-2018-base-wkstn-04-memonly-001, srl-2018-base-wkstn-06-memonly-002)
- REJECTED, superseded by curated successor: 6 (dfirmadness-001-desktop-001, srl-2018-base-file-001, srl-2018-base-rd-02-001, srl-2018-dmz-ftp-001, srl-2018-dmz-ftp-002, srl-2018-wkstn-05-001)
- REJECTED, failed checks: 1 (srl-2018-base-wkstn-06-memonly-001, all 5 plugins parse_error)
- INVALID, bad input: 1 (openuni22-server-001, whole-disk MBR not partition-extracted)

Total: 14.

## Rationale-hallucination flag

One carry-over from the openuni22-server-cdrive-001 single-case brief: the interpret rationale invents a "null structured_fields" claim about evidence record `259c5d48-d1cf-40ee-b151-21f2a484a2ec` (an `fls_list` against the Tasks inode that actually returned 496 entries). This is rationale-hallucination class, not finding-hallucination; the underlying scheduled-task artifact is real and cleanly cited, so the verdict stands. Logged for the interpret-LLM rationale-hallucination metric.
