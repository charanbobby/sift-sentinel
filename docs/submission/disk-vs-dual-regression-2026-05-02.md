# Disk-only vs dual-channel regression check, 2026-05-02

## TL;DR

Compared 6 host pairs (disk-only + dual sweep). 3 disk-only findings did not appear in the matching dual run (potential regressions, listed below). 11 dual-only findings did not appear in the disk-only run (memory-channel adds, the value the dual sweep produced).

## Per-host counts

| Host | Disk-only count | Dual count | Lost in dual | Added in dual |
|---|---|---|---|---|
| dc | 1 | 3 | 0 | 2 |
| file | 2 | 4 | 0 | 2 |
| rd-01 | 3 | 4 | 2 | 3 |
| rd-02 | 3 | 3 | 1 | 1 |
| wkstn-01 | 1 | 2 | 0 | 1 |
| wkstn-05 | 2 | 4 | 0 | 2 |

## Per-host detail

### dc

- disk-only run: `experiments\slice-2-notebook\out\runs\srl-2018-base-dc\srl-2018-base-dc-005` (1 findings)
- dual run:      `experiments\slice-2-notebook\out\runs\srl-2018-base-dc-dual\srl-2018-base-dc-dual-003` (3 findings)

**Added in dual (memory-channel adds):**
- `legitimate_responder_tool` / `high` | Windows service auto-start (DFIR memory acquisition driver) | value: \??\C:\windows\Mnemosyne.sys
- `legitimate_responder_tool` / `high` | Windows service auto-start (DFIR remote forensic agent) | value: C:\windows\subject_srv.exe -s "base-hunt.shieldbase.lan:5682" -l 3262 -v "F-Response Subject" -k "155522845"

### file

- disk-only run: `experiments\slice-2-notebook\out\runs\srl-2018-base-file\srl-2018-base-file-005` (2 findings)
- dual run:      `experiments\slice-2-notebook\out\runs\srl-2018-base-file-dual\srl-2018-base-file-dual-001` (4 findings)

**Added in dual (memory-channel adds):**
- `process_injection` / `high` | process_injection | value: powershell.exe PID 3164 — PAGE_EXECUTE_READWRITE shellcode at 0x4820000 and 0x4a80000
- `c2_beacon` / `high` | c2_beacon | value: powershell.exe PID 4072 → 172.16.4.10:8080 (encoded download cradle to squirreldirectory.com)

### rd-01

- disk-only run: `experiments\slice-2-notebook\out\runs\srl-2018-base-rd-01\srl-2018-base-rd-01-002` (3 findings)
- dual run:      `experiments\slice-2-notebook\out\runs\srl-2018-base-rd-01-dual\srl-2018-base-rd-01-dual-003` (4 findings)

**Lost in dual (regression candidates):**
- `legitimate_responder_tool` / `high` | F-Response DFIR tool installed as auto-start service | value: C:\windows\subject_srv.exe -s "base-hunt.shieldbase.lan:5682" -l 3262 -v "F-Response Subject" -k "155522845"
- `legitimate_responder_tool` / `high` | Mnemosyne memory acquisition kernel driver | value: \??\C:\windows\Mnemosyne.sys

**Added in dual (memory-channel adds):**
- `process_injection` / `high` | process_injection | value: c:\windows\temp\perfmon\p.exe (PID 8260) — PAGE_EXECUTE_READWRITE with cmd.exe spawn chain
- `process_injection` / `medium` | process_injection | value: powershell.exe (PID 8712) — multiple PAGE_EXECUTE_READWRITE regions, hidden cmdline
- `c2_beacon` / `medium` | C2 beacon — repeated outbound connections to internal host on port 8080 | value: 172.16.6.11 → 172.16.4.10:8080 (multiple ESTABLISHED/CLOSE_WAIT connections, no named process owner)

### rd-02

- disk-only run: `experiments\slice-2-notebook\out\runs\srl-2018-base-rd-02\srl-2018-base-rd-02-004` (3 findings)
- dual run:      `experiments\slice-2-notebook\out\runs\srl-2018-base-rd-02-dual\srl-2018-base-rd-02-dual-002` (3 findings)

**Lost in dual (regression candidates):**
- `requires_disambiguation` / `medium` | Packet capture kernel driver auto-start (WinPcap npf) installed alongside attacker services | value: system32\drivers\npf.sys

**Added in dual (memory-channel adds):**
- `process_injection` / `high` | process_injection | value: powershell.exe PID 6524 — PAGE_EXECUTE_READWRITE shellcode region at 0x77d0000 (PEB-walking pattern)

### wkstn-01

- disk-only run: `experiments\slice-2-notebook\out\runs\srl-2018-base-wkstn-01\srl-2018-base-wkstn-01-002` (1 findings)
- dual run:      `experiments\slice-2-notebook\out\runs\srl-2018-base-wkstn-01-dual\srl-2018-base-wkstn-01-dual-003` (2 findings)

**Added in dual (memory-channel adds):**
- `requires_disambiguation` / `medium` | Suspicious outbound ESTABLISHED connection from svchost.exe (DiagTrack) to internal host on port 8080 | value: 172.16.7.11:51892 → 172.16.4.10:8080 ESTABLISHED (PID 2332, svchost.exe -k utcsvc -p)

### wkstn-05

- disk-only run: `experiments\slice-2-notebook\out\runs\srl-2018-base-wkstn-05\srl-2018-base-wkstn-05-002` (2 findings)
- dual run:      `experiments\slice-2-notebook\out\runs\srl-2018-base-wkstn-05-dual\srl-2018-base-wkstn-05-dual-002` (4 findings)

**Added in dual (memory-channel adds):**
- `process_injection` / `medium` | process_injection | value: powershell.exe (PIDs 4328, 4064, 3920, 1124, 4072, 1332) — PAGE_EXECUTE_READWRITE regions; rundll32.exe (PID 7100) — PAGE_EXECUTE_READWRITE 
- `c2_beacon` / `medium` | C2 beacon — repeated outbound connections to 172.16.4.10:8080 | value: 172.16.7.15 → 172.16.4.10:8080 (5 connections: CLOSE_WAIT/CLOSED)

## How to read this

A regression is when a finding appears in the disk-only sweep but is missing from the dual sweep. Common causes: PLAN drift (the dual PLAN dropped the relevant tool call), INTERPRET drift (the dual INTERPRET classified the same evidence differently), or evidence trimming (a tool output got truncated upstream). Each entry should be investigated; not every diff is a real regression (the dual INTERPRET may legitimately re-classify a finding that was over-claimed in disk-only mode).
