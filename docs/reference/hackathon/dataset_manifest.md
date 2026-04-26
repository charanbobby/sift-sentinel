# SANS Hackathon 2026 — Dataset Manifest

**Source:** SANS shared drive (`HACKATHON-2026 / Compromised APT Attacks`)
**Access:** Shared by Rob Lee, accessible until Jun 16, 2026
**Local storage:** 4 TB drive, space not a constraint
**Download cost:** Each file takes several hours — stage ahead of investigation

---

## Status legend

- [x] Downloaded and available locally
- [~] Download in progress
- [ ] Not yet downloaded
- [!] Priority — pull next

---

## Datasets

Two separate compromised-enterprise-network cases. Each is a full network capture (multiple hosts, disk + memory).

1. **SRL-2015** — Older Windows mix (XP / Win7 / Server 2008 R2). Packaged as per-host ZIPs.
2. **SRL-2018** — Larger network, separate E01 disk images and `.7z` memory captures.

---

## SRL-2015 — Compromised Enterprise Network

Per-host ZIP bundles (each likely contains disk + memory + misc for one host).

| Status | Host | OS | IP | File | Notes |
|---|---|---|---|---|---|
| [ ] | nromanoff | Windows 7 32-bit | 10.3.58.5 | `win7-32-nromanoff-10.3.58.5.zip` | User workstation |
| [ ] | nfury | Windows 7 64-bit | 10.3.58.6 | `win7-64-nfury-10.3.58.6.zip` | User workstation |
| [ ] | controller | Windows Server 2008 R2 | 10.3.58.4 | `win2008R2-controller-10.3.58.4.zip` | Domain controller (likely) |
| [ ] | tdungan | Windows XP | 10.3.58.7 | `xp-tdungan-10.3.58.7.zip` | Legacy workstation |

---

## SRL-2018 — Compromised Enterprise Network

### Disk images (E01, forensic format)

| Status | Host | Role (inferred) | File | Notes |
|---|---|---|---|---|
| [x] | base-dc | Domain Controller | `base-dc-cdrive.E01` | ✅ `derived/base-dc.ntfs.dd` 36.11 GB sha256: `58973a4dcf74c3001dc3a769e88cd81609a94b5c529d6ac44e188e7a335f8410` |
| [x] | base-file | File Server | `base-file-cdrive.E01` | ✅ `derived/base-file.ntfs.dd` 31.69 GB sha256: `5f5cba969a29ee4ab5c3caf5a9967ef5b38de6a532b18832d121e308128cb0bc` |
| [~] | base-rd-01 | Remote Desktop / RDS | `base-rd-01-cdrive.E01` | On disk, conversion queued 2026-04-23 |
| [~] | base-rd-02 | Remote Desktop / RDS | `base-rd-02-cdrive.E01` | On disk, conversion queued after base-file 2026-04-23 |
| [ ] | base-wkstn-01 | Workstation | `base-wkstn-01-c-drive.E01` | |
| [x] | base-wkstn-05 | Workstation | `base-wkstn-05-cdrive.E01` | **Current target** — Slice 2 pipeline runs against this |
| [x] | dmz-ftp | DMZ FTP server | `dmz-ftp-cdrive.E01` | External-facing — likely initial foothold |
| n/a | *SRL-2018 (subfolder)* | — | — | Confirmed 2026-04-25: subfolder contains additional memory captures only (no disk images, no scenario brief, no ground truth). Out-of-scope for current Windows-disk pipeline. |

### Memory captures (.7z / .zip)

| Status | Host | Size | File | Notes |
|---|---|---|---|---|
| [ ] | base-admin | 1.0 GB | `base-admin-memory.7z` | Admin workstation |
| [ ] | base-av | 2.1 GB | `base-av-memory.7z` | Antivirus server |
| [x] | base-dc | 808.2 MB | `base-dc-memory.7z` | Domain controller (pairs with disk) |
| [ ] | base-elf | 672.8 MB | `base-elf-memory.7z` | Linux host? (ELF binaries?) |
| [x] | base-file | 303.5 MB | `base-file-memory.7z` | File server (pairs with disk) |
| [ ] | base-file | 774.9 MB | `base-file-snapshot5.7z` | File server later snapshot |
| [ ] | base-hunt | 1.1 GB | `base-hunt-memory.7z` | Threat hunting host? |
| [x] | base-mail | 2.7 GB | `base-mail-memory.7z` | Mail server — phishing landing likely. Extracted to `HACKATHON-2026/base-mail-memory/` (archive not on disk — extracted only) |
| [ ] | base-rd01 | 837.6 MB | `base-rd01-memory.7z` | RDS (naming differs from disk `base-rd-01`) |
| [x] | base-rd-02 | 931.9 MB | `base-rd-02-memory.7z` | RDS (pairs with disk) |
| [ ] | base-rd-03 | 932.8 MB | `base-rd-03-memory.7z` | RDS (no disk) |
| [ ] | base-rd-04 | 997.4 MB | `base-rd-04-memory.7z` | RDS (no disk) |
| [ ] | base-rd-05 | 513.6 MB | `base-rd-05-memory.7z` | RDS (no disk) |
| [ ] | base-rd-06 | 578.6 MB | `base-rd-06-memory.7z` | RDS (no disk) |
| [ ] | base-sp | 953.8 MB | `base-sp-memory.7z` | SharePoint server? |
| [ ] | base-wkstn-01 | 1.2 GB | `base-wkstn-01-mem.zip` | Workstation (Sep 2021 re-release — different format) |
| [ ] | base-wkstn-01 | 984.4 MB | `base-wkstn-01-memory.7z` | Workstation (original .7z) |
| [ ] | base-wkstn-02 | 969.2 MB | `base-wkstn-02-memory.7z` | Workstation |
| [ ] | base-wkstn-03 | 890 MB | `base-wkstn-03-memory.7z` | Workstation |
| [ ] | base-wkstn-04 | 895.5 MB | `base-wkstn-04-memory.7z` | Workstation |
| [x] | base-wkstn-05 | 625.5 MB | `base-wkstn-05-memory.7z` | Workstation (pairs with disk). Extracted to `HACKATHON-2026/base-wkstn-05-memory/` |
| [ ] | base-wkstn-06 | 549.2 MB | `base-wkstn-06-memory.7z` | Workstation |

> Screenshot cut off after `base-wkstn-06-memory.7z`. If more files exist below that row, add them here.

### Memory profile mapping (Vol 2.6.1)

Per-host kdbgscan + pslist verification — staged 2026-04-25 in `sift-mcp:/tmp/`. SRL-2018 hosts are not a single OS; the case manifest must store the profile per host because Vol2 will not auto-detect cross-build.

| Host | Staged path (sift-mcp) | Vol2 profile | Build | OS | Verified by | Boot |
|---|---|---|---|---|---|---|
| base-wkstn-05 | `/tmp/wkstn05.img` (3.2 GB) | `Win7SP1x64` | 7601 | Windows 7 SP1 x64 | kdbgscan + 5 plugins | (user probe) |
| base-file | `/tmp/base-file-memory.img` (2.0 GB) | `Win2012R2x64` | 9600.16452 winblue_gdr | Server 2012 R2 | kdbgscan + pslist (104 lines) | 2018-08-08 18:07:56 |
| base-dc | `/tmp/base-dc-memory.img` (5.0 GB) | `Win2016x64_14393` | 14393.2214 rs1_release | Server 2016 | kdbgscan + pslist (109 lines) | 2018-08-16 21:05:18 |

Other SRL-2018 hosts with both disk + memory available (`base-rd-02`, `base-mail`, `base-rd01`) not yet staged. Profile must be probed per host before pipeline runs against them.

---

## Additional datasets (not from SANS share)

### OpenUni22 — Compromised Windows Server 2022

- **Source:** Open University PhD research (Benjamin Donnachie). CC-BY-NC-SA 4.0.
- **Scenario:** Simulated UK small-office network, RDP exposed, Red Petya ransomware, Feb 2024. Disk decrypted post-incident.
- **Format:** 7-segment E01 (`20240212-decrypted-Windows_Server_2022.E01` through `.E07`)
- **Ground truth:** Available on request from author (benjamin.donnachie@open.ac.uk)
- **Value:** Windows Server 2022 (newer OS than SRL-2018), ransomware incident type, ground truth available — good additional Reference Dataset case

### Hadi3 — Windows 8.1 Challenge (negative-case stress test)

- **Format:** FTK Imager split format (`.001` extension), single segment
- **Scenario:** Published no-persistence DFIR scenario. Expected pipeline output: `findings: []`, zero hallucinations.
- **Role:** Named validation case for negative-case discipline (success criterion #6). Empirical proof the Critic isn't rubber-stamping LLM positive-finding bias.

---

## Open questions

- ~~What's inside the `SRL-2018` subfolder beside the E01 files? (Docs? Ground truth? Network captures?)~~ **Answered 2026-04-25:** memory captures only. No scenario brief, no ground truth, no network captures. Same out-of-scope status as the other memory files.
- Does SRL-2015 have memory captures we haven't seen yet, or are memory images bundled inside the per-host ZIPs?
- Is there a case brief / scenario document anywhere in the share (victim org, scope, "find evil" prompt)?
- Did the original `base-wkstn-05-memory.7z` get deleted after extraction, or was memory obtained from elsewhere? (Folder present, source archive not on disk.)

---

## Local staging (what's on disk now)

Path: `d:/Python Applications/Find Evil - Hackathon/HACKATHON-2026/`

| File / folder | Size | Role |
|---|---|---|
| `base-wkstn-05-cdrive.E01` | 14.8 GB | Slice 2/2.5 target disk — pipeline-ready |
| `base-wkstn-05-memory/` | — | Slice 2/2.5 target memory (extracted) |
| `dmz-ftp-cdrive.E01` | 12.8 GB | FTP foothold — conversion queued |
| `base-mail-memory/` | — | Mail server memory (extracted; .7z archive not on disk) |
| `base-dc-cdrive.E01` | ~36 GB | Domain controller disk — ✅ `derived/base-dc.ntfs.dd` (36.11 GB, sha256 `58973a4dcf...f8410`) |
| `base-dc-memory.7z` | 808 MB | Domain controller memory — on disk |
| `base-file-cdrive.E01` | ~40 GB | File server disk — ✅ `derived/base-file.ntfs.dd` (31.69 GB, sha256 `5f5cba9...b0bc`) |
| `base-file-memory.7z` | 303 MB | File server memory — on disk |
| `base-rd-02-cdrive.E01` | — | RDS disk — conversion queued after base-file |
| `dfirmadness-desktop/` | — | DFIR Madness Case 001 — Slice 2.5 second validation case |
| `derived/` | — | Derived artifacts (raw partitions, hashes) |
| `Compromised Windows Server 2022 (OpenUni22)/` | 7-segment E01 | Windows Server 2022, Red Petya ransomware incident, Feb 2024. Synthetic data. Research dataset with ground truth available (contact benjamin.donnachie@open.ac.uk). CC-BY-NC-SA 4.0. NOT from SANS share. |
| `Hadi3 Windows8.1-Challenge3.001` | FTK Imager .001 | Windows 8.1, published no-persistence scenario. Negative-case stress test — pipeline must return `findings: []`. Named in architecture + onboarding docs. |

---

## What to download next

**Updated 2026-04-23 — Slice 6 Reference Dataset staging in progress.**

Already on disk or converting: `base-dc` (disk+memory), `base-file` (disk+memory), `base-rd-02` (disk), `base-wkstn-05` (disk+memory), `dmz-ftp` (disk), `base-mail` (memory).

**Needs downloading (priority order):**

1. `base-wkstn-01-cdrive.E01` — second workstation for comparison with `base-wkstn-05`
2. `base-wkstn-01-memory.7z` (984 MB) — pairs with #1 above

Already on disk (no longer needed): `base-rd-01-cdrive.E01` ✅, `base-rd-02-memory.7z` ✅

**SRL-2015 — download for breadth (different case, older OS mix):**
5. `win2008R2-controller-10.3.58.4.zip`
6. `win7-64-nfury-10.3.58.6.zip`
7. `win7-32-nromanoff-10.3.58.5.zip`
8. `xp-tdungan-10.3.58.7.zip`

**Unknown datasets on disk — investigate before downloading more:**
- `Compromised Windows Server 2022 (OpenUni22)/` — catalogue this first
- `Hadi3 Windows8.1-Challenge3.001` — catalogue this first
