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
| [ ] | base-dc | Domain Controller | `base-dc-cdrive.E01` | |
| [ ] | base-file | File Server | `base-file-cdrive.E01` | |
| [ ] | base-rd-01 | Remote Desktop / RDS | `base-rd-01-cdrive.E01` | |
| [ ] | base-rd-02 | Remote Desktop / RDS | `base-rd-02-cdrive.E01` | |
| [ ] | base-wkstn-01 | Workstation | `base-wkstn-01-c-drive.E01` | |
| [x] | base-wkstn-05 | Workstation | `base-wkstn-05-cdrive.E01` | **Current target** — Slice 2 pipeline runs against this |
| [x] | dmz-ftp | DMZ FTP server | `dmz-ftp-cdrive.E01` | External-facing — likely initial foothold |
| [ ] | *SRL-2018 (subfolder)* | — | — | Contents unknown — confirm |

### Memory captures (.7z / .zip)

| Status | Host | Size | File | Notes |
|---|---|---|---|---|
| [ ] | base-admin | 1.0 GB | `base-admin-memory.7z` | Admin workstation |
| [ ] | base-av | 2.1 GB | `base-av-memory.7z` | Antivirus server |
| [ ] | base-dc | 808.2 MB | `base-dc-memory.7z` | Domain controller (pairs with disk) |
| [ ] | base-elf | 672.8 MB | `base-elf-memory.7z` | Linux host? (ELF binaries?) |
| [ ] | base-file | 303.5 MB | `base-file-memory.7z` | File server (pairs with disk) |
| [ ] | base-file | 774.9 MB | `base-file-snapshot5.7z` | File server later snapshot |
| [ ] | base-hunt | 1.1 GB | `base-hunt-memory.7z` | Threat hunting host? |
| [x] | base-mail | 2.7 GB | `base-mail-memory.7z` | Mail server — phishing landing likely. Extracted to `HACKATHON-2026/base-mail-memory/` |
| [ ] | base-rd01 | 837.6 MB | `base-rd01-memory.7z` | RDS (naming differs from disk `base-rd-01`) |
| [ ] | base-rd-02 | 931.9 MB | `base-rd-02-memory.7z` | RDS (pairs with disk) |
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

---

## Open questions

- What's inside the `SRL-2018` subfolder beside the E01 files? (Docs? Ground truth? Network captures?)
- Does SRL-2015 have memory captures we haven't seen yet, or are memory images bundled inside the per-host ZIPs?
- Is there a case brief / scenario document anywhere in the share (victim org, scope, "find evil" prompt)?
- Did the original `base-wkstn-05-memory.7z` get deleted after extraction, or was memory obtained from elsewhere? (Folder present, source archive not on disk.)

---

## Local staging (what's on disk now)

Path: `d:/Python Applications/Find Evil - Hackathon/HACKATHON-2026/`

| File / folder | Size | Role |
|---|---|---|
| `base-wkstn-05-cdrive.E01` | 14.8 GB | Current target disk |
| `base-wkstn-05-memory/` | — | Current target memory (extracted) |
| `dmz-ftp-cdrive.E01` | 12.8 GB | Perimeter FTP — initial foothold candidate |
| `base-mail-memory.7z` + `base-mail-memory/` | 2.85 GB (+ extracted) | Mail server memory — phishing evidence candidate |

---

## What to download next

Hold off on more downloads until `base-wkstn-05` gives us an IOC that names another host. Reasoning (from prior discussion): real DFIR pivots are driven by findings, not pre-guessed lists. The current three staged files already cover the two most likely initial-access front doors (FTP exploit, phishing email).

When we do need more, likely next candidates:

- **`base-dc-cdrive.E01` + `base-dc-memory.7z`** — if wkstn-05 shows credential theft or lateral movement patterns.
- **`base-file-cdrive.E01`** — if we see data-staging / exfil artifacts pointing at file server shares.
- **An RDS host (`base-rd-*`)** — if lateral movement over RDP is observed.
