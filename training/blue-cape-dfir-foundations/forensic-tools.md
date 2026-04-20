# Free Forensic Tools Reference

> Source: Blue Cape Security DFIR Foundations course + [README.md](README.md)
> Note: "Free" means open source or free for training/educational use. Some may require licenses for commercial use.
> **Agent-usability flag:** 🟢 = scriptable / CLI / CSV output (MCP-friendly) · 🟡 = CLI but output is messy / needs parsing · 🔴 = GUI-only (not directly usable by an agent)

---

## Suites (reference — not primary for agent)

| Tool | Purpose | Agent-usable? |
|------|---------|---------------|
| **Autopsy** | Full forensic suite — file analysis, timeline, keyword search, hash lookup, reporting. GUI wrapper over Sleuth Kit | 🔴 GUI |
| **KAPE** | Kroll Artifact Parser and Extractor — triage collection + orchestrated parsing. Targets (what to collect) + Modules (what to parse) | 🟡 CLI wrapper, Windows-focused |
| **GKape** | GUI front-end for KAPE | 🔴 GUI |

**Autopsy vs. Sleuth Kit for our agent:** Autopsy is the GUI, Sleuth Kit is the CLI underneath. The agent uses Sleuth Kit directly.

---

## Mounting

| Tool | Purpose | Agent-usable? |
|------|---------|---------------|
| **Arsenal Image Mounter** | Mount disk images (E01, raw, VMDK) as drive letters on Windows | 🔴 Windows GUI |
| **FTK Imager** | Acquire and mount forensic images, preview file systems | 🔴 Windows GUI |
| **ewfmount** (libewf) | Mount E01 as a raw block device on Linux — SIFT equivalent of Arsenal | 🟢 CLI, on SIFT |

---

## The Sleuth Kit (TSK) — core of our agent

Open-source CLI toolkit for disk image parsing. **Already on SIFT container.** These are the primitives our MCP server wraps.

| Tool | What it does | Used in slice |
|------|--------------|---------------|
| 🟢 `mmls` | List partitions in a disk image | 1 (proven — returns empty on F-Response volume images, hence pivot) |
| 🟢 `fsstat` | Filesystem metadata (type, cluster size, MFT location) | 1 ✅ / 2 |
| 🟢 `fls` | List files and directories (including deleted — marked `*`) | 2 |
| 🟢 `icat` | Extract file content by inode (needed for non-resident NTFS files) | 2+ (extracting hive bytes) |
| 🟢 `tsk_recover` | Recover deleted files en masse | Later |
| 🟢 `blkls` / `blkcat` | Read raw blocks (for carving / unallocated space) | Later |

**Why Sleuth Kit first:** every higher-level tool (Autopsy, Plaso, regripper wrappers) eventually calls into these. Wrapping them directly in MCP keeps contracts tight.

---

## Windows Registry

| Tool | What it does | Agent-usable? |
|------|--------------|---------------|
| 🟢 **RegRipper (`rip.pl`)** | Perl parser that runs named plugins against a registry hive (`NTUSER.DAT`, `SOFTWARE`, `SYSTEM`, `SAM`) | On SIFT |
| 🟢 **RECmd** (EZ Tools) | Alternative registry parser — CSV output, batch files for plugin sets | Windows-native, runnable via `dotnet` on Linux |

### Key RegRipper plugins for persistence (Slice 2)

| Plugin | Hive | What it extracts | MITRE |
|--------|------|------------------|-------|
| `user_run` | NTUSER.DAT | Run / RunOnce keys per user | T1547.001 |
| `run` | SOFTWARE | System-wide Run keys | T1547.001 |
| `services` | SYSTEM | Installed services (look for random 7-char names — Cobalt Strike signature) | T1543.003 |
| `schedagent` / `at` | SOFTWARE / SYSTEM | Scheduled tasks | T1053.005 |
| `image_file_execution_options` | SOFTWARE | IFEO debugger hijacks | T1546.012 |
| `appinit` | SOFTWARE | AppInit_DLLs persistence | T1546.010 |
| `userinit_mprlogonscript` | NTUSER.DAT | Logon script hijack (Cobalt Strike default) | T1037.001 |

---

## EZ Tools — Eric Zimmerman's parsers

**URL:** https://ericzimmerman.github.io/

All Windows-native C#/.NET, all produce **CSV** — ideal for agent consumption. Runnable on Linux via `dotnet run` (needs the .NET runtime added to SIFT container — not blocking for Slice 2).

| Tool | Parses | Answers |
|------|--------|---------|
| 🟢 **MFTECmd** | `$MFT` | Every file/directory with timestamps. Detects timestomping (SI vs FN) |
| 🟢 **PECmd** | Prefetch (`*.pf`) | Program execution history, run counts, first/last run times |
| 🟢 **LECmd** | LNK files | Recently accessed files, target paths, drive serials |
| 🟢 **JLECmd** | Jump Lists | Recent files per application (Office, Notepad, etc.) |
| 🟢 **SBECmd** | Shellbags | Folder access history — **including deleted folders** |
| 🟢 **RECmd** | Registry hives | Scriptable alternative to RegRipper |
| 🟢 **AppCompatCacheParser** | Shimcache | File *presence* evidence (not execution) |
| 🟢 **AmcacheParser** | `Amcache.hve` | Program execution + SHA1 hashes |
| 🟢 **EvtxECmd** | Windows Event Logs (`.evtx`) | Parsed event entries as CSV |
| 🔴 **Timeline Explorer** | Any EZ Tool CSV | GUI pivot / filter — not agent-usable, but output format matters |

**Key forensic rule these enable:** Shimcache + Amcache = evidence of presence, **not** of execution. Prefetch = evidence of execution. The agent must not conflate these when stating confidence.

---

## Memory Forensics

| Tool | Purpose | Agent-usable? |
|------|---------|---------------|
| 🟢 **Volatility 3** | Process, network, malware analysis from RAM dumps. On SIFT | CLI, well-structured text output |
| 🔴 **MemProcFS** | Memory as a virtual filesystem — mount memory as a drive | Windows GUI + Linux FUSE, but interactive |

### Key Volatility plugins for Slice 2+

| Plugin | What it finds | Stage |
|--------|---------------|-------|
| `windows.pslist` / `pstree` | Running processes + parent-child relationships | Any |
| `windows.cmdline` | Full command lines (catches encoded PowerShell) | Execution |
| `windows.netscan` | Active + historical network connections | C2 detection |
| `windows.malfind` | RWX memory regions backed by no file — injection/Cobalt Strike | Key plugin |
| `windows.dlllist` | Loaded DLLs per process (reflective-load detection) | Malware |
| `windows.handles` | Open handles — named pipes (Cobalt Strike default `msagent_##`, `MSSE-####-server`) | C2 |

**When memory matters:** fileless malware, active C2 sessions, injected code, encryption keys, plaintext credentials in LSASS. Memory is gone on power-off — always collect first (RFC 3227 volatility order).

---

## Timeline / Super-timeline

| Tool | Purpose | Agent-usable? |
|------|---------|---------------|
| 🟢 **log2timeline.py** (Plaso) | Parses 100+ artifact types into a single CSV timeline. On SIFT | CLI, slow but scriptable |
| 🟢 **psort.py** (Plaso) | Filter/sort the Plaso storage file, output CSV | CLI |
| 🟢 **pinfo.py** (Plaso) | Summary stats on a Plaso storage file | CLI |

**Workflow:** `log2timeline.py plaso.db image.E01` → `psort.py -o l2tcsv plaso.db > timeline.csv`. Output is a unified "super-timeline" across MFT, registry, event logs, prefetch, browser history, etc.

---

## Browser / User Artifacts

| Tool | Purpose | Agent-usable? |
|------|---------|---------------|
| 🔴 **NirSoft suite** | Browser history/cache/password extraction (WebBrowserPassView, BrowsingHistoryView, etc.) | Windows GUI |
| 🟢 **Hindsight** | Chromium-based browser history parser — Python, CSV output | Could add to SIFT |

---

## Malware / Static Analysis

| Tool | Purpose | Agent-usable? |
|------|---------|---------------|
| 🔴 **PEStudio** | Static PE analysis — imports, sections, strings, flags | Windows GUI |
| 🟡 **CyberChef** | Data transforms (Base64, XOR, decompression) | Web UI; has a CLI (`chef`) |
| 🟢 **scdbg** | Shellcode emulator / tracer | CLI |
| 🟢 **YARA** | Pattern-match malware signatures against files/memory | CLI, on SIFT |

Reference: see [cobalt-strike-artifacts.md](cobalt-strike-artifacts.md) and [empire-artifacts.md](empire-artifacts.md) for defender-perspective IOCs these tools surface.

---

## Event Logging (target-side, not investigation-side)

| Tool | Purpose | Relevance |
|------|---------|-----------|
| **Sysmon** | Enhanced Windows event logging (process creation w/ hashes, network connections, named pipes, file deletes, DLL loads) | Target system must have it installed *before* the attack. Referenced throughout the Cobalt Strike / Empire IOC docs. If evidence lacks Sysmon, many IOC patterns become invisible |

Our hackathon evidence (`base-wkstn-05`) may or may not have Sysmon — check during Slice 2 when we enumerate event logs.

---

## Tools on our SIFT Docker container (confirmed Slice 1)

From `which` output in [slice-1-docker-runbook.md](../../docs/runbooks/slice-1-docker-runbook.md):
- ✅ `mmls`, `fls`, `fsstat`, `icat` (Sleuth Kit)
- ✅ `7z`
- ✅ `ewfmount` / `ewfinfo` (libewf — needed for E01)
- ✅ RegRipper (`rip.pl`)
- ✅ Plaso (`log2timeline.py`, `psort.py`)
- ⏳ `volatility3` — **not yet installed**, add when memory analysis slice arrives
- ⏳ `EvtxECmd` — not yet installed, add when event logs become relevant
- ⏳ EZ Tools (.NET) — install via `apt install dotnet-runtime-8.0` + GitHub release when needed

---

## Tool selection by slice

| Slice | Question | Tools |
|-------|----------|-------|
| 1 ✅ | *What filesystem is on the E01?* | `mmls`, `fsstat`, `ewfinfo` |
| **2** | *What persistence mechanisms exist?* | `fls` (locate hives) → `icat` (extract bytes) → `rip.pl` with `user_run`, `run`, `services`, `schedagent`, `image_file_execution_options`, `userinit_mprlogonscript` plugins |
| 3 | *Do findings contradict each other?* | Same tool set + cross-check with Plaso timeline |
| 4 | *Initial access vector?* | + Plaso super-timeline + EvtxECmd on Security.evtx + browser history |
| 5 | *Fileless / injected payloads?* | + Volatility 3 (`malfind`, `cmdline`, `netscan`, `handles`) |

---

## Additional tools we could use — decisions

| Candidate | Verdict for hackathon | Why |
|-----------|----------------------|-----|
| **EZ Tools via dotnet on Linux** | 🟢 Yes, by Slice 4 | CSV output is far easier for the agent than EvtxECmd alternatives; worth the one-time dotnet install |
| **Volatility 3** | 🟢 Yes, Slice 5 | Required for memory analysis; `malfind` is the Cobalt Strike detection workhorse |
| **YARA** | 🟢 Yes, Slice 5 | Rule-based pattern match for known C2 / malware signatures — cheap, deterministic, pairs well with AI interpretation |
| **Hindsight** | 🟡 Maybe | Only if initial-access path involves browser (drive-by, download). Add if needed |
| **KAPE** | 🔴 No | Windows-native, overlaps with what our MCP server will already do, and we want custom orchestration anyway |
| **Autopsy** | 🔴 No | GUI-only; its value is the interactive investigator workflow, not agent automation |
| **Atomic Red Team** | 🟡 Out of scope, but useful | For generating *our own* ground-truth cases in Slice 4 eval harness if public cases aren't enough. See [lab-pwf.md](lab-pwf.md) for the full "plant evil, then hunt it" lab workflow |
| **MemProcFS** | 🔴 No | Interactive; Volatility covers the same surface programmatically |

---

## Decision principles

1. **CLI + structured output wins.** Agents reason over CSVs and structured text; they fight with GUIs.
2. **Wrap Sleuth Kit primitives, not Autopsy.** Every suite eventually shells to TSK. Skip the GUI layer.
3. **Defer installs until the slice needs them.** Volatility, EZ Tools, dotnet runtime — not until a slice's question requires them. Keeps the container slim and the surface area auditable.
4. **Each tool the agent uses must show up in `tool_calls.jsonl`** (Slice 2 audit trail). If it doesn't produce a loggable call, it doesn't belong in the agent's toolset.
