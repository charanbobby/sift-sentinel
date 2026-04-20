# MCP Server Tools — Quick Reference

**What this file is:** a plain-English guide to the forensic tools our MCP server exposes to the agent, written for someone new to digital forensics. Each tool has a plain-English "what investigative question does it answer?" — technical detail comes after.

**Source of truth:** [`experiments/slice-2-notebook/mcp_server/server.py`](../../experiments/slice-2-notebook/mcp_server/server.py). Tools are spawned over stdio by `docker exec -i --user sansforensics -e FIND_EVIL_CASE_ID=<case> sift python3 /opt/mcp/server.py`.

---

## The big picture

We have a **Windows disk image** (an `.E01` file — think of it as a compressed, sealed copy of a whole hard drive the attacker touched). We never boot it. We never mount it read-write. We poke at it with offline analysis tools that can read the raw bytes and understand Windows' filesystem (NTFS) + its internal structures.

The investigation question for Slice 2 is *"Given a Windows disk image suspected of compromise, what persistence mechanisms did the attacker install?"* — i.e. **what did the attacker set up so their malware survives a reboot?** On Windows there are ~8-15 common places to look: registry Run keys, installed services, scheduled tasks, login scripts, IFEO debugger hijacks, AppInit DLLs, etc. (Slice 2 is deliberately scoped to this artifact class; broader *"what happened on this host?"* investigations need specialist agents for execution history, event-log timeline, network artifacts, and user activity — future slices.)

Our MCP server gives the agent **four purpose-built tools** to answer that question. Think of them as the Lego blocks for a persistence hunt.

---

## What we have today

| Tool | Investigative question | Status |
|---|---|---|
| `fsstat_e01` | *"Is this even a Windows disk? How is it laid out?"* | ✅ live |
| `fls_list` | *"What files and folders are on the disk — including deleted ones?"* | ✅ live |
| `icat_extract` | *"Pull a specific file's raw bytes out of the image so I can hand it to another tool."* | ⬜ deferred (needed for C8) |
| `regripper_run` | *"Given a Windows registry file, what do the persistence-relevant sections say?"* | ⬜ deferred (needed for C8) |

### `fsstat_e01(e01_path)` — filesystem overview

**Plain English:** "Is this a Windows disk? What filesystem? Where does the file index live?"

Like reading the label on a box before opening it. Confirms the filesystem is `NTFS` (Windows' default — our whole persistence-hunting logic assumes this), tells you the volume serial, OS version hint, and where the **MFT** starts.

> **MFT** = Master File Table. NTFS's internal table-of-contents. Every file on the disk has a row in it. Think of it as the filesystem's `index.html` — if you can read the MFT, you can find every file (living or deleted).

Wraps the Sleuth Kit CLI `fsstat`. Fast (~200ms). Doesn't touch files. First call on any new image.

### `fls_list(e01_path, parent_inode=None, recurse=False)` — directory listing

**Plain English:** "List the files and folders at this location — and show me the deleted ones too."

Like `ls` on the raw disk image without booting it. Each entry comes with an **inode**.

> **Inode** = the filesystem's internal numeric ID for a file. Think of it as a primary key in a database table. Two files can have the same name in different folders, but their inodes are unique. Our other tools take inodes as input, so `fls_list` is how you discover them.

`parent_inode=None` lists the root. With `recurse=True`, you walk the whole subtree — expensive, but useful when you want to find e.g. every file named `NTUSER.DAT` on the disk without knowing exactly where it is.

Wraps Sleuth Kit's `fls`. The output looks like pipe-separated rows: `type | path | inode | mode | size | timestamps…`.

### `icat_extract(e01_path, inode, dest_path)` — *(deferred)*

**Plain English:** "I know a specific file is on this disk at inode N. Dump its raw bytes somewhere I can work with them."

Think of this as `cat <file>` — but pointed at a file trapped inside an offline disk image. We need it because most downstream forensic tools read files on disk, not files inside E01 blobs.

The `dest_path` must live under the writable case dir (`/home/sansforensics/cases/<case>/analysis/…`) — the `/mnt/hackathon/` evidence mount is read-only for forensic integrity.

Typical use: once `fls_list` tells you the `SOFTWARE` hive has inode 12345, `icat_extract` dumps those bytes to `analysis/hives/SOFTWARE` so `regripper_run` can parse them.

Wraps Sleuth Kit's `icat`.

### `regripper_run(hive_path, plugin)` — *(deferred)*

**Plain English:** "I've extracted a Windows registry file — what's in its [Run keys / Services / Scheduled Tasks] section?"

> **Registry hive** = a single file on disk that stores a chunk of Windows' settings. Think of a hive as a `.sqlite` file for Windows configuration — it's a binary file with a tree of keys/values. The important hives for persistence are `SOFTWARE`, `SYSTEM`, `SECURITY` (all under `C:\Windows\System32\config\`) and `NTUSER.DAT` (one per user, in their profile folder).

`regripper_run` runs one named **plugin** against one hive. Each plugin is a pre-built report for a specific registry path. We allowlist these plugins (the persistence-relevant ones):

| Plugin | What it reports | Why it matters for persistence |
|---|---|---|
| `run` | HKLM `…\Run` autostarts (system-wide) | Most common malware autostart |
| `user_run` | HKCU `…\Run` autostarts (per-user) | Same idea, user-scoped |
| `services` | Installed Windows services | Services run at boot as SYSTEM — high-value target |
| `schedagent` | Scheduled tasks (registry-side) | Tasks fire on triggers (login, idle, timer) |
| `image_file_execution_options` | IFEO "debugger" entries | Classic hijack: set "debugger" on notepad.exe → malware runs in its place |
| `appinit` | AppInit_DLLs | DLLs injected into every GUI app at launch |
| `userinit_mprlogonscript` | Winlogon Userinit / login scripts | Runs when any user logs in |

Any other plugin name → rejected at the MCP boundary.

Wraps the community tool `rip.pl` (Harlan Carvey's RegRipper).

### Typical workflow today

1. `fsstat_e01` — "Yep, it's NTFS. MFT at cluster 786432."
2. `fls_list` — find hive inodes (`SOFTWARE`, `SYSTEM`, `NTUSER.DAT`).
3. `icat_extract` *(deferred)* — dump hive bytes to `analysis/hives/`.
4. `regripper_run` *(deferred)* — iterate persistence plugins, collect findings.

**The gap:** this tells us *what exists* in persistence locations. It does NOT tell us:
- *When* a persistence entry was added (timeline).
- Whether the executable it points at *actually ran* (execution evidence).
- Whether that executable is known-malicious (hash lookup).
- What else of interest might be hiding in unallocated space (carving).

The wishlist below addresses those gaps.

---

## What the return shape looks like

Every tool call returns the same shape:

```json
{
  "tool_call_id": "<uuid>",
  "tool": "fsstat_e01",
  "args": {"e01_path": "/mnt/hackathon/..."},
  "exit_code": 0,
  "duration_ms": 178,
  "stdout_excerpt": "first ~64 KB of output (what the agent reads)",
  "stdout_hash": "sha256 of the FULL stdout",
  "stdout_path": "/home/sansforensics/cases/<case>/analysis/raw/<uuid>.stdout",
  "truncated": false
}
```

- **`stdout_excerpt`** — capped at 64 KB so the agent's prompt doesn't blow up on a giant file listing.
- **`stdout_path`** — full output saved to disk; use this when the agent needs to re-read, or for the audit trail.
- **`tool_call_id`** — the primary key for the audit trail. Every call also appends one row to `<case>/analysis/tool_calls.jsonl` — so every finding can be traced back to the exact tool invocation that produced it. This is the forensic integrity piece: nobody can claim we fabricated evidence.

---

## Tools we could build next (wishlist)

Not implemented. Ranked by *what investigative question would they unblock for Slice 2*. High = we'd genuinely want this for the persistence question. Medium = useful corroboration. Low = stretch / later slice.

### Group A — "When did this happen?" (timeline reconstruction)

| Tool | Investigative question | Wraps | Why useful | Priority |
|---|---|---|---|---|
| `mft_parse` | *"Give me the timestamps (create / modify / access / MFT-change) for every file, so I can build a timeline."* | `analyzeMFT.py` or `MFTECmd` | Attackers often install persistence right after initial access — a timeline pins it | Medium |
| `usn_parse` | *"What files have been created / modified / renamed / deleted recently, in order?"* | `UsnJrnl2Csv` or custom parser | NTFS's change journal — survives deletion, shows attacker file operations | Medium |
| `timeline_build` | *"Build a super-timeline combining filesystem + registry + event logs events."* | `log2timeline` / `plaso` | THE canonical DFIR timeline tool. Heavy — many hours to run — but one call answers "when" for everything | Low (heavy, later slice) |

### Group B — "What actually ran?" (execution evidence)

| Tool | Investigative question | Wraps | Why useful | Priority |
|---|---|---|---|---|
| `prefetch_parse` | *"What programs were actually executed on this machine, and when?"* | `PECmd` or `pf` parser | Windows' Prefetch folder logs every .exe that runs. Directly corroborates persistence: a Run key without a matching prefetch entry is suspicious (malware or recently-added) | **High** |
| `amcache_parse` | *"What programs were installed or executed, even if now deleted?"* | `AmcacheParser` | Amcache.hve is a registry hive that keeps execution records for ~months. Often reveals deleted malware names + hashes | **High** |
| `shimcache_parse` | *"Same as amcache but with less detail — used when amcache is absent."* | regripper `shimcache` plugin or `AppCompatCacheParser` | Older Windows versions / certain configurations keep ShimCache instead of Amcache | Medium |
| `evtx_parse` | *"What did Windows log — logins, service starts, process creation?"* | `python-evtx` or `EvtxECmd` | Event Logs (.evtx) are Windows' security/system journal. Service creation events (7045) + scheduled task creation (106) + process creation (4688) are direct persistence corroboration | **High** |

### Group C — "What's this file? Is it malicious?"

| Tool | Investigative question | Wraps | Why useful | Priority |
|---|---|---|---|---|
| `file_hash` | *"Compute md5/sha1/sha256 of a file extracted from the image."* | `hashlib` (pure Python) | Prereq for any hash-based lookup; cheap and easy | **High** (trivial add) |
| `vt_lookup` | *"Is this hash known-malicious on VirusTotal?"* | VirusTotal API | Turns a hash into a known-bad/known-good verdict. External API call — needs an API key, rate limits apply | Medium (external dep) |
| `strings_scan` | *"Pull printable strings from this file/offset — URLs, emails, suspicious paths."* | `strings` + regex filters | Cheap triage for unknown binaries | Low |

### Group D — "What did the user do?" (user activity)

| Tool | Investigative question | Wraps | Why useful | Priority |
|---|---|---|---|---|
| `shellbags_parse` | *"Which folders did a user open in Explorer?"* | regripper `shellbags` plugin | Sometimes persistence is placed in a folder the user opens — shellbags confirm the user was there | Low |
| `browser_history` | *"What URLs did this user visit / download?"* | `hindsight` or sqlite parsing | Initial access often comes from a browser. Out of persistence scope but important upstream | Low (initial-access, not persistence) |

### Group E — "What's hiding in the free space?"

| Tool | Investigative question | Wraps | Why useful | Priority |
|---|---|---|---|---|
| `file_carve` | *"Scan unallocated space for file headers — recover deleted files."* | `foremost` or `scalpel` | Attackers delete their tools on cleanup; carving recovers them | Low (expensive; later slice) |

### Recommendation for Slice 2 scope

If we had time for **exactly two more tools** after `icat_extract` + `regripper_run`, the best ROI is:

1. **`file_hash`** — trivial to add, makes every extracted file uniquely identifiable. Prereq for anything else. One-hour addition.
2. **`prefetch_parse`** or **`amcache_parse`** — turns our "this persistence entry points at `updater.exe`" finding into "…and `updater.exe` actually ran on 2018-03-15 at 14:22". Massive uplift in finding quality.

Everything else is either "nice-to-have for this question" or "belongs to a different investigative question" (initial access, lateral movement, exfiltration).

---

## Discipline enforced server-side

Every tool call goes through the same guardrails — not for style points, but because an agent calling subprocess is one compromised prompt away from `rm -rf`. Eight things the server does on every call:

1. **argv arrays only** — no `shell=True`, no string interpolation into a shell. Agent-controlled input never gets parsed by bash.
2. **Typed inputs** — Pydantic models on every tool argument. Wrong types fail at the MCP boundary, before the filesystem is touched.
3. **Read path allowlist** — `fsstat_e01` / `fls_list` / `icat_extract` only accept paths under `/mnt/hackathon/` (the read-only evidence mount). Any other path → rejected.
4. **Write path allowlist** — `icat_extract`'s `dest_path` must live under `/home/sansforensics/cases/<case>/analysis/`. No writing anywhere else.
5. **Plugin allowlist for `regripper_run`** — only the persistence-related plugins (see table above). Any other plugin name → rejected.
6. **Output truncation** — each tool's stdout cap at 64 KB for the agent; full output persisted to disk + sha256 hashed for the audit trail.
7. **Audit trail** — one JSONL line per call in `<case>/analysis/tool_calls.jsonl` with uuid, args, argv, exit code, duration, output hash + path. This is the tamper-evident chain that lets any finding be traced to its source.
8. **stdout is reserved for MCP protocol framing** — all diagnostics go to stderr. Mixing them breaks the protocol.

---

## DFIR background (deeper learning when you want it)

- **Sleuth Kit** (fsstat / fls / icat): foundational offline filesystem analysis. [training/blue-cape-dfir-foundations/forensic-tools.md](../../training/blue-cape-dfir-foundations/forensic-tools.md) §*Sleuth Kit*.
- **RegRipper** + Windows registry layout: same file §*Registry analysis*.
- **Persistence techniques** — MITRE ATT&CK tactic TA0003 "Persistence". The plugins we allowlist map 1:1 to common sub-techniques (Registry Run Keys → T1547.001, Services → T1543.003, Scheduled Tasks → T1053.005, IFEO → T1546.012, etc.).
