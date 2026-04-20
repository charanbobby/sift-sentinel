# DFIR Investigation Scope — The Full Map

**Purpose:** give a DFIR newbie (the project owner) a mental model of a complete digital-forensics investigation, so scope decisions on this project are made against the real size of the field, not a cartoon version of it. Authored 2026-04-19 during a scope-expansion conversation when the question came up: *"are persistence and initial access the only two things DFIR covers?"* Short answer: no — they're ~20% of it.

---

## The attack lifecycle — what investigators reconstruct

A complete investigation traces an incident through the MITRE ATT&CK tactics (the "why" an attacker does something). In the order they typically appear on a compromised host:

| # | Stage | What the attacker is doing | Example artifacts |
|---|---|---|---|
| 1 | Reconnaissance | Gathering info about the target | External scans, dropped enum scripts |
| 2 | Resource Development | Standing up infrastructure | Attacker-side C2 domains, phishing kits |
| 3 | **Initial Access** | Getting in | Phishing emails, exploited services, stolen creds, webshell files |
| 4 | **Execution** | Running their first malicious code | Prefetch, Shimcache, Amcache, event logs (4688 process creation, 4104 PowerShell) |
| 5 | **Persistence** | Making sure they stay after reboot | Registry Run keys, services, scheduled tasks, WMI event subscriptions, COM hijacking |
| 6 | Privilege Escalation | Getting higher access | UAC-bypass evidence, token manipulation, exploit traces |
| 7 | Defense Evasion | Avoiding detection | Timestomping (SI vs FN mismatch), log clearing, process hollowing, indirect execution |
| 8 | Credential Access | Stealing creds | LSASS dumps, SAM access, Kerberoasting, DCSync |
| 9 | Discovery | Mapping the environment | AD enumeration, network-recon commands in history |
| 10 | Lateral Movement | Moving to other systems | RDP/SMB logons, admin shares, PsExec artifacts, remote service installs |
| 11 | Collection | Gathering target data | Staged ZIPs, keylogger output, clipboard dumps |
| 12 | Command & Control | Keeping the shell open | Beacon configs, unusual outbound connections, DNS tunneling, Domain-fronting |
| 13 | Exfiltration | Getting data out | Rclone/curl execution, cloud uploads, PowerShell webclient |
| 14 | Impact | Causing damage | Encryption artifacts, wiping, ransom notes, account lockouts |

## Artifact surfaces — where the evidence lives

No single artifact answers a full investigation. Investigators cross-reference across many surfaces:

### Host-level (disk + memory)

- **NTFS filesystem:** MFT, USN Journal, $LogFile, MACE timestamps, deleted files, slack space, Alternate Data Streams.
- **Windows Registry:** SYSTEM, SOFTWARE, SECURITY, SAM, NTUSER.DAT (per user), UsrClass.dat (per user), Amcache.hve.
- **Windows Event Logs (.evtx):** Security (4624 logon, 4688 process, 4672 privilege, 4697/7045 service install), System, Application, Sysmon (operational), PowerShell/Operational, Defender/Operational, Microsoft-Windows-TaskScheduler/Operational.
- **Execution artifacts:** Prefetch (`.pf`), Shimcache (in SYSTEM hive), Amcache.hve, UserAssist, MUICache, RecentFileCache.
- **Scheduled tasks:** `C:\Windows\System32\Tasks\*` (XML files) + registry SchedulingAgent keys.
- **User activity:** browser history (SQLite DBs), browser cache, LNK files, Jump Lists, Shellbags, recent-docs (NTUSER), typed URLs, WordWheelQuery.
- **Services / drivers:** Services subkey of SYSTEM hive, driver files in `drivers\`, WMI repository at `C:\Windows\System32\wbem\Repository\`.
- **Memory:** running processes + command lines (Volatility `pslist`/`pstree`), network connections (`netscan`), injected code / reflective DLLs (`malfind`, `ldrmodules`), credentials (`hashdump`, `mimikatz`-style), encryption keys (in-memory only), loaded drivers / rootkits.

### Network-level

- PCAPs (full capture), NetFlow (connection metadata only), firewall logs, DNS logs, proxy logs, TLS metadata (SNI, JA3), IDS/IPS alerts, lateral-movement traffic (internal SMB/RDP/WinRM/PSRemoting).

### Application-level

- Web server logs, database audit logs, email server logs (Exchange/Postfix), authentication logs (AD, SSO), VPN logs.

### Cloud-level

- AWS CloudTrail, Azure AD sign-in + audit, Google Workspace audit, O365 Unified Audit Log, identity-provider logs, storage-access logs, API call logs.

### Identity / credential surfaces

- Active Directory: DC replication (DCSync evidence), Kerberos tickets (Kerberoasting/Golden Ticket evidence), NTLM hashes, service-principal names.

---

## The investigation questions these artifacts answer

A real engagement tries to answer some subset of:

1. **Who did it?** (attribution — rarely decisive)
2. **When did it start?** (initial-access time — dictates the "time window" for every other analysis)
3. **How did they get in?** (initial-access vector — informs remediation)
4. **What did they do?** (chronological timeline of actions)
5. **What did they take?** (exfiltration — dictates breach-notification obligations)
6. **Are they still in?** (current persistence — dictates incident containment urgency)
7. **What's the blast radius?** (lateral movement + access scope — dictates systems to re-image)
8. **What needs to happen to contain + remediate?** (the actionable output of the investigation)
9. **Is this one actor or multiple?** (modern attacks often have an Initial Access Broker + separate ransomware operator — artifacts may come from two different campaigns overlapping in time)

---

## Where this project currently sits

**Our pipeline answers a narrow slice of question 3 + question 6**:
- Question 3 (initial access): **not yet** — Step 0 + Critic is all Q1 (persistence).
- Question 6 (are they still in — via persistence): **yes**, on NTFS + Registry only.

**Our current tools** (`fsstat_e01`, `fls_list`, `icat_extract`, `regripper_run`) cover:
- NTFS filesystem metadata + directory listings + file extraction.
- Windows Registry (SYSTEM + SOFTWARE + NTUSER) — any plugin regripper ships.

**Out of scope by deliberate choice** (see PLAN.md Key Decisions, 2026-04-19):
- Memory forensics (needs Volatility MCP + memory captures).
- Network forensics (PCAPs / firewall / DNS).
- Cloud-log forensics.
- Non-Windows / cross-platform disk forensics (Linux/macOS filesystems).
- Event log parsing — `*.evtx` files live on disk but aren't parsed by our current tools (note: candidate for Slice 3.5 / Slice 4 expansion if we answer initial-access + timeline questions).
- Prefetch / Shimcache / Amcache / LNK / Jump Lists / browser artifacts — all disk-resident but not in current tool set.
- Scheduled-task XML files (`C:\Windows\System32\Tasks\*`) — disk-resident, not parsed.

The "deliberate narrowing" framing is specifically so these gaps read as **documented extension points, not unfinished work** — critical for the hackathon demo narrative.

---

## For scope-expansion decisions

When considering whether to add a new investigation question or artifact type, the right framing is:

1. Which of the 14 attack-lifecycle stages does this cover?
2. Which of the 9 investigation questions does it answer?
3. What tools are needed and do they exist on SIFT (or runnable in Linux)?
4. Is the ground truth for this investigation available publicly, or do we need to hand-annotate?
5. Does it generalize the existing pipeline architecture (same EXTRACT → PLAN → EXECUTE → INTERPRET skeleton), or does it require a new flow?

A scope expansion that can't answer (5) in favor of "yes, same architecture, just new tools and new prompt" is the architectural differentiation story. A scope expansion that requires a fundamentally new pipeline is a second project.
