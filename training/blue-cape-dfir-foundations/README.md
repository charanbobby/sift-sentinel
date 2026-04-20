# Blue Cape Security — DFIR Foundations & Techniques

**URL:** https://bluecapesecurity.com/courses/dfir-foundations-techniques-readiness/
**Hours:** 8 hrs video + case files + 70-question assessment
**Tools:** Volatility3, Arsenal Image Mounter, KAPE, forensic utilities

## Purpose

Build forensics domain knowledge, then distill it into a SKILL.md that captures investigative reasoning — not tool syntax (Protocol SIFT already handles that).

## Focus Areas for SKILL.md Output

Capture the **thinking**, not the commands:

- **When** to use which tool (decision logic, not flags)
- **What** artifact combinations confirm vs. suggest (e.g., Shimcache + Amcache = presence, not execution)
- **How** to sequence an investigation (triage order, what to check first)
- **What** to corroborate (never trust a single artifact)
- **Where** analysts commonly get it wrong (false positives, misinterpretations)
- **How** to structure findings (confirmed vs. inferred, confidence levels)

## Course Notes

### NIST SP 800-86 — The Forensic Process

**Source:** https://csrc.nist.gov/pubs/sp/800/86/final

The foundational framework. Four phases, sequential, each feeds the next:

```
Collection → Examination → Analysis → Reporting
```

| Phase | What | Integrity Rule |
|-------|------|----------------|
| **Collection** | Identify, label, record, acquire data from relevant sources | Preserve integrity during acquisition |
| **Examination** | Process collected data (automated + manual), extract data of interest | Preserve integrity during processing |
| **Analysis** | Analyze extracted data to derive useful information, identify findings | Findings must trace back to examined data |
| **Reporting** | Report results, describe actions, recommend improvements | Must be reproducible from the evidence |

**Key insight for our agent:** This is the pipeline decomposition. Each phase is a reviewable step — maps directly to SKILL.md Phase 5a (Extract → Reconcile → Plan → Execute). The agent should produce artifacts at each phase boundary, not just a final report.

**NIST framing:** IT forensics view, not law enforcement. Focus is on incident response and operational problem-solving, not courtroom evidence (though integrity standards still apply).

#### Collection — Order of Volatility (RFC 3227)

Collect the most volatile evidence first — it disappears fastest:

```
1. Memory (RAM)          ← gone on power off
2. Disk (filesystem)     ← persists but can be overwritten
3. Logs (event logs)     ← persists but can rotate/be cleared
```

**Why this matters for our agent:** When the agent triages a live system, it should prioritize memory acquisition before disk imaging before log collection. If it starts with logs while memory is still available, it risks losing the most valuable evidence. The agent's investigation sequencing logic needs this priority order baked in.

### Threat Landscape — Attack Chain & Actor Roles

**Source:** https://redcanary.com/threat-detection-report/trends/ransomware/

Modern attacks involve **separate actors** with different roles:

```
Initial Access → Recon → Lateral Movement → Exfiltration → Encryption
|____________|   |_______________________________________________|
      ↓                              ↓
 Initial Access              Other Adversary
    Broker              (e.g., Ransomware operator)
```

| Actor | Role | Business Model |
|-------|------|----------------|
| **Ransomware-as-a-Service (RaaS)** | Build and sell/license ransomware toolkits | Subscription/affiliate model — they're businesses |
| **Initial Access Broker (IAB)** | Gain initial foothold into target systems, then sell that access | Marketplace — sell credentials, VPN access, webshells to highest bidder |

**Why this matters for our agent:** The artifacts left behind differ by actor. The IAB leaves initial access traces (phishing emails, exploited vulnerabilities, stolen credentials). The ransomware operator leaves recon, lateral movement, exfiltration, and encryption artifacts. The agent needs to recognize it may be looking at **two separate attack chains** overlapping on the same system, potentially with a time gap between initial access and the rest.

### Ransomware Attack Lifecycle (5 Stages)

**Source:** https://securityintelligence.com/posts/how-ransomware-attacks-happen/

```
Stage 1: Initial Access
    Phishing email or exploit of internet-facing service
        ↓
Stage 2: Post-Exploitation Foothold
    Establish persistence (scheduled tasks, run keys, RAT, etc.)
    Command and Control (C2) established
    Second-stage malware/post-exploitation toolkits downloaded
        ↓
Stage 3: Recon, Credential Harvesting, Lateral Movement
    Gather credentials (LSASS, SAM, cached creds, Kerberos)
    SMB lateral movement
    Interactive attacker establishes access to other systems
        ↓
Stage 4: Data Collection and Exfiltration
    Gather credentials + identify high-value targets
    Data exfil (WinSCP, RClone, cURL, etc.)
        ↓
Stage 5: Ransomware Deployment
    Obtain domain admin privileges
    Stage ransomware on share
    Deploy via domain admin using GPO/PsExec/SMS/Group Policy
```

**Artifacts per stage (what the agent should look for):**

| Stage | Key Artifacts |
|-------|--------------|
| 1 - Initial Access | Phishing emails, exploit logs, webshell files, suspicious inbound connections |
| 2 - Foothold | Scheduled tasks, registry run keys, new services, C2 beacons, unknown processes |
| 3 - Recon/Lateral | LSASS dumps, SAM access, Kerberoasting, SMB connections, RDP logs, new accounts |
| 4 - Exfiltration | Large outbound transfers, WinSCP/RClone/cURL execution, staging directories |
| 5 - Deployment | Domain admin usage, GPO modifications, PsExec execution, mass file encryption |

**Why this matters for our agent:** This is the investigation roadmap. When the agent finds an artifact, it should map it to a stage and then look for artifacts from adjacent stages to build the full timeline. Finding LSASS dump artifacts (Stage 3) should trigger the agent to look backwards for the initial access vector (Stage 1-2) and forwards for exfiltration evidence (Stage 4).

### Attack Infrastructure — Three Adversary Components

```
ADVERSARY SIDE                              TARGET SIDE

┌──────────────────┐                     
│  Phishing Server │ ── (email) ──────→  User clicks/opens
└──────────────────┘                        ↓ (user action = detonation)
                                            ↓
┌──────────────────┐                        ↓
│ Download Server  │ ←── pulls payload ── Target Machine
└──────────────────┘                        ↓
                                            ↓
┌──────────────────┐                        ↓
│ C2 Callback      │ ←→ ongoing comms ←→ Compromised Machine
│ Server           │    (commands, exfil)
└──────────────────┘
```

| Component | Purpose | Artifacts to look for |
|-----------|---------|----------------------|
| **Phishing server** | Deliver the lure | Email headers, sender domains, malicious URLs/attachments |
| **Download server** | Host the payload | Outbound HTTP/HTTPS connections, downloaded executables, browser/download history |
| **C2 callback server** | Persistent command channel | Beaconing patterns, unusual outbound connections, DNS queries to suspicious domains |

**Key point:** Everything starts with a **user action** — click, open, enable macros. The phishing server is inert until someone triggers it. This is why the initial access stage often leaves the most human-readable artifacts (emails, browser history, file downloads).

**Why this matters for our agent:** When investigating, the agent should trace the infrastructure chain: find the C2 traffic → identify the download source → find the original phishing vector. Each server leaves different network artifacts. The agent should also look for the user action that detonated the attack (email opened timestamp, file download timestamp) as the anchor point for the investigation timeline.

### Lateral Movement & C2 Stealth

Once one machine is compromised, the threat **propagates internally**:

- **Lateral movement uses internal protocols** — RPC, SMB, etc. between systems inside the firewall
- **No internet required** — attacker moves laterally without touching the perimeter
- **SMTP can also be a vector** — internal email spreading malware to other users/systems
- **C2 communication is deliberately hidden** — encrypted, tunneled, mimicking legitimate traffic, or using uncommon channels. It may or may not be visible in network captures

**Key forensic implication:** Don't assume you'll see the full picture in network logs. The C2 channel may be invisible. Focus on:
- **Host artifacts** as primary evidence (process execution, file creation, registry changes)
- **East-west traffic** (internal-to-internal) for lateral movement — not just north-south (internal-to-internet)
- **Multiple compromised hosts** — finding evil on one machine means looking for the same indicators across all systems in the environment

**Why this matters for our agent:** The agent shouldn't stop at one host. When it finds indicators of compromise, it should check whether those same artifacts appear on other systems. Lateral movement means the investigation scope expands. The agent also can't rely solely on network evidence for C2 — host-based artifacts (process trees, scheduled tasks, persistence mechanisms) may be the only evidence available.

### Enterprise DFIR Domains — Skill Development Map

| Fundamentals | Intermediate | Advanced |
|-------------|-------------|----------|
| Active Directory Domain Services | Data Acquisition Techniques | Red Team Attack Operations |
| Authentication Protocols | Windows Forensic Analysis | Enterprise Incident Response |
| Group Policy Objects | Malware Analysis | Threat Hunting |
| Living Off the Land Tools | Network Traffic Analysis | Cyber Threat Intelligence |
| Windows System Internals | Cloud Forensic Analysis | |
| SOC Tools and Applications | | |

**Where we sit for the hackathon:** The fundamentals column is what our agent needs to understand as context (AD, auth protocols, GPO, LOTL, Windows internals). The intermediate column is what our agent will actually *do* (acquisition, forensic analysis, network traffic). The advanced column is the aspiration — threat hunting is literally "Find Evil."

**Living Off the Land (LOTL)** is key — attackers use legitimate system tools (PowerShell, certutil, wmic, bitsadmin) instead of dropping custom malware. The agent needs to flag suspicious *usage patterns* of normal tools, not just look for known-bad binaries.

### MITRE ATT&CK Framework

**Reference:** https://attack.mitre.org/

The common language for describing adversary behavior. Maps tactics (the *why*) to techniques (the *how*):

| Tactic | What the attacker is trying to do |
|--------|----------------------------------|
| Reconnaissance | Gather info about the target |
| Resource Development | Set up infrastructure (phishing servers, C2, etc.) |
| Initial Access | Get in (phishing, exploits, valid accounts) |
| Execution | Run malicious code |
| Persistence | Stay in (survive reboots, credential changes) |
| Privilege Escalation | Get higher access |
| Defense Evasion | Avoid detection |
| Credential Access | Steal credentials (LSASS, SAM, Kerberos) |
| Discovery | Map the environment |
| Lateral Movement | Move to other systems |
| Collection | Gather target data |
| Command and Control | Communicate with compromised systems |
| Exfiltration | Steal data out |
| Impact | Disrupt/destroy (encryption, wiping) |

**Why this matters for our agent:** MITRE ATT&CK is the shared vocabulary. When the agent records a finding, it should map it to a technique ID (e.g., T1059.001 = PowerShell execution, T1003.001 = LSASS memory dump). Valhuntir's report-mcp already does MITRE mapping — our agent should too. Judges will expect findings tagged with ATT&CK technique IDs.

### C2 Frameworks — Know What You're Hunting

Common C2 frameworks the agent needs to recognize artifacts from:

| Framework | What It Is | Key Artifacts |
|-----------|-----------|---------------|
| **Cobalt Strike** | Commercial red team tool, heavily abused by real attackers | Beacon processes, named pipes, malleable C2 profiles, shellcode injection, Cobalt Strike watermarks in memory |
| **Empire / PowerShell Empire** | PowerShell-based post-exploitation framework | Encoded PowerShell commands, staged listeners, obfuscated scripts, WMI/scheduled task persistence |

**TODO:** ~~Spend time understanding these frameworks~~ Done — see [cobalt-strike-artifacts.md](cobalt-strike-artifacts.md) and [empire-artifacts.md](empire-artifacts.md) for full defender-perspective breakdowns.

### Understanding Data Sources

Four categories of evidence sources across the network:

```
                        Internet
                           |
                      [ Firewall ] ← Network data source
                           |
                       [ Switch ]
                      /    |     \
               Office    Internal    DMZ
               Network   App Svcs   (S1, S2)
              PC1-PC3    S3, S4
```

| Data Source | What It Provides | Examples |
|-------------|-----------------|----------|
| **Endpoint** | Host-level artifacts from individual machines | Memory dumps, disk images, event logs, registry, prefetch, file system artifacts |
| **Network** | Traffic flowing between systems | PCAPs, firewall logs, IDS/IPS alerts, netflow, DNS logs, proxy logs |
| **Application** | Logs from services and software | Web server logs, database logs, email server logs, authentication logs |
| **Cloud** | Cloud platform telemetry | Cloud trail/audit logs, storage access logs, identity provider logs, API logs |

**Why this matters for our agent:** The agent needs to know which data source to query for which stage of the attack. Network data catches C2 and lateral movement. Endpoint data catches execution and persistence. Application data catches initial access (email, web exploits). Cloud data catches exfiltration and credential abuse. A thorough investigation correlates across all four.

### Windows OS Components for Forensics

The core Windows artifacts an investigator (and our agent) needs to understand:

| Component | What It Tells You | Key Forensic Value |
|-----------|------------------|-------------------|
| **NTFS** | File system — file creation, modification, deletion, timestamps | MFT ($MFT) records every file, USN Journal tracks changes, $LogFile for transactions. Timestamps can reveal anti-forensics (timestomping) |
| **Windows Registry** | System and user configuration, persistence, program execution | Run keys (persistence), MRU lists (user activity), USB history, installed software, user accounts, network connections |
| **Windows Event Logs** | System, security, and application events | Logons (4624), process creation (4688), service installs (7045), PowerShell (4104), scheduled tasks, account changes |
| **Other Windows Artifacts** | Supplementary evidence sources | Prefetch (program execution), Shimcache/Amcache (execution evidence), Shellbags (folder access), Jump Lists (recent files), LNK files (shortcuts), SRUM (resource usage) |

**Why this matters for our agent:** These four categories are the primary evidence sources for endpoint forensics on Windows — which is the most common target in the hackathon's case data. The agent needs to know which component answers which investigative question:
- **When** was something executed? → Prefetch, Event Logs, NTFS timestamps
- **What** persisted across reboots? → Registry, Scheduled Tasks, Services
- **Who** did it? → Event Logs (logon events), Registry (user SIDs)
- **What changed?** → USN Journal, MFT, Registry timeline

And critically — **Memory**:

| What memory reveals | Why it's unique |
|--------------------|-----------------| 
| Running processes + command lines | Shows what was active at capture time — including fileless malware that never touches disk |
| Network connections | Active C2 sessions, lateral movement connections |
| Injected code / DLLs | Cobalt Strike Beacons, Empire agents, reflective-loaded payloads |
| Credentials | Plaintext passwords, Kerberos tickets, NTLM hashes in LSASS |
| Encryption keys | Ransomware keys, C2 session keys — only exist in memory |
| Loaded drivers / rootkits | Kernel-level threats invisible to disk forensics |

Memory is the **most volatile** (order of volatility — collect first) but also the **richest** — it's the only place to find fileless malware, active C2 sessions, and decrypted content. Once power is lost, it's gone.

### Data Acquisition Options

Two approaches — choose based on the situation:

| | A) Live Data Collection | B) Forensic Duplication / Disk Imaging |
|--|------------------------|---------------------------------------|
| **What** | Collect volatile evidence and files without full drive duplication | Full bit-for-bit copy of disk, partition, or logical volume |
| **When** | Need speed, collecting at scale across many endpoints | Need complete evidence preservation, deep analysis |
| **Mode** | Live (system running) | Live or offline (system powered down) |
| **Formats** | Triage packages (KAPE, velociraptor) | **Raw** (bit-to-bit copy), **E01** (Encase evidence file), **AFF** (advanced forensics format) |
| **Hardware** | Acquisition toolkit only | Write blocker + storage medium |
| **Trade-off** | Faster, less complete — may miss deleted files, slack space | Slower, complete — preserves everything including unallocated space |

**Key decision:** You don't always need the full disk. At enterprise scale (hundreds of endpoints), live collection of targeted artifacts is practical. For deep-dive investigation of key systems, full disk imaging preserves everything.

**Write blocker** is critical for disk imaging — prevents any writes to the evidence drive during acquisition, maintaining forensic integrity.

**Why this matters for our agent:** The hackathon case data will come in these formats (E01 disk images, raw memory dumps). The agent needs to know what it's working with — a full disk image gives access to everything (deleted files, slack space, unallocated), while a triage collection gives only targeted artifacts. The agent should adapt its investigation approach based on what's available.

### VM Image Formats — Disk vs Memory

#### Disk Image Formats
- **Fixed-size vs dynamic** (expandable) allocation
- **Snapshots:** point-in-time (incremental vs. full)
- Hypervisor formats:
  - **VMDK** — VMware's virtual disk format
  - **VHD/VHDX** — Microsoft's virtual disk format (Hyper-V)
  - **VDI** — Oracle VirtualBox default disk format

#### Memory Image Formats
| Hypervisor | Format | Saved State File |
|-----------|--------|-----------------|
| VirtualBox | **ELF** (memory dump format) | `.sav` |
| VMware | **VMEM, VMSS** (memory files) | `.vmsn` |
| Hyper-V | **BIN** (memory file format) | `.vsv` |

**Why this matters for our agent:** The agent needs to detect the format it's been given and route to the correct tool. Volatility handles ELF, VMEM, and raw dumps but needs the right profile/format handler. Disk images need mounting (ewfmount for E01, or direct VMDK/VHD access) before filesystem tools can work on them.

### Data Examination — NTFS (New Technology File System)

Underlying file system for any Windows OS.

**Structure:** Disk → Partition → File System (Volume). Each partition can be NTFS, FAT32, etc.

**NTFS Features:**
- **Journaling** — tracks file system transactions for crash recovery
- **Alternate Data Streams (ADS)** — hidden data streams attached to files (attackers hide payloads here)
- **Volume Shadow Copies** — point-in-time snapshots (can recover deleted/modified files)
- **Access Control Lists** — file/folder permissions
- **Compression** — built-in file compression
- **Max 2TB** per partition (MBR) or larger with GPT

**Important NTFS Forensic Artifacts:**

| Artifact | What It Records | Forensic Value |
|----------|----------------|----------------|
| **$MFT** (Master File Table) | Record of every file and directory on the volume | The index of everything — file names, timestamps, sizes, parent directories. Even deleted files retain MFT entries until overwritten |
| **$LogFile** | MFT metadata changes (journal) | Tracks recent changes to file metadata — can reveal timestamp manipulation |
| **$UsnJrnl** (USN Journal) | File change tracking | Records file creates, deletes, renames, data changes. High-volume changelog — great for timeline building |

**Why this matters for our agent:** These three artifacts ($MFT, $LogFile, $UsnJrnl) are the foundation of disk forensics. The agent should parse $MFT first to understand what's on the disk, then use $UsnJrnl to build a timeline of changes, and check $LogFile to detect if timestamps were tampered with (timestomping).

#### MFT Record Structure

Every file and directory on NTFS gets an MFT record. Each record contains:

| Component | What It Stores |
|-----------|---------------|
| **Record Header** | Signature ("FILE"), sequence number, flags (in-use / deleted), record size |
| **$STANDARD_INFORMATION (SI)** | Timestamps (Created, Modified, Accessed, Entry Modified — "MACE"), file permissions, flags. **Updated by the OS** — can be manipulated by tools like timestomp |
| **$FILE_NAME (FN)** | File name, parent directory reference, and its own set of MACE timestamps. **Updated by the kernel** — harder for attackers to manipulate |
| **$DATA** | The actual file content (or pointers to clusters if large) |

**Key forensic insight — SI vs FN timestamps:**
- `$STANDARD_INFORMATION` timestamps can be **faked** (timestomping — attackers backdate files to blend in)
- `$FILE_NAME` timestamps are **kernel-managed** and much harder to tamper with
- **If SI timestamps are older than FN timestamps, that's a red flag for timestomping** — the file claims to be old but the kernel knows it was created recently

**Why this matters for our agent:** When the agent parses MFT records, it should compare SI and FN timestamps. A mismatch (SI < FN) is a strong indicator of anti-forensics. This is exactly the kind of self-correction logic the judges want — the agent detects something doesn't add up and flags it.

### Eric Zimmerman's Tools (EZ Tools)

**What:** Collection of parsers for Windows artifacts. The go-to toolkit for extracting and converting Windows forensic data into analyzable formats.

**URL:** https://ericzimmerman.github.io/

**Workflow demonstrated in course:**
```
Hidden system file ($MFT on C:\)
    → Extract to triage folder (using KAPE or FTK Imager)
    → Parse with EZ Tool (MFTECmd.exe)
    → Output as CSV
    → Analyze in Timeline Explorer or spreadsheet
```

**Key EZ Tools:**

| Tool | What It Parses | Output |
|------|---------------|--------|
| **MFTECmd** | $MFT (Master File Table) | CSV — every file/directory with all timestamps, sizes, paths |
| **PECmd** | Prefetch files (.pf) | CSV — program execution history with timestamps and run counts |
| **LECmd** | LNK files (shortcuts) | CSV — recently accessed files, paths, timestamps |
| **JLECmd** | Jump Lists | CSV — recent files per application |
| **SBECmd** | Shellbags | CSV — folder access history (even deleted folders) |
| **RECmd** | Windows Registry | CSV — parse specific registry keys/values |
| **AppCompatCacheParser** | Shimcache | CSV — evidence of file presence on system |
| **AmcacheParser** | Amcache.hve | CSV — program execution with SHA1 hashes |
| **EvtxECmd** | Windows Event Logs (.evtx) | CSV — parsed event log entries |
| **Timeline Explorer** | Any EZ Tool CSV output | Interactive GUI for sorting, filtering, searching forensic data |

**Why this matters for our agent:** EZ Tools are already on SIFT Workstation. The agent's workflow should mirror this pattern — extract artifact → parse with EZ Tool → output CSV → analyze structured data. Structured CSV output is much easier for an AI agent to reason about than raw binary artifacts. The agent should call these tools via MCP and work with the CSV output.

#### NTFS Resident vs Non-Resident Files

| Type | Where data lives | When |
|------|-----------------|------|
| **Resident** | Data stored directly inside the MFT record itself | Small files (~700 bytes or less) — the $DATA attribute fits within the MFT entry |
| **Non-Resident** | Data stored in clusters elsewhere on disk, MFT record holds pointers (data runs) to those clusters | Larger files — content is fragmented across the disk |

**Forensic implication:** When the MFT shows a file as **non-resident**, the actual content isn't in the MFT — you need to follow the data run pointers to find the file content scattered across disk clusters. For deleted non-resident files, the MFT entry may still exist but the clusters could already be overwritten by new data.

**Why this matters for our agent:** When the agent encounters a non-resident file of interest (like a malware payload or exfiltration staging file), it can't just read the MFT — it needs to use tools like `icat` (Sleuth Kit) to extract the actual file content from the referenced clusters. The agent should recognize this distinction and choose the right tool accordingly.

**In practice:** When parsing MFT with MFTECmd, non-resident files show **offset values** pointing to where the actual data lives on disk. The agent can use these offsets to locate and extract the fragmented file content from the disk image.

#### Timestamp Discrepancy Analysis — File Origin Detection

NTFS tracks four timestamps (MACE): Created, Modified, Accessed, Entry Modified.

**Key rule:** When a file is created locally, the **Created** timestamp is the earliest. But when a file is **copied or moved from elsewhere**, it carries the original Modified timestamp with it — which can be **older** than the Created timestamp on this system.

| Scenario | Created (C) vs Modified (M) | What it means |
|----------|---------------------------|---------------|
| C < M | Normal — file created here, then modified later | File originated on this system |
| C > M | **Anomaly** — Modified is older than Created | File was brought in from elsewhere (downloaded, copied, transferred). It carried its original Modified timestamp |
| C = M | File hasn't been modified since creation | Could be either local or transferred |

**Forensic value:** If an attacker drops a tool or malware onto a system, the timestamps may reveal it wasn't created locally. A Modified timestamp older than the Created timestamp = the file existed somewhere else first.

**Why this matters for our agent:** This is another pattern-matching opportunity. When the agent parses MFT output, it should flag any files where Modified < Created — especially in suspicious directories (`%TEMP%`, `%APPDATA%`, `C:\ProgramData`). Combined with the SI vs FN timestamp comparison (timestomping detection), this gives the agent two independent timestamp anomaly checks.

**Further reading:** "MACB Times in Windows Forensic Analysis" — reference for understanding how each timestamp (Modified, Accessed, Changed/Entry, Birth/Created) behaves across different file operations (copy, move, rename, download, etc.).

---

### Forensic Workstation VMs — Ready-to-Go Options

| VM | Focus | OS | Notes |
|----|-------|-----|-------|
| **SIFT Workstation** | Forensic tools | Linux | Primary workstation for the hackathon. Full forensic toolkit (Volatility, Sleuth Kit, EZ Tools, log2timeline, etc.) |
| **Flare VM** | Malware tools | Windows | Mandiant's reverse engineering environment. Good for malware analysis, not primary forensic acquisition |
| **REMnux** | Malware tools | Linux | Malware analysis-focused (static analysis, deobfuscation, network analysis). Complements SIFT |
| **KALI** | Light forensic tools | Linux | Primarily pentesting/offensive. Has some forensic tools but not purpose-built for DFIR |

**Why this matters for our agent:** Our agent runs on **SIFT Workstation** — that's the hackathon requirement. But understanding the ecosystem matters: if evidence includes malware samples that need reverse engineering, the agent should note that as a finding and recommend Flare VM or REMnux analysis rather than trying to do it on SIFT. The agent's scope is forensic investigation (SIFT), not malware reverse engineering.

---

### Hands-On Forensic Case Analysis

#### KAPE & GKape — Artifact Collection and Processing

**KAPE** (Kroll Artifact Parser and Extractor) is a triage tool for collecting and processing forensic artifacts from live systems or mounted images. **GKape** is its GUI front-end.

| Component | Purpose |
|-----------|---------|
| **Targets** | Define which files/artifacts to collect (e.g., registry hives, event logs, MFT, prefetch) |
| **Modules** | Define which parsers to run against collected artifacts (e.g., EZ Tools, RegRipper) |
| **GKape** | GUI wrapper — select targets and modules via checkboxes, configure source/destination, execute |

**Workflow:** Select target source (drive or mounted image) → pick Targets to collect → pick Modules to parse → run → get structured output (CSVs, timeline data).

KAPE essentially automates the "collect artifact → parse with tool → output CSV" pipeline that EZ Tools handle individually.

**Why this matters for our agent:** KAPE is a collection/orchestration layer on top of the individual EZ Tools we already documented. The agent could use KAPE as a single entry point to batch-collect and parse multiple artifact types at once, rather than calling each EZ Tool separately. Understanding KAPE's target/module structure helps the agent know which artifacts are available and how they map to forensic questions.

#### Autopsy — Open-Source Digital Forensics Platform

**Autopsy** is a GUI-based digital forensics platform built on top of **The Sleuth Kit (TSK)**. It provides a case-management interface for analyzing disk images, file systems, and artifacts.

| Feature | Description |
|---------|-------------|
| **Case management** | Create cases, add data sources (disk images, local drives, logical files) |
| **Ingest modules** | Plug-in analysis modules that run automatically — hash lookup, keyword search, web artifacts, email, registry, etc. |
| **File system browsing** | Navigate the full directory tree of a disk image, including deleted files and unallocated space |
| **Timeline** | Consolidated timeline view across file system timestamps and artifact events |
| **Keyword search** | Index and search across all files in the image (including slack space) |
| **Tagging & reporting** | Tag items of interest, generate HTML/PDF reports |

**Relationship to Sleuth Kit:** Autopsy is the GUI; Sleuth Kit provides the underlying CLI tools (`fls`, `icat`, `mmls`, `tsk_recover`, etc.) that do the actual disk image parsing. You can use either independently.

**Performance note:** Autopsy's full ingest can run for **~24 hours** on a typical case, but the most actionable results (file system indexing, hash lookups, recent activity) are available within **~25 minutes**. Investigators don't wait for full completion — they start analyzing early results while ingest continues in the background.

**Why this matters for our agent:** Autopsy is useful for interactive investigation but is GUI-heavy — not ideal for agent automation. However, the underlying **Sleuth Kit CLI tools** are scriptable and available on SIFT. The agent should use TSK commands directly (e.g., `fls` to list files, `icat` to extract file content by inode) rather than trying to drive Autopsy. Understanding what Autopsy does helps the agent replicate the same analysis programmatically. The 25-minute insight window is a good benchmark — the agent should similarly prioritize fast, high-value artifact parsing first rather than waiting for exhaustive analysis.

#### Enterprise SOC Tools — SIEM, EDR, NDR, XDR

These are the detection and monitoring platforms that SOC analysts use in enterprise environments. DFIR investigators often pull evidence from these systems.

| Tool Type | What It Does | Data Sources | Examples |
|-----------|-------------|--------------|----------|
| **SIEM** (Security Information & Event Management) | Aggregates and correlates logs from across the environment. Central search/alerting platform | Firewall logs, Windows Event Logs, auth logs, proxy logs, DNS, application logs | Splunk, Microsoft Sentinel, Elastic SIEM, IBM QRadar |
| **EDR** (Endpoint Detection & Response) | Monitors endpoint activity — process execution, file changes, network connections, registry modifications. Enables remote response actions | Endpoint telemetry (process trees, command lines, file writes, DLL loads, network connections) | CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Carbon Black |
| **NDR** (Network Detection & Response) | Monitors network traffic for anomalies and threats. Captures packet-level or flow-level data | Network traffic (PCAP, NetFlow, DNS queries, TLS metadata, lateral movement patterns) | Zeek (Bro), Darktrace, ExtraHop, Corelight |
| **XDR** (Extended Detection & Response) | Unified platform combining EDR + NDR + SIEM capabilities into a single correlated view | Cross-domain: endpoint + network + cloud + identity + email | Microsoft 365 Defender, Palo Alto Cortex XDR, CrowdStrike Falcon Complete |

**How they relate:**
- **SIEM** = log aggregation and search (broad but shallow per source)
- **EDR** = deep endpoint visibility (deep but endpoint-only)
- **NDR** = deep network visibility (deep but network-only)
- **XDR** = attempts to unify all three into one correlated platform

**DFIR context:** During an investigation, SIEM provides the initial alert and log correlation. EDR gives you the process-level detail on compromised hosts. NDR reveals lateral movement and C2 communication patterns. Investigators query all of these to build a complete picture.

**Why this matters for our agent:** The hackathon focuses on offline forensic analysis (disk images, memory dumps), not live SOC tooling. But the agent should understand that in a real engagement, these tools provide the initial detection and scoping — the artifacts the agent analyzes (event logs, prefetch, network captures) are the same data these platforms ingest. If the agent's findings reference indicators (IPs, hashes, process names), an analyst would pivot into these tools to check enterprise-wide exposure.
