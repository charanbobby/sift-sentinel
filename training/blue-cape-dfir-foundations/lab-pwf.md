# Practical Windows Forensics (PWF) Lab

**Repository:** https://github.com/bluecapesecurity/PWF
**By:** Blue Cape Security
**License:** Free for educational use

## What It Is

A DIY lab where you simulate real attacks on a Windows VM, capture memory + disk images, then investigate them with forensic tools. Exactly the workflow your hackathon agent will automate.

## 5-Stage Workflow

### Stage 1: Target System Prep
- Windows 10 Enterprise Evaluation VM (VirtualBox or VMware)
- Install Sysmon (enhanced event logging)
- Disable Defender temporarily
- Snapshot clean state

### Stage 2: Attack Simulation
- Run `ART-attack.ps1` (Atomic Red Team — MITRE ATT&CK techniques)
- Generates artifacts: execution, persistence, defense evasion
- Keep spawned processes alive before acquisition

### Stage 3: Evidence Acquisition
- **Memory capture:**
  - VMware: extract `.vmem` + `.vmsn` snapshot files
  - VirtualBox: `vboxmanage debugvm <UUID> dumpvmcore --filename win10-mem.raw`
- **Disk imaging:**
  - VMware: copy `.vmdk` files
  - VirtualBox: `vboxmanage clonemedium disk <UUID> --format raw win10-disk.raw`
- **Hash verification:** `Get-FileHash -Algorithm SHA1` or `shasum`

### Stage 4: Forensic Workstation Setup
- Windows Server 2019/2022 VM (4GB RAM, 100GB dynamic)
- Tools: Volatility, Arsenal Image Mounter, FTK Imager, EZ Tools, KAPE, RegRipper, EventLog Explorer

### Stage 5: Investigation
- User account artifacts
- Program execution evidence
- Persistence mechanisms (registry run keys, scheduled tasks, services)
- NTFS artifacts (file creation/deletion)
- PowerShell activity
- DLL injection indicators
- Timeline reconstruction

## Requirements
- VirtualBox or VMware
- 4GB+ RAM per VM (can run sequentially)
- ~90GB disk total (two VMs + evidence + working data)

## Included Resources
- PWF cheat sheet (PDF)
- Analysis notes template (Word)
- Investigation objectives checklist (CSV)
- RegRipper plugin reference (CSV/Excel)

## Relevance to Hackathon
This lab produces exactly the evidence types the hackathon supports — memory captures and disk images with known attack artifacts. Good for:
- Building domain intuition (you know what the "evil" looks like because you planted it)
- Testing your agent against evidence with known ground truth
- Practicing the investigation workflow your agent will automate

## Note
PWF is now part of Blue Cape's Analyst 1 Training Track (bluecapesecurity.com/analyst1/), but the GitHub repo and materials remain free.
