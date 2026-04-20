# DFIR Learning Resources — Curated for Find Evil Hackathon

> **Note:** AI engineering, MCP, prompt design, agentic frameworks — already in your wheelhouse.
> These resources focus purely on **forensics domain knowledge** — the gap that matters.

---

## Tier 1: Foundations (Pre-hackathon — completed)

> Captured here for reference. The Blue Cape course was completed before Slice 1 began; notes live in `../../training/blue-cape-dfir-foundations/`.

### Blue Cape Security — DFIR Foundations & Techniques (FREE)
- **URL:** https://bluecapesecurity.com/courses/dfir-foundations-techniques-readiness/
- **Hours:** 8 hrs video + downloadable case files + 70-question knowledge assessment
- **Covers:** SOC operations, conducting DFIR investigations, real scenario practice
- **Tools:** Volatility3, Arsenal Image Mounter, KAPE, forensic utilities
- **Certificate:** Yes (up to 8 CPE)
- **Why this one:** Longer, more comprehensive, and more focused than any Udemy equivalent. Hands-on with real case files. Free beats paid here.

### Blue Cape Security — DFIR Workshop Series (FREE, 3-part)
- **URL:** https://bluecapesecurity.com/dfir-workshop-series/
- **What:** Deeper insights and practical applications
- **Why:** Builds on foundations, gets you to intermediate level fast

### SIFT Cheat Sheet (Reference — keep open while working)
- **URL:** https://www.sans.org/posters/sift-cheat-sheet
- **What:** Quick reference for all SIFT tools and commands

---

## Tier 2: Volatility Deep-Dives (Udemy — worth it here)

Free resources cover Volatility basics, but these go deeper into scripting and real-world threat hunting where the free options are thinner.

### SDF: Memory Forensics 1 (Udemy)
- **URL:** https://www.udemy.com/course/surviving-digital-forensics-memory-analysis-1/
- **What:** Volatility from scratch — RAM dumps, process analysis, fast-triage compromise assessment
- **Why:** Builds hands-on muscle memory for the exact tool your agent will automate

### SDF: Memory Forensics 2 (Udemy)
- **URL:** https://www.udemy.com/course/surviving-digital-forensics-memory-analysis-2/
- **What:** Scripting Volatility, advanced malware detection in memory
- **Why:** Understanding how to script Volatility helps you design better MCP tool wrappers

### Mastering Threat Hunting: Memory Forensics with Volatility (Udemy)
- **URL:** https://www.udemy.com/course/mastering-threat-hunting-memory-forensics-with-volatility/
- **What:** Real-world threat hunting — rootkits, hidden processes, network connections
- **Why:** This is literally "Find Evil" in course form. Teaches the investigative reasoning your agent needs to replicate.

---

## Tier 3: Supplementary Free Resources

### Memory Forensics Introduction (FREE, YouTube)
- **URL:** https://www.dfir.training/free/youtube/introduction-to-memory-forensics
- **What:** Intro with Volatility 2.6, Windows 10 sample exercise
- **Why:** Quick primer before the Udemy deep-dives

### DFIR.Science — Intro to Digital Forensics (FREE, YouTube)
- **URL:** https://www.dfir.training/free/youtube/free-intro-to-digital-forensics-course
- **What:** Complete beginner course, no prior knowledge assumed
- **Why:** Fills foundational gaps if Blue Cape doesn't cover something

### BlackPerl — DFIR Malware Analysis Series (FREE, YouTube)
- **URL:** https://www.classcentral.com/course/youtube-blackperl-dfir-malware-analysis-series-63989
- **What:** 6-hour series on DFIR including advanced memory forensics
- **Why:** Malware analysis perspective — different angle from the investigation-focused courses

### Cyber 5W — Free DFIR Course
- **URL:** https://cyber5w.com/
- **What:** Beginner-friendly DFIR course
- **Why:** Another perspective, good for reinforcement

---

## Hackathon-Specific Resources

### NotebookLM — Hackathon Q&A Resource
- **URL:** https://notebooklm.google.com/notebook/f0957a60-6fb2-452b-93d4-ecd73ba47779
- **What:** Official hackathon resource for building questions and project inspiration

### Rob Lee's Substack — Protocol SIFT Introduction
- **URL:** https://robtlee73.substack.com/p/introducing-protocol-sift-meeting
- **What:** Deep dive into Protocol SIFT architecture and motivation

### Rob Lee's Substack — Hackathon Registration Announcement
- **URL:** https://robtlee73.substack.com/p/registration-is-open-find-evil-hackathon
- **What:** Getting started tips, who should participate, what to expect

### Valhuntir Documentation (Example Submission)
- **URL:** https://appliedir.github.io/Valhuntir/
- **What:** Full platform docs — architecture, CLI reference, security model
- **Repository:** https://github.com/AppliedIR/Valhuntir

### Protocol SIFT Repository
- **URL:** https://github.com/teamdfir/protocol-sift
- **What:** The base framework every submission builds on

### Starter Case Data
- **URL:** https://sansorg.egnyte.com/fl/HhH7crTYT4JK
- **What:** Sample disk images and memory captures for development and testing

### Hackathon Slack
- **URL:** https://join.slack.com/t/sansaihackathon/shared_invite/zt-3srjz86zo-bwHi_v1aKTg2IJAU4_4OwA
- **What:** Team formation, mentorship, technical Q&A

---

## Reference Directories (Browse as needed)

- **DFIR Diva:** https://training.dfirdiva.com/listing-category/dfir — 341 DFIR resources, filterable
- **Class Central:** https://www.classcentral.com/subject/digital-forensics — 800+ courses aggregated
- **DFIR Training Wiki:** https://www.dfir.training/ — community-maintained tools and training

---

## Suggested Learning Path

### Pre-hackathon foundations (done)
- [x] Blue Cape DFIR Foundations (8 hrs)
- [x] SIFT Workstation explored — pivoted from VirtualBox VM to `digitalsleuth/sift-docker:jammy` Docker container on 2026-04-17 (Hyper-V conflict; see [PLAN.md](../planning/PLAN.md) Key Decisions)
- [x] Protocol SIFT installed inside the SIFT Docker container (Slice 1)
- [x] Read Valhuntir docs — architectural notes captured in [Learning.md](Learning.md)
- [x] Joined hackathon Slack
- [x] Project structure stood up on D: drive per SKILL.md

### During hackathon — domain depth as needed
- [ ] SDF Memory Forensics 1 + 2 (Udemy) — when working on memory analysis features (later slices, not Slice 2)
- [ ] Mastering Threat Hunting with Volatility (Udemy) — when designing the "find evil" reasoning logic
- [ ] Blue Cape Workshop Series — for intermediate reinforcement on specific artifact types

---

## SIFT Workstation Download

- **URL:** https://www.sans.org/tools/sift-workstation (requires free SANS account)
- **File:** OVA, 8.74 GB
- **Last updated:** March 26, 2026
- **Requirements:** VirtualBox (free), 16GB+ RAM recommended
- **Default credentials:** `sansforensics` / `forensics`
