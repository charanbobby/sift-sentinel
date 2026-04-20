I'm continuing a coursework note-taking session for the SANS "Find Evil" hackathon.

**What we're doing:**
I'm going through the Blue Cape Security DFIR Foundations & Techniques course
(https://bluecapesecurity.com/courses/dfir-foundations-techniques-readiness/).
As I share screenshots and describe concepts, you capture them into structured
notes in the training folder.

**Project location:** d:\Python Applications\Find Evil - Hackathon

**Key files:**
- Course notes: training/blue-cape-dfir-foundations/README.md (main file — append new sections here)
- C2 framework references: training/blue-cape-dfir-foundations/cobalt-strike-artifacts.md, empire-artifacts.md
- Lab reference: training/blue-cape-dfir-foundations/lab-pwf.md
- Tool reference: training/blue-cape-dfir-foundations/forensic-tools.md
- Cheat sheet PDF: training/blue-cape-dfir-foundations/PracticalWindowsForensics-cheat-sheet.pdf
- Project plan / slice status: docs/planning/PLAN.md (source of truth)
- Architectural analysis: docs/learning/Learning.md, docs/learning/learning-resources.md
- Workflow: SKILL.md (10-phase workflow)

**Current project state:**
- Slice 1 ✅ done (Docker + Protocol SIFT + Claude Code ran first real MCP tool call against the E01)
- Slice 2 in progress — Jupyter notebook + our own MCP server, structured findings JSON
- Runtime is a SIFT Docker container (not the VM — pivoted on 2026-04-17)

**How to capture notes:**
- Read the end of README.md first to see where we left off
- Add each new topic as a ### subsection under the current section
- Include a "Why this matters for our agent" annotation for each concept
- If something is a reference list (like tools), put it in a separate .md file
- Keep forensic accuracy — these notes become the knowledge base for our AI agent

**Where we left off in the course:**
- Covered: NIST SP 800-86, Order of Volatility, Threat Landscape, Ransomware Lifecycle,
  Attack Infrastructure, DFIR Domains, MITRE ATT&CK, C2 Frameworks, Data Sources,
  Windows OS Components, Data Acquisition, VM formats, NTFS deep dive, MFT structure,
  EZ Tools, Resident vs Non-Resident files, Timestamp Discrepancy Analysis,
  Forensic Workstation VMs, Free Forensic Tools
- The course is moving into hands-on forensic case analysis next

**My preferences:**
- Follow SKILL.md phases in order
- I'm an AI/MCP expert — only suggest forensics domain knowledge, not AI stuff
- Be concise, don't over-explain things I already know
