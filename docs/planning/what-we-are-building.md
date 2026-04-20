# What We're Building — Plain-English Overview

**Last updated:** 2026-04-18

A plain-English primer on what this project *will be* and where it fits in the cybersecurity lifecycle. Read [concepts.md](concepts.md) first if you're new to DFIR terminology.

> **Status check (2026-04-17):** Slice 1 is done — Protocol SIFT runs in Docker and Claude Code has answered one question on one E01. Everything else in this document describes the **target** we are building toward. Live slice status lives in [PLAN.md](PLAN.md); treat that as the source of truth, not this doc.

---

## One-line summary

A **forensics analyst in a box.** After an attack happens, the goal is an AI agent that autonomously investigates the compromised machine and reports *how they got in* and *how they stayed in* — work that today takes a human DFIR analyst a full shift or more for the narrow scope we target (initial access + persistence on one Windows host).

We are **not** preventing the attack. We are **accelerating the investigation** that happens after.

---

## Timeline — where we fit in an attack lifecycle

```
ATTACK LIFECYCLE                              WHO HANDLES IT
─────────────────────────────────────────────────────────────

 [1] 📧 Attacker sends phishing email   ──▶  Email security (Proofpoint etc)
         │                                    ❌ NOT US
         ▼
 [2] 👤 User clicks link / opens doc    ──▶  User awareness training
         │                                    ❌ NOT US
         ▼
 [3] 💥 Exploit runs, malware drops     ──▶  EDR (CrowdStrike, Defender)
         │                                    ❌ NOT US
         ▼
 [4] 🔒 Malware installs persistence    ──▶  EDR / antivirus
         │   (registry run key, scheduled        ❌ NOT US
         │    task, service, etc.)
         ▼
 [5] 📡 Attacker steals data / encrypts ──▶  SIEM alerts, analyst
         │                                    ❌ NOT US
         ▼
 ═══════════════════════════════════════════════════════════
    🚨  ALERT FIRES — "something is wrong on host WIN-042"
 ═══════════════════════════════════════════════════════════
         │
         ▼
 [6] 🧊 IR team pulls disk image + RAM  ──▶  Human responder
         │   (E01 file, memory dump)          ❌ NOT US
         ▼
 ╔═══════════════════════════════════════════════════════════╗
 ║ [7] 🔍 FORENSIC INVESTIGATION                             ║
 ║                                                           ║
 ║     ▶ Parse disk structure (mmls, fsstat)                 ║
 ║     ▶ Timeline events (plaso, log2timeline)               ║
 ║     ▶ Carve registry hives (regripper)                    ║
 ║     ▶ Scan memory (volatility)                            ║
 ║     ▶ Cross-reference, spot contradictions, retry         ║
 ║     ▶ Output: "Initial access = phishing PDF exploit      ║
 ║               CVE-XXXX. Persistence = Run key at          ║
 ║               HKCU\...\Run\updater.exe"                   ║
 ║                                                           ║
 ║                   🎯  THIS IS THE TARGET  🎯              ║
 ╚═══════════════════════════════════════════════════════════╝
         │
         ▼
 [8] 🧹 Contain, eradicate, recover     ──▶  IR team
                                              ❌ NOT US
```

---

## Target architecture (where the AI engineering lives)

> This is the end-state, not today's state. Today: left-hand box (tools via Protocol SIFT's MCP) works; the reasoning loop is Claude Code's native behaviour, not something we've architected yet.

```
┌─────────────────────────────────────────────────────────┐
│  COMPROMISED DISK IMAGE (.E01)                          │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
            ┌──────────────────────────────┐
            │      CLAUDE CODE AGENT       │
            │  (autonomous reasoning loop) │
            └───┬──────────────────────┬───┘
                │                      │
        picks tool                 reviews own output
                │                      │
                ▼                      ▼
       ┌────────────────┐    ┌──────────────────────┐
       │   MCP TOOLS    │    │ SELF-CORRECTION:     │
       │ (typed, sand-  │    │ "mmls failed → try   │
       │  boxed)        │    │  fsstat instead"     │
       │                │    │ "timeline contradicts│
       │ • mmls         │    │  registry → re-run"  │
       │ • fsstat       │    └──────────────────────┘
       │ • plaso        │
       │ • volatility   │
       │ • regripper    │
       └───────┬────────┘
               │
               ▼
       ┌─────────────────────────┐
       │ STRUCTURED FINDINGS JSON│
       │ + full audit trail      │
       │ (every tool call logged)│
       └─────────────────────────┘
```

---

## The four portfolio-worthy pieces — and what's built

| # | Piece | Why it's interesting | Slice | Status |
|---|-------|---------------------|-------|--------|
| 1 | **MCP-native tool calls** | Typed contracts, not shell strings — the agent can't invent flags | 5 | ⬜ Generic MCP via Protocol SIFT today; typed contracts still to build |
| 2 | **Self-correction loop** | Agent spots its own contradictions and retries — architected, not just native model behaviour | 3 | ⬜ Not started. The mmls→fsstat pivot in Slice 1 was Claude Code's default behaviour, not our loop |
| 3 | **Architectural sandboxing** | Tools are read-only, scoped to the image — guardrails in the *system*, not the prompt | 1 / 5 | 🟡 Partial: Docker read-only bind-mount works (inherited from Protocol SIFT). Tool-scoped guardrails = Slice 5 |
| 4 | **Audit trail** | Every decision logged — critical for high-stakes domains (forensics, medical, legal) | 6 | ⬜ Not started |

The portfolio thesis depends on actually shipping slices 3, 5, and 6 — those are where *we* do engineering rather than wiring someone else's tools together.

---

## Short version

We're building the autonomous analyst that runs between *"alert fired"* and *"here's the report."* The forensics domain is the stage; the AI engineering (typed MCP + self-correction + architectural sandboxing + audit trail) is the actual portfolio piece — most of which is still ahead of us. See [PLAN.md](PLAN.md) for what exists today.
