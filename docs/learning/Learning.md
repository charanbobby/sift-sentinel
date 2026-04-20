# Learning.md — Architectural Breakdown

**Reference Projects Studied:**
1. **Valhuntir** (AppliedIR/Valhuntir) — Steve Anson's AI-augmented IR platform, example hackathon submission
2. **Protocol SIFT** (teamdfir/protocol-sift) — Rob Lee's base framework connecting Claude Code to SIFT tools via MCP

**License:** Both MIT — free to build on, must attribute.

---

## 1. Protocol SIFT — The Base Framework

### What It Is
A configuration package that connects Claude Code to 200+ forensic tools on SIFT Workstation via Model Context Protocol (MCP). It's the starting point every hackathon submission builds on.

### Architecture (Simple)
```
Claude Code (terminal) → MCP protocol → SIFT forensic tools (200+)
```

### Repository Structure
```
protocol-sift/
├── global/
│   ├── CLAUDE.md              # Global behavioral rules for Claude Code
│   ├── settings.json          # Tool permissions & audit hook
│   └── settings.local.json    # Machine-level overrides
├── skills/
│   ├── memory-analysis/SKILL.md
│   ├── plaso-timeline/SKILL.md
│   ├── sleuthkit/SKILL.md
│   ├── windows-artifacts/SKILL.md
│   └── yara-hunting/SKILL.md
├── case-templates/CLAUDE.md   # Per-case instructions
└── analysis-scripts/
    └── generate_pdf_report.py
```

### Key Design Decisions

| Decision | How Protocol SIFT Does It | Why |
|----------|--------------------------|-----|
| Tool permissions | settings.json pre-approves forensic CLIs, blocks destructive ops (`rm -rf`, `dd`, `wget`) | Evidence integrity — can't accidentally destroy evidence |
| Write paths | Restricted to `./analysis/*`, `./reports/*`, `./exports/*` | Chain of custody — evidence directories read-only |
| Audit trail | `Stop` hook writes to `forensic_audit.log` | Every tool execution logged |
| Skill files | Domain-specific SKILL.md per forensic discipline | Claude Code loads context per analysis type |
| Case isolation | Per-case CLAUDE.md loaded from case directory | Each investigation has its own context |

### Skills (5 Domains)
1. **Memory Analysis** — Volatility 3 plugins, symbol resolution, process trees
2. **Timeline Generation** — log2timeline/Plaso, psort, pinfo
3. **Filesystem Forensics** — Sleuth Kit tools, disk image mounting, file carving
4. **Windows Artifacts** — EZ Tools (Shimcache, Amcache, MFT, Registry), Event Logs
5. **Threat Hunting** — YARA scanning, IOC sweeps

### Starting an Investigation (Protocol SIFT Flow)
```bash
export CASE=CLIENT-IR-2025-001
mkdir -p /cases/${CASE}/{analysis,exports,reports}
cp ~/.claude/case-templates/CLAUDE.md /cases/${CASE}/CLAUDE.md
# Mount evidence
sudo ewfmount /cases/${CASE}/suspect.E01 /mnt/ewf_rd01
# Launch Claude from case root
cd /cases/${CASE}
claude
```

### Limitations
- No self-correction loop — Claude just runs tools sequentially
- No structured findings management — output is freeform
- No human approval workflow — analyst must manually verify
- No evidence indexing — searches are manual tool commands
- Basic audit trail (log file only, no cryptographic integrity)

---

## 2. Valhuntir — The Full Platform (Example Submission)

### What It Is
Transforms Protocol SIFT from a simple tool connector into a full IR platform where one analyst manages an "agentic AI team" with human-in-the-loop approval, forensic knowledge reinforcement, and structured evidence management.

### Architecture (3 Layers)

```
┌─────────────────────────────────────────────┐
│ USER INTERFACES                              │
│  Claude Code / LLM Client                    │
│  Examiner Portal (browser, 8 tabs)           │
│  vhir CLI (case mgmt, approvals)             │
└──────────────┬──────────────────────────────┘
               │ MCP Streamable HTTP
┌──────────────▼──────────────────────────────┐
│ GATEWAY LAYER (sift-gateway, port 4508)      │
│  Auth (bearer token, 96-bit entropy)         │
│  Request routing to /mcp/{backend}           │
│  Examiner Portal served at /portal/          │
│  Tool discovery (dynamic at runtime)         │
└──────────────┬──────────────────────────────┘
               │ stdio (internal only)
┌──────────────▼──────────────────────────────┐
│ MCP BACKENDS (9 servers, 100 tools total)    │
│  forensic-mcp (23) — findings, timeline      │
│  case-mcp (15) — case lifecycle              │
│  report-mcp (6) — report generation          │
│  sift-mcp (5) — Linux forensic tools         │
│  opensearch-mcp (17) — evidence indexing     │
│  forensic-rag-mcp (3) — knowledge search     │
│  windows-triage-mcp (13) — baseline check    │
│  opencti-mcp (8) — threat intelligence       │
│  wintools-mcp (10) — Windows tools           │
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│ TOOL LAYER                                    │
│  200+ forensic tools (Volatility, TSK, etc.) │
│  OpenSearch (evidence indexing at scale)      │
│  Forensic knowledge (22K records, 59 tools)  │
│  Windows triage baseline (2.6M records)      │
│  OpenCTI (threat intelligence)               │
└─────────────────────────────────────────────┘
```

### Key Architectural Decisions

| Decision | How Valhuntir Does It | Why | Adapt for Us? |
|----------|----------------------|-----|---------------|
| Gateway aggregation | Single HTTP endpoint (port 4508) proxies all MCP backends | Any LLM client works — not locked to Claude Code | Yes — keeps us client-agnostic |
| Client ↔ Server protocol | MCP Streamable HTTP (never stdio for clients) | Stdio is internal only, HTTP enables remote access | Follow this pattern |
| Findings workflow | DRAFT → human review → APPROVED | AI cannot approve its own work | Core requirement — judges want this |
| Cryptographic approval | HMAC-SHA256 signed, PBKDF2 key derivation | Tamper-proof audit trail | Important for submission |
| Evidence integrity | Read-only evidence dirs, kernel sandbox (bubblewrap) | Chain of custody | Required |
| Tool execution | Denylist (SIFT) + allowlist (Windows) + shell=False | Prevents destructive commands architecturally | Judges value architectural > prompt-based constraints |
| Knowledge reinforcement | 8 layers: response enrichment, discipline reminders, RAG, baselines | Prevents hallucination structurally | Key differentiator |
| Token budget decay | Caveats always; advisories decay after 3 calls | Balances accuracy vs. cost | Smart optimization |
| Evidence indexing | OpenSearch with 15 parsers + Hayabusa (3700 Sigma rules) | Scale — millions of records queryable | Powerful but resource-heavy |
| Multi-examiner | Export/merge with examiner-prefixed IDs | Team collaboration | Nice-to-have |

### Investigation Workflow (9 Steps)
1. **Create case** — name, examiner, directory
2. **Register evidence** — hash, chain of custody
3. **Ingest and index** — parse into OpenSearch (or analyze directly)
4. **Scope investigation** — review data, identify hosts/artifacts, check Hayabusa alerts
5. **Enrich programmatically** — validate against baselines, check IOCs (zero LLM tokens)
6. **Search and analyze** — query across records, aggregate patterns, build timelines
7. **Record findings** — AI stages as DRAFT with evidence provenance
8. **Human review** — examiner approves/rejects (HMAC-signed)
9. **Generate report** — only approved findings included

### Human-in-the-Loop Controls (9 Layers)

| Layer | Control | Type |
|-------|---------|------|
| L1 | DRAFT → APPROVED gate | Structural |
| L2 | HMAC verification ledger | Cryptographic |
| L3 | Case data deny rules (41 rules) | Permission |
| L4 | Kernel sandbox (bubblewrap) | Kernel |
| L5 | File permissions (chmod 444) | Filesystem |
| L6 | Report reconciliation (bidirectional) | Integrity |
| L7 | Password authentication | Authentication |
| L8 | Provenance enforcement (MCP > HOOK > SHELL > NONE) | Structural |
| L9 | Kernel namespace isolation | Kernel |

### Forensic Knowledge System (8 Layers)

| Layer | What | Token Cost |
|-------|------|------------|
| L1: Response enrichment | Caveats, field meanings, corroboration in tool responses | ~39K across 100-call session |
| L2: Discipline reminders | 15 rotating methodology reminders | ~50 tokens/response |
| L3: Contextual reminders | opensearch-mcp context-aware injections | Variable |
| L4: Finding validation | Structural enforcement on record_finding() | Minimal |
| L5: MCP server instructions | Structured briefings at session init | One-time |
| L6: Client configuration | CLAUDE.md, FORENSIC_DISCIPLINE.md, TOOL_REFERENCE.md | Persistent |
| L7: Forensic RAG | 22K+ records (Sigma, MITRE, LOLBAS, etc.) | Per-query |
| L8: Windows triage baseline | 2.6M known-good records, offline lookup | Zero LLM tokens |

### Resource Requirements

| Component | Min RAM | Disk |
|-----------|---------|------|
| Core (no OpenSearch) | 16 GB | 50 GB + evidence |
| With OpenSearch | 32 GB | 100 GB + indices |
| Lite (stdio only) | 8 GB | 30 GB + evidence |

### Case Directory Structure
```
cases/INC-2026-0219/
├── CASE.yaml                    # Case metadata
├── evidence/                    # Original evidence (locked, read-only)
├── extractions/                 # Extracted artifacts
├── reports/                     # Generated reports
├── findings.json                # F-alice-001, F-alice-002, ...
├── timeline.json                # T-alice-001, ...
├── todos.json                   # TODO-alice-001, ...
├── iocs.json                    # Auto-extracted from findings
├── evidence.json                # Evidence registry (SHA-256)
├── actions.jsonl                # Investigative actions (append-only)
├── evidence_access.jsonl        # Chain-of-custody log
├── approvals.jsonl              # HMAC-signed approval trail
├── pending-reviews.json         # Portal edits awaiting approval
└── audit/                       # Per-backend JSONL logs
```

### Examiner Portal (8 Tabs)
1. Overview — case summary
2. Findings — review, edit, approve/reject with audit trail
3. Timeline — chronological event view
4. Hosts — identified systems
5. Accounts — user accounts found
6. Evidence — registered evidence items
7. IOCs — auto-extracted indicators of compromise
8. TODOs — investigation task tracking

### Critical Warning from Authors
> "If you just tell Valhuntir to 'Find Evil' it will more than likely hallucinate rather than provide meaningful results. The AI can accelerate, but the human must guide it and review all decisions."

---

## 3. What Protocol SIFT Has vs. What Valhuntir Adds

| Capability | Protocol SIFT | Valhuntir |
|-----------|--------------|-----------|
| Tool execution | Yes (via MCP) | Yes (via MCP + gateway) |
| Audit trail | Basic (log file) | Full (per-backend JSONL, HMAC-signed) |
| Self-correction | No | Partial (knowledge enrichment, discipline reminders) |
| Findings management | No | Yes (DRAFT → APPROVED workflow) |
| Human approval gate | No | Yes (cryptographic, password-gated) |
| Evidence indexing | No | Yes (OpenSearch, 15 parsers) |
| Forensic knowledge | Basic (skill files) | Deep (8 layers, 22K records, 2.6M baselines) |
| Report generation | Basic (PDF script) | Full (6 profiles, IOC aggregation, MITRE mapping) |
| Client flexibility | Claude Code only | Any MCP-compatible client |
| Destructive command prevention | Prompt-based (settings.json) | Architectural (denylist + allowlist + shell=False) |
| Evidence integrity | Write path restrictions | Kernel sandbox + file permissions + deny rules |
| Case management | Template-based | Full lifecycle (init, register, export, merge) |

---

## 4. What Needs to Change for Our Submission

### Must Keep (Hackathon Requirements)
- Self-correction — agents detect and resolve their own errors
- Accuracy validation — findings traceable to specific artifacts
- Analytical reasoning — structured investigative narrative output
- Audit trail — judges trace findings to tool executions
- Open source (MIT/Apache 2.0)

### Adapt to Our Stack (per SKILL.md)
| Valhuntir Approach | Our Adaptation |
|-------------------|----------------|
| pip install on host | Docker containers mounted to D: drive, uv instead of pip |
| WeasyPrint for reports | Could keep or replace with our stack |
| Browser portal (vanilla HTML/JS) | Next.js + React + TypeScript + Tailwind if building custom UI |
| No notebook prototyping | Phase 3: prototype pipeline in Jupyter first |
| No cost/token observability | Phase 7: trace every LLM call, cost per step |
| OpenSearch (heavy, 32GB RAM) | Start with SQLite + FTS5, scale if needed |
| SIFT VM requirement | SIFT VM for forensic tools, our app code in Docker on D: drive |

### Opportunities to Differentiate
1. **Self-correction loop** — Valhuntir doesn't have a true self-correction agent loop. The hackathon judges rank "autonomous execution quality" #1. Build an agent that evaluates its own output, detects inconsistencies, and retries.
2. **Persistent learning loop** — Iteration-over-iteration improvement tracking (starter idea from hackathon). Show approach changes across iterations.
3. **Per-step model selection** — Use cheap models for mechanical extraction, expensive for reasoning (per SKILL.md Phase 5c). Valhuntir uses single model.
4. **Cost observability** — Surface token usage, cost per step, latency inline. Judges won't explicitly score this but it demonstrates engineering maturity.
5. **Notebook-first validation** — Prove the pipeline works in Jupyter before building the app. Cleaner demo, more confident submission.
6. **Prompt distillation** — Run strong model once on hardest step, encode reasoning into cheaper prompts. 40-120x cost reduction.

### What to Study Further
- [ ] Valhuntir's forensic-mcp `record_finding()` validation logic — how it enforces provenance
- [ ] sift-mcp denylist implementation — the exact architectural constraint pattern
- [ ] Token budget decay mechanism — how enrichment cost is managed across sessions
- [ ] Hayabusa integration — 3700 Sigma rules auto-applied after EVTX ingest
- [ ] The 15 evidence parsers — what data formats they handle

### Attribution
- Valhuntir: MIT license, Steve Anson (SANS Author), AppliedIR/Valhuntir
- Protocol SIFT: MIT license, Rob Lee, teamdfir/protocol-sift

---

## 5. Key Forensic Concepts to Learn

### Essential Tools (Priority Order)
1. **Volatility 3** — Memory forensics: processes, network connections, loaded DLLs, credentials
2. **The Sleuth Kit (TSK)** — Disk image analysis: file recovery, timeline, keyword search
3. **Plaso/log2timeline** — Super-timeline generation from multiple evidence sources
4. **EZ Tools** (Eric Zimmerman) — Windows artifacts: Shimcache, Amcache, MFT, Registry, Shellbags, Prefetch
5. **Hayabusa** — Windows Event Log analysis with 3700+ Sigma detection rules
6. **YARA** — Pattern matching for threat hunting

### Key Forensic Principles
- **Evidence is sovereign** — if tool output conflicts with hypothesis, revise hypothesis
- **Absence of evidence ≠ evidence of absence** — anti-forensics can hide artifacts
- **Shimcache/Amcache prove PRESENCE, not execution** — common misinterpretation
- **Timestamps can be manipulated** — always corroborate with multiple sources
- **Chain of custody** — evidence must be verifiable from collection to report

### Data Types the Hackathon Supports
- Disk images (E01, raw)
- Memory captures (RAM dumps)
- Log files (Windows Event Logs, syslog)
- Network captures (PCAP)
- Remote endpoints via MCP
