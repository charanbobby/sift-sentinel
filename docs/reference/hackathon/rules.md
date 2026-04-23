# FIND EVIL! Hackathon — Rules & Guidelines

**Source:** https://findevil.devpost.com/rules (+ Devpost overview page — full page text captured 2026-04-23; prior version of this doc was a partial summary missing components 1, 4, 7 and the architectural-approach list).

---

## 1. Key Dates

| Phase | Timeline |
|-------|----------|
| Submission Period | Apr 15, 2026 12:00 PM EDT – Jun 15, 2026 11:45 PM EDT |
| Judging Period | Jun 19, 2026 12:00 AM EDT – Jul 3, 2026 12:00 AM EDT |
| Winners Announced | On/around Jul 8, 2026 12:00 PM EDT |

## 2. Eligibility Requirements

### Who CAN Enter
- Individuals at legal age of majority in their residence
- Teams of up to 5 eligible individuals
- Organizations (corporations, nonprofits, LLCs, partnerships, etc.)
- Eligible individuals may join multiple teams or enter individually

### Who CANNOT Enter
- Residents of countries/regions prohibited by US law (Brazil, Quebec, Russia, Crimea, Cuba, Iran, North Korea, OFAC-designated areas)
- Employees, representatives, agents of sponsoring/promotional entities and their immediate families/households
- Judges, judges' employers, and their immediate families/households
- Parent companies, subsidiaries, or affiliates of ineligible organizations

### Team Representation
Teams/organizations must designate one authorized representative who meets eligibility requirements.

## 3. Project Requirements

### What Must Be Created
Working software application that extends Protocol SIFT's autonomous incident response using an agentic framework as the primary execution engine.

**One goal:** make Protocol SIFT a fully autonomous incident response agent. Submission must improve how Protocol SIFT processes case data — any case data type. Data type doesn't define the track; **the quality of autonomous execution does.**

**Supported data types:** Disk images, memory captures, log files, network captures, remote endpoints via MCP.

### Mandatory Capabilities
1. **Self-correction** — Agents detect and resolve their own errors/inconsistencies without human intervention
2. **Accuracy validation** — All findings traceable to specific artifacts, files, offsets, or log entries
3. **Analytical reasoning** — Output presented as structured investigative narrative, not raw execution logs

### Technical Specifications
- **Platform:** Linux terminal / SIFT Workstation environment
- **Framework requirement:** Must run on/integrate with SANS SIFT Workstation using Claude Code or OpenClaw (or a comparable agentic alternative — see architectural approaches below)
- **Novelty requirement:** Substantially new work created during hackathon period (April 15 – June 15, 2026)
- **Foundation use:** May build on pre-existing open-source libraries, frameworks, SIFT codebase

### Supported Architectural Approaches

Devpost lists four primary architectural patterns. Other patterns are not auto-disqualified, but these are the intended targets.

1. **Direct Agent Extension (Claude Code / OpenClaw)** — Extend Protocol SIFT's existing agent loop. Better prompts, smarter sequencing, self-correction routines. On-ramp for most participants; fastest path to a working submission. OpenClaw's architecture also suits custom MCP tool wrappers.
2. **Custom MCP Server** — Expose typed functions (`get_amcache()`, `extract_mft_timeline()`, `analyze_prefetch()`) instead of generic `execute_shell_cmd`. Agent *physically cannot* run destructive commands because the server doesn't expose them. MCP server parses tool output natively, preventing context-window overload. *Devpost framing: "the most sound architecture in the evaluation. It's also the most work."*
3. **Multi-Agent Frameworks (AutoGen, CrewAI, LangGraph)** — Decompose analysis into specialized communicating agents. No single model holds all raw data → prevents context degradation. Structured execution records via agent-to-agent logging. Warning: requires max-iteration caps + graceful degradation against infinite loops.
4. **Alternative Agentic IDEs (Cursor, Cline, Aider)** — AI-native dev environments. Good UI but designed for software dev, not IR. Rely on prompt adherence for evidence protection, not architectural enforcement. If submitting under this track, Accuracy Report *must* document behavior when the model ignores read-only rules.

## 4. Submission Requirements

**All eight components required. Missing any one means elimination.**

### Repository-Level Gate
- Public open-source repository with **MIT or Apache 2.0** license
- README with complete setup instructions
- All necessary source code, assets, and dependencies included

### The 8 Required Components (Devpost numbering)

1. **Code Repository** — GitHub (public). MIT or Apache 2.0 license.
2. **Demo Video (5 min max)** — Screencast of live terminal execution with audio narration. **Must show the agent working against real case data, including at least one self-correction sequence.**
3. **Architecture Diagram** — How components connect: agent, SIFT tools, MCP servers, data sources, output pipeline. **Must identify which architectural pattern you're using** and **document where security boundaries are enforced**. **Prompt-based vs. architectural guardrails must be clearly distinguished.** Judges need to understand trust boundaries at a glance.
4. **Written Project Description** — Devpost project-story format: What it does, How you built it, Challenges, What you learned, What's next. Be specific about design decisions, tradeoffs, and which qualities of autonomous execution you address.
5. **Dataset Documentation** — What the agent was tested against, source of data, what it found. Reproducibility starts here.
6. **Accuracy Report** — Self-assessment of findings accuracy. FPs, missed artifacts, hallucinated claims. **Must include a section documenting your evidence-integrity approach: how does your architecture prevent original data from being modified? If using prompt-based restrictions, document what happens when the model ignores the restriction. Did you test for spoliation?** Failure modes found are *signal, not weakness* — document them.
7. **Try-It-Out Instructions** — Live deployment URL *or* step-by-step instructions for judges to run locally on the SIFT Workstation. Document any specific tools/dependencies in the README.
8. **Agent Execution Logs** — Structured logs, full agent communication + tool execution sequence. Format requirements vary by architecture:
    - **Multi-agent:** agent-to-agent message logs with timestamps
    - **Single-agent:** tool execution logs with timestamps and token usage
    - **Persistent loop:** iteration-over-iteration traces showing how the agent's approach changed
    - Judges must be able to trace any finding back to the specific tool execution that produced it.

## 5. Judging Criteria (Ranked by Priority)

1. **Autonomous Execution Quality** (tiebreaker) — Does the agent reason about next steps, handle failures, and self-correct in real time?
2. **IR Accuracy** — Are findings correct? Hallucinations caught and flagged? Confirmed findings distinguished from inferences?
3. **Breadth and Depth of Analysis** — How much case data can the agent handle? **Depth on fewer types beats shallow coverage of many.**
4. **Constraint Implementation** — Are guardrails architectural or prompt-based? Where are security boundaries enforced, and were they tested for bypass?
5. **Audit Trail Quality** — Can judges trace any finding back to the specific tool execution that produced it?
6. **Usability and Documentation** — Can another practitioner deploy and build on this?

### Named Judge
- **Rob T. Lee** — CAIO, SANS Institute. (Sole judge named on Devpost overview.)

## 6. Prize Structure

| Place | Cash | Benefits |
|-------|------|----------|
| 1st: SLAYED EVIL | $10,000 | SANS Summit pass + hotel + OnDemand course per member; SANS webcast presentation |
| 2nd: HUNTED EVIL | $7,500 | SANS Summit pass + hotel + OnDemand course per member; SANS webcast presentation |
| 3rd: FOUND EVIL | $4,500 | OnDemand course per member |

Total pool: $22,000 in cash + SANS training/event benefits.

## 7. IP & Ownership
- All submissions remain property of creators
- Sponsor receives non-exclusive license for judging purposes
- Projects must not have been developed with financial support from sponsor

## 8. Legal
- Disputes resolved by individual, final, binding arbitration (AAA rules)
- Governed by laws of State of New York, USA
- All materials in English or with English translations
