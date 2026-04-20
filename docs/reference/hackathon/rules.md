# FIND EVIL! Hackathon - Rules & Guidelines

**Source:** https://findevil.devpost.com/rules

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

**Preferred frameworks:** Claude Code and OpenClaw
**Acceptable alternatives:** Comparable agentic architectures

**Supported data types:** Disk images, memory captures, log files, network captures, remote endpoints via MCP

### Mandatory Capabilities
1. **Self-correction** — Agents detect and resolve their own errors/inconsistencies without human intervention
2. **Accuracy validation** — All findings traceable to specific artifacts, files, offsets, or log entries
3. **Analytical reasoning** — Output presented as structured investigative narrative, not raw execution logs

### Technical Specifications
- **Platform:** Linux terminal / SIFT Workstation environment
- **Framework requirement:** Must run on/integrate with SANS SIFT Workstation using Claude Code or OpenClaw
- **Novelty requirement:** Substantially new work created during hackathon period (April 15 – June 15, 2026)
- **Foundation use:** May build on pre-existing open-source libraries, frameworks, SIFT codebase

## 4. Submission Requirements

### Repository Requirements
- Public open-source repository with MIT or Apache 2.0 license
- README with complete setup instructions
- All necessary source code, assets, and dependencies included

### Required Submission Materials
1. **Text Description** — Features and functionality explanation
2. **Demo Video** — Under 5 minutes, screencast with live terminal execution and audio narration
3. **Architecture Diagram** — Component connections: agent, SIFT tools, MCP servers, evidence sources, output pipeline
4. **Evidence Dataset Documentation** — What tested against, data source, findings produced
5. **Accuracy Report** — Self-assessment: false positives, missed artifacts, hallucinated claims
6. **Agent Execution Logs** — Structured logs with timestamps and token usage

## 5. Judging Criteria (Ranked by Priority)

1. **Autonomous Execution Quality** (tiebreaker)
2. **IR Accuracy**
3. **Breadth and Depth of Analysis**
4. **Constraint Implementation**
5. **Audit Trail Quality**
6. **Usability and Documentation**

## 6. Prize Structure

| Place | Cash | Benefits |
|-------|------|----------|
| 1st: SLAYED EVIL | $10,000 | SANS Summit pass + hotel + OnDemand course per member; webcast presentation |
| 2nd: HUNTED EVIL | $7,500 | SANS Summit pass + hotel + OnDemand course per member; webcast presentation |
| 3rd: FOUND EVIL | $4,500 | OnDemand course per member |

## 7. IP & Ownership
- All submissions remain property of creators
- Sponsor receives non-exclusive license for judging purposes
- Projects must not have been developed with financial support from sponsor

## 8. Legal
- Disputes resolved by individual, final, binding arbitration (AAA rules)
- Governed by laws of State of New York, USA
- All materials in English or with English translations
