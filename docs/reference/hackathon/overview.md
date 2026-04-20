# FIND EVIL! Hackathon Overview

**Source:** https://findevil.devpost.com/

## Event Details
- **Duration**: April 15 – June 15, 2026
- **Format**: Online, Public
- **Location**: Remote/Virtual
- **Prize Pool**: $22,000+
- **Participants**: 773 registered
- **Organizer**: SANS Institute

## Challenge Description

### The Core Problem
The hackathon addresses a critical speed gap in cybersecurity. AI-powered attackers can achieve full domain compromise in under 8 minutes, while human incident responders are still accessing their toolkits. The challenge seeks to close this dangerous gap through autonomous AI agents.

### Mission Statement
Participants build autonomous AI agents on the SANS SIFT Workstation—a platform containing 200+ incident response tools developed over 18 years. The focus is on Protocol SIFT, which connects AI agents to tools via Model Context Protocol (MCP). Teams must teach agents to think analytically, sequence investigations logically, and self-correct when analyses don't align.

## Eligibility & Requirements

### Who Can Participate
- Must be above legal age of majority in their country
- Open to all countries/territories (standard restrictions apply)
- Teams up to 5 members or solo participants welcome

### Themes
- Cybersecurity
- Machine Learning/AI
- Beginner Friendly

## What to Build

### Core Objective
Improve Protocol SIFT's autonomous incident response capabilities across any forensic data type: disk images, memory captures, log files, network traffic, or remote endpoints.

### Supported Architectural Approaches

1. **Direct Agent Extension** (Claude Code/OpenClaw): Enhanced prompting and self-correction routines within existing agent loops
2. **Custom MCP Server**: Purpose-built servers exposing typed functions instead of generic shell commands, preventing destructive operations architecturally
3. **Multi-Agent Frameworks** (AutoGen, CrewAI, LangGraph): Specialized agents handling different analysis domains with structured communication
4. **Alternative Agentic IDEs** (Cursor, Cline, Aider): AI-native development environments with built-in interfaces

### Starter Project Ideas
- Self-correcting triage agents that evaluate and improve their own output
- Multi-source correlation engines comparing disk and memory findings
- MCP-connected live triage systems
- Analyst training loops explaining reasoning at each step
- Accuracy benchmarking frameworks with ground truth testing
- Purpose-built MCP servers with zero spoliation risk
- Persistent learning loops with iteration tracking and max-iteration caps

## Required Submissions (All 8 Components)

1. **Code Repository**: Public GitHub with MIT/Apache 2.0 open-source license
2. **Demo Video**: 5 minutes maximum showing live execution with narration
3. **Architecture Diagram**: Component connections, architectural patterns, security boundaries
4. **Project Description**: Devpost format covering approach, challenges, learnings
5. **Dataset Documentation**: Testing data sources and findings
6. **Accuracy Report**: Self-assessment of findings, false positives, hallucinations, and evidence integrity methods
7. **Try-It-Out Instructions**: Deployment URL or local setup steps for judges
8. **Agent Execution Logs**: Structured logs tracing all tool executions and agent communications

## Judging Criteria (Ranked by Priority)

1. **Autonomous Execution Quality** (tiebreaker): Real-time reasoning, failure handling, self-correction
2. **IR Accuracy**: Correct findings, caught hallucinations, confirmed vs. inferred distinctions
3. **Analysis Breadth/Depth**: Volume of case data handled effectively
4. **Constraint Implementation**: Architectural vs. prompt-based guardrails
5. **Audit Trail Quality**: Traceability from findings to specific tool executions
6. **Usability & Documentation**: Deployability and community buildability

## Prize Structure

| Place | Prize | Awards |
|-------|-------|--------|
| 1st (Slayed Evil) | $10,000 cash | SANS Summit pass + hotel + OnDemand course per member; webcast presentation |
| 2nd (Hunted Evil) | $7,500 cash | SANS Summit pass + hotel + OnDemand course per member; webcast presentation |
| 3rd (Found Evil) | $4,500 cash | OnDemand course per member |

## Key Resources

- **Slack Community**: Protocol SIFT Slack for questions, team formation, mentor access
- **SIFT Workstation**: Download from sans.org/tools/sift-workstation
- **Installation**: Protocol SIFT installs via: `curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash`

## Context & Motivation

The hackathon responds to November 2025 Anthropic findings on state-sponsored operations using AI for reconnaissance and lateral movement at "physically impossible" request rates for humans. SIFT Workstation represents the defensive counterpart—giving incident responders AI co-pilots operating at adversarial speeds.

## Important Notes

- Judges will evaluate evidence integrity approaches carefully
- Submissions using prompt-based restrictions must document failure modes
- Structured execution logs enable complete auditability of findings
- Multi-agent submissions require timestamped inter-agent communication logs
- Persistent loop submissions must demonstrate iteration-over-iteration improvement
