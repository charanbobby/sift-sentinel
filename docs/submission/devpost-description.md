# Sift Sentinel — Devpost Project Description

> Copy-paste this into Devpost. The sections map to Devpost's standard fields.
> Update the GitHub URL, demo video link, and any TODOs before submitting.

---

## Inspiration

A junior analyst arrives at 2am with a hard-drive image pulled from a compromised Windows machine. They have roughly an hour to answer two questions: what did the attacker do to make sure they can come back after a reboot, and what is the attacker doing right now if the machine is still live? The typical toolkit is a forensics workstation, a dozen command-line tools, and tribal knowledge about where to look. This project automates that triage so a single analyst — or a judge evaluating a submission — can get the answer in minutes, not hours, without needing to know which tool produces which file.

We also noticed that the threat landscape has shifted. Attackers in 2025-2026 have started using AI tools themselves on compromised hosts: running large-language-model prompts to generate payloads, using AI assistants to help them enumerate the network, storing model weights in the user profile. Those artifacts do not appear in any classic DFIR checklist. We built specific detectors for them.

---

## What it does

Sift Sentinel takes one input: a Windows hard-drive image (E01 format). Optionally, it also accepts a Windows memory dump captured from the same machine. It produces one output: a short, cited report that lists every persistence mechanism the attacker installed and, if memory is available, every sign that the attacker is still active right now.

The pipeline works in five stages a human can follow along with:

1. **Extract:** A fast, cheap AI model skims the image metadata and decides which parts of the disk are worth examining (registry hives, scheduled-task folders, startup locations, and so on).
2. **Plan:** A second AI model writes a specific plan of tool calls to run — which forensic tools, against which files, in which order. A human sees this plan and approves it before anything executes.
3. **Execute:** The approved tools run. Each call is checked against the approved plan before it fires; any call that wasn't in the plan is rejected automatically.
4. **Interpret:** A third AI model reads the tool outputs and writes structured findings. Each finding names the tactic (how the attacker maintains access), the specific technique (what mechanism they used), and cites the exact piece of evidence from the tool output that supports the claim.
5. **Critic:** A deterministic rule engine (no AI involved) checks every finding against more than a dozen rules before the finding is allowed out. Rules include: every claim must cite real evidence in the tool output, absence claims are only allowed if all tools ran cleanly, memory-class findings must have three independent corroborating signals. Findings that fail go back to the AI for a corrected pass, with a budget cap on retries.

A human then sees the final findings and approves or escalates before anything is committed.

---

## How we built it

**The core pipeline** is a LangGraph state machine. Each stage is a typed node; failures route back to re-plan with a budget cap rather than crashing. Every stage logs to a shared trace so a human can replay exactly what happened and why.

**The MCP server** sits between the AI and the forensic tools. The AI cannot run arbitrary shell commands. It can only call a small set of typed functions: five for disk analysis (filesystem stats, directory listing, file extraction, registry parsing, scheduled-task parsing) and five for memory analysis (process list, command lines, network connections, loaded DLLs, injection scan). Each call carries a capability token tied to the human-approved plan; calls outside the plan, or against paths outside the case folder, are rejected by the server before execution.

**Two-channel evidence handling** keeps raw bytes and parsed fields separate. The analysis AI never sees raw forensic bytes; it only sees structured fields the server extracted. If the server's prompt-injection scanner flags an evidence record (for example, an attacker-controlled filename that contains text designed to manipulate an AI), the parsed content is walled off before it reaches the analysis stage.

**Real-time cost transparency:** every AI call prints its actual cost — read directly from the provider's usage field, not from a hand-maintained price table — before and after the call. A runaway prompt is visible in seconds.

**AI-attacker detection:** the memory channel includes detectors for artifacts left by attackers who use AI tools on the compromised host. These include model-weight files in unexpected locations, LLM-related process names, and prompt-injection payloads embedded in scheduled-task XML.

---

## Challenges we ran into

**The hardcoded-name trap.** Early versions of the planner would guess scheduled-task filenames like "At1" from XP-era documentation and try to parse them directly. On Windows 7 and later, those files don't exist. The fix was a prompt-layer rule that forbids any hardcoded task name and requires the planner to enumerate the task folder first, then parse whatever is actually there. We added a regression test so the rule can't silently drift out of the prompt.

**False critic escalations.** The critic rule that checks for unsubstantiated absence claims was initially too strict: it rejected memory-class findings that correctly reported "no injection found" in a given process. The rule had to be narrowed to exempt findings in the `NOT_FOUND` category, which is the category the interpreter uses specifically for confirmed-absence memory results.

**Cost transparency vs. cost surprise.** We discovered mid-project that directory-listing tool outputs (which can be 100,000+ characters of inode tables) were being passed directly to the interpretation AI. The interpretation AI only needed the parsed forensic findings, not the navigation data. Stripping those outputs before the interpretation call reduced per-run cost by roughly an order of magnitude.

---

## Accomplishments that we're proud of

- **Zero false positives across every case with a known answer key.** On three machines where we have an official ground-truth answer, the agent found every malicious item and never invented one.
- **The agent literally cannot run arbitrary shell commands.** This is not a prompt-level constraint; it is an architectural one. The MCP server rejects any call not in the human-approved plan before the call reaches the OS.
- **A deterministic critic that catches AI mistakes before humans see them.** More than a dozen rules, no AI in the loop, budget cap on retries. The critic fired 13 times across 7 runs; 12 of those were real issues it correctly caught.
- **Memory-channel findings with independent corroboration.** Every memory-class finding cites at least three independent signals from separate Volatility plugins. A finding that appears in only one plugin is held for human escalation.

---

## What we learned

Building a safe AI agent for forensic work is less about the AI and more about the scaffolding around it. The AI is good at reading tool output and writing structured summaries. It is bad at knowing what tools to run without guardrails, staying within a pre-approved scope, and not inventing plausible-sounding evidence. Every architectural decision in this project is a response to one of those failure modes.

We also learned that AI-assisted attackers leave different artifacts than classic malware. The threat landscape is moving faster than most DFIR checklists, and the detectors have to be built explicitly; they don't fall out of standard persistence-hunting workflows.

---

## What's next for Sift Sentinel

- **Hosted try-it-out endpoint.** A judge with Claude Code can connect to our MCP server, pass a case file path, and watch the agent run without installing anything locally.
- **AI-attacker demonstration case.** We are building a synthetic disk image with staged AI-assisted-attacker artifacts (model weights in the user profile, LLM-related process names, prompt-injection payloads in task XML) to demonstrate the detection chain end to end.
- **Ablation study completion.** Two ablation rows (capability-token verification disabled; classification field removed) have code prepared but need runs to fill in the accuracy delta numbers.
- **Ground-truth annotation of memory-channel findings.** The four runtime findings from the first dual-channel run are plausible to human review; they need annotation against an authoritative source before they become scored true positives.

---

## Built with

Python, LangGraph, Anthropic Claude (Sonnet 4.6 for planning and interpretation, Haiku for extraction), Google Gemini Flash (cheap structured-output extraction), Volatility 2.6.1, The Sleuth Kit, RegRipper, SIFT Workstation (Ubuntu forensics container), Docker, MCP (Model Context Protocol)

---

## Links

- GitHub: https://github.com/charanbobby/sift-sentinel
- Architecture diagram: see `docs/planning/architecture.html` in the repo
- Accuracy report: see `docs/submission/accuracy-report.md` in the repo
- Demo video: TODO (recorded closer to deadline)
