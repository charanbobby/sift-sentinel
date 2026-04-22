# Teammate invite email

Used 2026-04-22 to invite Narayan Paravasthu to sift-sentinel. Kept as a template — adapt the middle paragraph to match the next recipient's strengths.

---

**To:** `<recipient email>`
**Subject:** Pulling you into a SANS hackathon thing

Hey Narayan,

Hope you're doing well — congrats again on the MBA kickoff at Westcliff.

Wanted to pull you into something I've been heads-down on for the last few weeks. I'm submitting to the SANS "Find Evil 2026" hackathon (due mid-June) — the prompt is to build an autonomous AI agent that runs on top of the SIFT Workstation for DFIR. It's turned into a much more interesting build than I expected going in.

One-liner: think SOC L1 persistence triage, but the analyst is an LLM, and there's a 13-rule deterministic critic sitting between the LLM's findings and anything that lands in the case record. The project vocabulary maps pretty directly onto stuff you live in — SOAR-style playbooks (we use LangGraph), detection engineering on structured agent output (the critic is basically Sigma-shaped rules over findings JSON), MITRE ATT&CK TA0003 sub-technique mapping baked into every finding, and capability-token scoping at the tool boundary. Your threat-detection + insider-threat background would be a real unlock, especially on the critic rule design and the negative-case stress test (we deliberately want to prove the critic isn't rubber-stamping LLM positive-finding bias).

Repo: `<repo URL>`

I wrote a couple of docs so you don't have to wade through the full plan to get started:

- Start here — `docs/onboarding/01-onboarding.md` (a ~25-min read that translates our architecture into SOC/SIEM/SOAR vocabulary)
- Then a concrete walkthrough on a real CTF image — `docs/onboarding/02-walkthrough.md` (end-to-end on DFIR Madness Case 001, with the actual pipeline outputs)

No pressure at all — take a look when you get a chance. Happy to hop on a quick call if it's easier to walk you through it live.

— Charan
