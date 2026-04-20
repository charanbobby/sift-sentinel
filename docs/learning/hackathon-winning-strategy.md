# Find Evil Hackathon — Winning Strategy Framing

**Purpose:** a framework for making scope and priority decisions against the *real* judging environment of this hackathon, not a generic "build cool stuff" target. Updated 2026-04-19 after learning the field size (~2000 participants).

> **⚠️ Read this before making any scope-expansion decision.** It changes what "good work" even means for this submission.

---

## The judging environment

- **Sponsor:** SANS (DFIR-focused training organization).
- **Submission deadline:** 2026-06-15 (~8 weeks from 2026-04-19).
- **Field size:** ~2000 participants (learned 2026-04-19).
- **Reference submission judges have already seen:** [Protocol SIFT / Valhuntir](https://github.com/…) — a 9-server MCP platform for forensics. **Not a prior winner, but the "example" template.** Judges have internalized what that shape looks like. Building a Valhuntir-shaped submission makes us indistinguishable from a large fraction of the 2000-entry field.

### Judging reality at 2000 submissions

Nobody reads 2000 entries deeply. Likely filtering:

1. **Screening pass (~30 seconds per entry):** demo video, README hook, does-it-run check. Most entries get eliminated here.
2. **Shortlist pass (~10 minutes per entry):** actual code review, eval numbers, novel claims.
3. **Deep review (~1 hour per entry, for finalists only).**

**This means:** a project can have the best engineering in the field and still lose at screening if the hook isn't clear in 30 seconds.

---

## What judges likely reward (inferred from SANS context + Valhuntir baseline)

| Signal | Why it matters | How to demonstrate |
|---|---|---|
| **Runs on real evidence** | 80% of hackathon submissions will be scaffolded demos on fake data. Real E01 = credibility. | Pipeline runs end-to-end on a public DFIR CTF image (DFIR Madness Case 001 works — published answer key makes results verifiable). |
| **At least one genuinely novel claim** | In a 2000-person field, *"we did Valhuntir but smaller"* loses. *"We did the thing no one else did"* wins shortlisting. | Capability tokens, adversarial-evidence defense (injection audit of tool stdout), chain-of-custody sha256 auditing, deterministic Critic with self-correction — any of these as a focal point. |
| **Eval numbers behind claims** | "We built an agent" with no eval ≈ bullshit. "P=1.00 across N cases + hallucination-count=0" = research-grade signal. | `score.py` + per-case scorecards + pre/post deltas for each substantial change. |
| **Honest limitations** | Overclaim is penalized disproportionately at this scale because judges have seen thousands of "works great!" claims that don't. | "Here are 3 cases we validated. Here's what's out of scope. Here's what we'd do next." |
| **Strong demo narrative** | Judges at 2000 scale remember stories, not feature lists. | One sentence that frames the whole submission. Two demo clips max. The 30-second hook is all most judges will see. |

## What judges likely penalize

- **Generic architecture.** Default Claude Code + stock MCP + basic README ≈ noise.
- **Scope creep + nothing finished.** A half-built 5-stage DFIR agent loses to a fully-built 2-stage agent.
- **Unsubstantiated claims.** "Self-correcting" without a disagreement log = prompt language, not engineering.
- **Undocumented failures.** If the demo hides the edge cases, reviewers will assume the worst.

---

## The four differentiation axes (not just one)

My earlier scope analysis framed this on a single axis — **breadth** (how many investigation questions / stages we cover). That was too narrow. There are at least four:

| Axis | What it means | Where "winning" lives on it |
|---|---|---|
| **Breadth** | How many of the 14 attack-lifecycle stages we cover | Shallow here is fine; Valhuntir already went wide. Going wider = chasing. |
| **Depth** | How rigorous the single-stage analysis is — eval numbers, failure modes, critic loops | **Deep here is differentiating** — rarely well-done at hackathon scale. |
| **Novelty** | What we do that no other hackathon submission in the field does | **Where the hook lives.** Capability tokens + injection defense are the strongest candidates. |
| **Autonomy posture** | L1 (human approves plan) → L2 (agent self-corrects) → L3 (exception-only escalation) | Already documented in the autonomy-dial climb in PLAN.md. Rare for hackathon entries to address. |

**The combo that wins a 2000-person hackathon:** depth + novelty + documented-honest autonomy climb. Breadth is the dimension *not* to compete on.

---

## Three winning framings — ranked by feasibility at 8 weeks × 2000 field

### Framing A — "Narrow-rigorous architecture demo" (current path)

**Pitch:** *"An MCP-native DFIR agent that runs end-to-end on real disk images, with a deterministic self-correction critic and instruction-audit for adversarial evidence. Three cases validated, precision 1.00, zero hallucinated evidence."*

- **Scope:** Q1 (persistence) only.
- **Strengths:** Slices 3 + 5 + 6 all novel, each a hook on its own. Eval numbers already strong.
- **Risk:** Demo feels small — "this is just persistence?"
- **Who this beats:** Valhuntir clones (most of the field), demos without eval numbers.
- **Who beats this:** Entries that do equivalent rigor AND have a more memorable story.

### Framing B — "Narrow-but-generalizing" (T2)

**Pitch:** *"Same architecture, two investigation questions (what persistence, how did they get in), cross-referenced timeline, critic catches seeded failure modes on demo. The architecture is the product."*

- **Scope:** Q1 + Q2 (persistence + initial-access timeline).
- **Strengths:** Cross-reference demo is memorable. "Architecture generalizes" is a defensible claim. Keeps novelty (capability tokens, injection defense) on the plan.
- **Risk:** Q2 ground-truth is thinner (1 case with public answer); can't carry the "rigor" narrative as strongly. Added tool work (event log + Prefetch parsers) costs 3–4 weeks = pushes one novel slice (5 or 6) off the plan.
- **Trade:** gain demo memorability, lose some novelty slice.

### Framing C — "Full attack-chain" (explicitly rejected)

**Pitch:** *"Autonomous DFIR agent covering the full ransomware-attack lifecycle: initial access → persistence → lateral movement → exfil."*

- **Scope:** 4+ investigation questions, many new artifact types.
- **Strengths:** Ambitious, potentially memorable IF delivered.
- **Risk:** At 8 weeks × existing ~5 slices of commitments, very high chance of 60%-complete at deadline. Resembles Valhuntir (the template everyone's copying).
- **Don't pick this** unless willing to drop Slices 5 (capability tokens) + 6 (observability) entirely — which kills novelty.

---

## The "what makes us the only one?" test

A useful litmus: *"Is there anything in our submission that nobody else in the 2000-entry field will have done?"*

- **Capability tokens per-plan, per-tool** (Slice 5) — genuinely rare in MCP projects. Research-adjacent.
- **Adversarial-evidence scanning before LLM sees tool output** (Slice 5) — essentially unaddressed by Valhuntir, rarely discussed in public hackathon projects.
- **Sha256 chain-of-custody linked to plan digest** (Slice 6) — compliance-adjacent, credible in legal-context DFIR.
- **Deterministic Critic with per-rule self-correction instruction templates** (Slice 3) — most hackathon "self-correction" claims are unstructured LLM retry loops. Ours is rule-based with audit.

Every one of these is on the current plan and none are made stronger by adding a second investigation question. **The novelty budget is in the guardrail slices, not in tool breadth.**

---

## Recommended posture (given 2000 participants)

1. **Lock the scope at Framing A or B — not C.**
2. **Front-load novelty work.** Slices 3 + 5 + 6 (Critic + capability tokens + injection defense + chain-of-custody) are where the hook lives. Do these before any scope widening.
3. **Treat Q2 (T2) as optional-stretch, not a committed slice.** If Slices 3/5/6 finish on time, *then* consider Q2 as a "generalization demonstration" in Slice 4 (cheap: one new tool, reuse existing pipeline + Critic). If they don't, Q1-only is a complete submission.
4. **Write the 30-second pitch first.** Before any more code, draft the submission abstract. If the abstract doesn't have a sentence judges will remember, the scope is wrong.
5. **Budget eval expansion.** 2 cases (base-wkstn-05 + DFIR Madness) is minimum. Target 5+ cases by Slice 4 — publicly-available DFIR CTF images cost no new annotation work when ground truth is published.

---

## Tripwires — when to cut scope

Triggers to fall back from Framing B → A, or reduce Framing A scope:

- **Slice 3 Phase B (Critic) takes >2 weeks.** Kill T2 / Q2 entirely.
- **Slice 5 (capability tokens + injection defense) hits a blocker.** This is the novelty hook — if it doesn't ship, all the other slices lose their framing. Fall back to just Critic + observability, drop T2.
- **Q2 tool work on Linux (Prefetch parser, event-log filtering) eats >1 week on fail-fast probes.** Drop Q2.
- **Eval numbers regress after Slice 5 capability-token changes.** Stop, restore Slice 2.5 pipeline, do not ship Slice 5 until fixed.

---

## What this means for the next decision

Current pending decision: commit to T2 (add Q2 as its own slice)?

**Revised recommendation given 2000 participants:** **do not commit T2 as a slice now.** Proceed with Slice 3 Phase B (Critic implementation) and Slice 5 (novelty hooks). Treat Q2 as a late-stage stretch demo that either rides along with Slice 4 (if cheap enough) or becomes a documented extension point (if not). The novelty slices are what differentiate in a 2000-entry field — they shouldn't be traded for a second investigation question unless that question *also* carries novelty.
