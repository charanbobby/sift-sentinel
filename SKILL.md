# Project Bootstrap — How I Build Projects

This skill defines my preferred workflow for building new AI/software projects with Claude Code. Follow these phases in order. Each phase must be validated before moving to the next.

**Proven on:** Fair Play Initiative (document→database pipelines), MaplePulse (synthetic focus groups). The patterns are domain-agnostic.

---

## Phase 1: Research & Reference Study

**Before writing any code**, find and deeply study a reference project.

1. Identify an existing open-source project that solves a similar problem
2. Read every file — understand the data pipeline, prompting strategy, architecture decisions
3. Create a `Learning.md` — a comprehensive architectural breakdown, file by file
4. Identify what needs to change for our domain (don't port blindly — adapt)
5. Note attribution requirements (check LICENSE files)

**Output:** `Learning.md` in `docs/learning/` with full architectural analysis

---

## Phase 2: Data Grounding

**Ground everything in real data, never random values.**

1. Identify authoritative data sources (government census, official statistics, industry databases)
2. Research and structure probability weights / lookup tables from real sources
3. Build the data layer first — this is the foundation everything else depends on
4. Validate data integrity: check for nonsensical combinations (e.g., entry-level job with executive salary)
5. If using time-sensitive data, add inflation/adjustment factors to bring values to current year

**Output:** Data module with source attribution comments

---

## Phase 3: Notebook Prototype

**Always start in Jupyter.** Notebooks let me run each step independently, inspect intermediate state, and iterate without restarting servers.

1. **Verify before you prescribe.** Before folding any unfamiliar API call, env var, or library pattern into the notebook, probe it in isolation — a one-off container script, a 3-line Python snippet, a single curl. This catches wrong endpoints, missing deps, and version mismatches in seconds instead of after they're wrapped in ten cells of pipeline code. Never prescribe code you haven't run.
2. Create `experiments/` directory for notebooks
3. Build the core pipeline end-to-end in a notebook first
4. Run each node independently, inspect outputs at every stage
5. Use notebooks to discover that prompt quality is the bottleneck (it usually is)
6. Add observability/tracing integration from day one — not after scaling

**Output:** Working notebook in `experiments/` that proves the pipeline works

---

## Phase 4: Prompt Engineering (Parallel Workstream)

**Design prompts separately from code.**

1. Use a playground environment (OpenAI Playground, etc.) for prompt iteration
2. Test against edge cases: vague inputs, culturally sensitive topics, deliberately bad content
3. Identify failure modes: sycophancy, hallucination, generic outputs
4. Iterate until prompts handle edge cases
5. Hand refined prompts to Claude Code for integration

### Anti-Sycophancy Checklist
- Use narrow scales with anchored descriptions (1-5, not 1-10)
- Avoid aspirational labels ("perfect" → use "natural")
- Replace booleans with 3+ level enums (true/false → irrelevant/somewhat/directly_relevant)
- Add explicit calibration instructions: "Score independently. Do not default to positive scores."
- Consider multi-model rotation to diversify biases

### Prompt Hardening
Don't just tell the AI what to do — tell it what NOT to do, and what to do when there's nothing to do.

- **Entity-type boundaries:** Define clear category fences so the LLM doesn't misclassify entities across schema fields (e.g., a law name landing in a location field, a category ending up as a tag).
- **Exclusion categories:** Explicitly list what should NOT be extracted (e.g., boilerplate, definitions, metadata that isn't actionable data).
- **Absence handling:** When data is missing from the source, the model must output `NOT FOUND` instead of fabricating plausible values. Without this, hallucinated dates, names, or IDs silently corrupt the database with realistic-looking but invented data.
- **Over-extraction guards:** Set expected output ranges so the model knows when it's being too aggressive (e.g., "this input type typically yields 10-20 items, not 50").

### Prompt Distillation
Use a strong model to teach cheap models — no fine-tuning required.

1. Run a strong model (e.g., Claude Sonnet) once on the hardest pipeline step
2. Study its output — extract the structural reasoning patterns it discovered
3. Encode those patterns as explicit guidance in cheaper models' system prompts
4. Result: cheap model follows the same playbook at 40-120x cost reduction
5. Instantly reversible — it's just prompt text, not model weights

**Output:** Refined, hardened prompts ready for code integration

---

## Phase 5: AI Pipeline Design

**Decompose monolithic AI calls into transparent, reviewable steps.**

This is the most critical architectural decision for any AI-powered application. A single AI call that goes from input to output is a black box. When the output triggers real consequences, you need to know exactly why.

### 5a. Pipeline Decomposition

Break every AI pipeline into discrete steps where each step produces a reviewable artifact:

| Pattern | Example (Fair Play) | Example (MaplePulse) |
|---------|-------------------|---------------------|
| **Extract** — identify what the input contains | Keyword chips mapped to schema categories | Parse audience brief → structured AudienceSpec |
| **Reconcile** — match against existing state | Entity matching against DB records | Search existing personas before generating new ones |
| **Plan** — propose what to do (HUMAN CHECKPOINT) | Table-by-table INSERT plan with confidence scores | Context projection — which persona attributes matter |
| **Execute** — carry out the approved plan | Generate SQL from the plan | Fan-out reactions from projected personas |

**Why decomposition works:**
1. Each step produces a reviewable artifact — no more black boxes
2. Each step can use a different model (expensive where quality matters, cheap where mechanical)
3. Errors are localized — if the output is wrong, check the plan; if the plan is wrong, check the extraction
4. Human checkpoint separates "what did the AI understand?" from "what will it do?"

### 5b. Entity Reconciliation

**A stateless pipeline will silently corrupt shared databases.** If your pipeline writes to a database, it MUST know what's already there.

- Pre-query existing records before LLM processing
- Pass existing records as context so the LLM can match against them (catches typos, abbreviations, name variations)
- Run deterministic conflict detection (date overlaps, duplicate entities, overwrites)
- Human reviews flagged conflicts before execution
- Matched IDs flow downstream so the plan reuses existing records instead of creating duplicates

### 5c. Per-Step Model Selection

Make model choice a first-class concern, not an afterthought:

| Step Type | Model Strategy | Why |
|-----------|---------------|-----|
| Classification / extraction | Cheapest (gemini-3-flash, gpt-5-nano) | Mechanical task, quality floor is high |
| Reconciliation / matching | Mid-tier | Needs semantic understanding but not creativity |
| Planning / reasoning | Best available (Claude Sonnet) | The verification gate — quality matters most here |
| Code generation / execution | Cheap | Follows the plan mechanically |
| Multi-perspective reactions | Fan-out across multiple models | Diversity of perspective, not depth |

### 5d. Prompt Caching

For pipelines that run repeatedly with the same system prompts / schema context:

- Cache static context (system prompts, schema definitions, few-shot examples) across runs
- Only variable content (the actual input) changes per call
- OpenRouter supports this natively; ~40% cost reduction on repeated runs
- The more the pipeline runs, the cheaper it gets

**Output:** Decomposed pipeline with reviewable artifacts at each step

---

## Phase 6: Fan-Out to Full-Stack App

**Once the notebook validates the pipeline, deliberately expand to a proper application.** This is not incremental — it's a planned architectural expansion.

### 6a. Architecture Decisions

Make and document these choices before writing app code:

| Decision | My Defaults |
|----------|-------------|
| Backend | FastAPI (async-native, SSE, Pydantic) |
| Frontend | Next.js + React + TypeScript + Tailwind |
| Streaming | Server-Sent Events (simpler than WebSockets for unidirectional) |
| Containerization | Docker Compose (services mounted to D: drive) |
| Package manager | uv (never pip) |
| DB (simple projects) | SQLite + FTS5 (migrate later if needed) |
| LLM routing | OpenRouter (single API, cost tracking, prompt caching) |
| State machine | LangGraph (for multi-step AI workflows with branching) |

### 6b. Frontend-First with Mock Data

1. Build the complete UI with mock data before connecting to backend
2. Include deliberately negative/edge-case mock data to test all UI states
3. Validate the full user workflow experience end-to-end with mocks
4. Only then connect to the real backend

### 6c. Human-in-the-Loop Splits

Split long-running pipelines into phases with human checkpoints:
- User reviews and approves intermediate results before proceeding
- User can exclude bad results before they pollute downstream steps
- This builds trust — the system shows its work

### 6d. Sandbox / Production Isolation

**AI-generated actions must never touch production without human approval.**

- Playground mode (SQLite): full execution, reset/seed, sample data for testing
- Production mode (PostgreSQL): review only, execution disabled, no reset capability
- Auto-detect from `DATABASE_URL` — no manual toggle needed
- This is a core architectural decision, not a convenience feature

### 6e. Dual-Database Strategy (when needed)

Use two databases when analytics must survive resets:
- **Main DB** (`DATABASE_URL`): Domain data — SQLite in dev, PostgreSQL in prod
- **Analytics DB** (`ANALYTICS_DATABASE_URL`): Always PostgreSQL — feedback ratings, token usage, cost logs persist even when main DB is reset in playground mode

**Output:** Working full-stack app with Docker Compose

---

## Phase 7: Observability & Cost Optimization

1. Trace every LLM call — model, tokens, cost, latency
2. Group related calls by session/run ID
3. Name spans for each pipeline phase
4. Use visual trace tools to find bottlenecks (Langfuse, Arize, or in-app UI)
5. Optimize model selection: use cheap models (gemini-3-flash, gpt-5-nano) for agent/tool-calling tasks, reserve expensive models for quality-critical steps
6. Surface observability where the user already works — token badges, cost per step, latency inline in the UI, not buried in a separate dashboard

**Output:** Integrated tracing with cost visibility

---

## Phase 8: Evaluation & Feedback Loop

**Build evals before declaring done.** Don't rely on vibes.

### 8a. Evaluation Framework

1. Combine automated checks (fire every run) with human-in-the-loop judgments
2. Embed eval UI into the existing workflow — don't make testers fill out separate forms
3. Define pass criteria up-front for each eval
4. Store eval data linked to traces (e.g., via trace_id)
5. Automated evals fire silently; human evals are lightweight (thumbs up/down or Good/Partial/Bad)

### 8b. Feedback-Driven Progressive Autonomy (Trust Lifecycle)

Human ratings aren't just for measurement — they're the mechanism for earning autonomy:

| Phase | Behavior | Trigger |
|-------|----------|---------|
| **Hands-On** | Human reviews every output, rates every step | Default starting state |
| **Building Trust** | High-confidence results auto-approve; human reviews only flagged items | Model consistently rates >90% Good on a step |
| **Autonomous** | Routine work flows through automatically; humans handle exceptions only | Sustained high performance + cost viability |

**The feedback loop closes the circle:** Human ratings → model comparison → confidence thresholds → progressive autonomy. Without the ratings infrastructure, there's no path from Phase 1 to Phase 3.

**Output:** Eval framework with defined pass criteria and a path to progressive autonomy

---

## Phase 9: Production Deployment

1. Docker Compose with named volumes for persistence
2. Multi-stage Docker builds (slim images, health checks, restart policies)
3. Nginx reverse proxy with Let's Encrypt SSL
4. Secrets in `.env` on server only — never in git, never in Docker image
5. Bump `APP_VERSION` before every deploy
6. Rebuild containers after backend code changes (no asking)
7. Lifespan hooks with daemon threads for slow initialization (DB init doesn't block health checks)

**Output:** Deployed application

---

## Phase 10: Demo Scripts

**Every project gets two scripts for video presentation — one business, one technical.** These are written after the app works but before recording. They live in `docs/`.

### 10a. Business Script (`docs/script_business.md`)

**Audience:** Non-technical — marketers, founders, hiring managers, potential users.
**Length:** 5-7 minutes.
**Tone:** Conversational, honest, minimal jargon. Do NOT oversell.

**Structure:**

| Section | Duration | Purpose |
|---------|----------|---------|
| **Hook** | 15-30s | One sentence: what does this solve? Lead with a concrete scenario, not a feature list. |
| **The Problem** | 45-60s | The pain point everyone recognizes. Use specific examples, not abstractions. |
| **What It Does** | 60-90s | Step-by-step walkthrough of the core workflow. Screen recording with narration. |
| **Live Demo** | 2-3 min | Hero demo with real data. Show every screen. Let reactions/results stream — don't rush. Add 1-2 quick alternative demos (different modes/use cases). |
| **Honest Limitations** | 30-45s | What this is NOT. Position as complement, not replacement. Use an analogy ("spell-checker for messaging," "first filter, not the final answer"). |
| **Why The Data Matters** | 30-60s | What grounds this beyond generic AI. Real data sources, quality controls, design decisions that prevent common AI failure modes. |
| **Close** | 15-30s | Recap + call to action. Link in description. |

**Rules:**
- Do NOT oversell — be honest about what it is and isn't
- Keep technical details minimal — save for the technical video
- Credit reference projects / inspiration
- Include `[PLACEHOLDER]` tags for screen recordings and examples to fill during recording
- Include `[SCREEN: ...]` cues for what to show on screen at each moment

### 10b. Technical Script (`docs/script_technical.md`)

**Audience:** Hiring managers evaluating decision-making, system thinking, and AI-augmented development. Also: engineers who want to understand the architecture.
**Length:** 15-20 minutes.
**Tone:** Honest narrative. Claude Code wrote most of the code — what matters is the sequence of decisions, problems spotted, architecture shaped, and interventions that turned AI output into a working product.
**Style:** Storytelling through the build journey — each section is a problem → decision → result.

**Structure:**

| Section | Purpose |
|---------|---------|
| **The Spark** | How you found the reference project, what you learned, what needed to change for your domain |
| **Data Grounding** | What data you researched, why it matters, what problems you caught (e.g., nonsensical data combinations) |
| **The Prototype** | Notebook phase — what the pipeline looked like, what it taught you |
| **Prompt Engineering** | Meta prompting workflow, playground iterations, failure modes discovered |
| **Fan-Out to Full-Stack** | Architecture decisions table, frontend-first approach, why each choice |
| **The [Domain] Problem** | The biggest quality problem you hit and how you solved it (sycophancy, hallucination, duplication, etc.) |
| **The [Key Feature]** | The most architecturally interesting feature and the decisions behind it |
| **Observability** | What you instrumented, what it revealed, what you optimized |
| **Production Deployment** | Deployment decisions, human-in-the-loop workflow, infrastructure |
| **Evaluation Framework** | How you measure quality — automated + human evals, pass criteria |
| **Architecture Evolution** | Full picture diagram — all layers, all components |
| **What I'd Do Differently** | Honest retrospective — shows self-awareness |
| **My Role vs. AI's Role** | Two-column breakdown: your decisions/interventions vs. Claude Code's implementation. End with the pattern statement. |

**Rules:**
- Each section: show the problem, show your decision, show the result, move on
- Reference `[DIAGRAM: ...]` tags for architecture diagrams (build a separate `diagrams_technical.html`)
- Include a git commit table showing the evolution commit by commit
- Include technical stats (LOC, endpoints, components, LLM calls per run, dev time)
- Don't apologize for using AI tools — the value is in the decisions, not the keystrokes
- The "My Role vs. AI's Role" section is critical — it demonstrates what you actually bring to the table

### 10c. Technical Diagrams Page (`docs/diagrams_technical.html`)

A self-contained HTML page opened alongside the technical video. Each diagram maps to a script section via `[DIAGRAM: ...]` cues.

**Structure:**
- Sticky TOC at top with color-coded links to each diagram
- One card per diagram, each with title + script section reference
- Cards scroll independently — click TOC to jump

**Diagram types to include (adapt per project):**

| Diagram | What it shows | Visual pattern |
|---------|--------------|----------------|
| Data/Enrichment Pipeline | How raw data becomes usable entities | Vertical flow: source → transform → enrich → output |
| Pipeline Flow | Multi-step AI pipeline with node names | Vertical chain of pipe-nodes with arrows |
| Project Evolution | How the project grew phase by phase | Horizontal phase cards with dates + parallel workstreams below |
| Before/After Comparison | Quality problem you fixed (e.g., sycophancy, duplication) | Side-by-side red/green cards with tables |
| Key Feature Architecture | The most interesting feature (agent, reconciliation, etc.) | Vertical flow with nested tool boxes |
| Observability Stack | What you instrumented and why | Side-by-side cards (production tracing vs. dev debugging) |
| Human-in-the-Loop Workflow | Multi-phase workflow with checkpoints | Horizontal workflow cards with endpoints, red text on human gates |
| Evaluation Framework | Automated vs. human evals | Two columns (automated / human) + storage architecture |
| System Architecture | Full stack overview | Three columns (frontend / backend / data+infra) |
| My Role vs. AI's Role | Two-column decision/implementation split | Blue (your decisions) + purple (Claude Code's implementation) |

**Design rules:**
- Pure HTML + inline CSS — no external dependencies, works offline
- Clean, professional look: white cards on light gray, rounded corners, subtle shadows
- Color-coded by section (blue for data, purple for pipeline, red for problems, green for solutions, amber for features)
- Print-friendly: `@media print` removes shadows, adds borders
- Use `scroll-margin-top` on cards so TOC jumps land cleanly below the sticky nav
- End with "The Pattern" callout — the same statement from the technical script

### 10d. Optional: Marketing Script (`docs/script_marketing.md`)

A read-along script for screen recording the live app. Shorter (5 min), heavily demo-driven, minimal talking. Copy-paste examples provided inline for each demo scenario. Include rapid-fire section showing range of inputs.

**Output:** Script files in `docs/`, diagrams HTML page, ready for video recording

---

## Environment Constraints (Always Apply)

- **Never `pip install` on host machine** — C: drive space constrained. Always use Docker containers mounted to D: drive
- **Always use `uv`** instead of pip inside containers
- **Testing models:** `google/gemini-3-flash` and `openai/gpt-5-nano` (cheap, fast)
- **Always rebuild Docker containers** after backend code changes without asking
- **Always bump `APP_VERSION`** in `backend/main.py` before deploying via `push.sh`

---

## Key Technical Insights (Hard-Won Lessons)

1. **Trust is earned, not declared.** You don't flip a switch and call the system reliable. You measure your way there — Phase 1 feedback is what makes Phase 3 possible.

2. **The plan is the product.** Extraction and execution are implementation details. The structured plan is what a human can actually read and approve. This is the verification gate.

3. **Prompt distillation > fine-tuning** for iteration speed. Run a strong model once, encode its reasoning into cheap models' prompts. 40-120x cost reduction, no training data, instantly reversible.

4. **RAG is not always the answer.** For exhaustive single-document extraction, full-text input beats retrieval. RAG adds value with many documents, not single-document pipelines. Test before assuming you need it.

5. **LLMs fill blanks — they don't flag them.** When source data is missing, the model fabricates plausible values instead of reporting the gap. Every extraction prompt needs explicit absence handling.

6. **Stateless pipelines corrupt shared databases.** If your pipeline doesn't know what's already in the DB, it will silently create duplicates. Entity reconciliation is not optional for production use.

7. **Playground mode is not optional.** AI-generated code/queries must never touch production without human approval. The sandbox/production split is a core architectural decision.

8. **Search before generate.** Always check existing data before creating new data. This keeps costs low and leverages organic growth of your data pool.

9. **Fail fast, in isolation, before it matters.** Unfamiliar APIs fail silently when folded into larger code. A 30-second throwaway probe ("does this endpoint return what I think?") saves hours of debugging inside a notebook or container. The time you spend verifying in isolation is always less than the time you spend debugging integrated code.

---

## The Pattern

> I identify problems, design solutions, choose technologies, craft prompts, and direct architecture. Claude Code turns those decisions into working code — fast and reliably. The skill is knowing *what* to build and *when* to intervene.

### Decision Flow

```
Research reference → Ground in real data → Prototype in notebook →
Design & harden prompts → Design decomposed pipeline →
Fan out to full-stack → Add observability →
Build evals & feedback loop → Deploy
```

Each phase validates the previous one. Don't skip ahead.
