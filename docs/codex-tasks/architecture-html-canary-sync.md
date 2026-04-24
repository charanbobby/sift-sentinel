# Codex task — sync architecture.html with canary tripwire + Slice 5 shipped status

**Created:** 2026-04-24 · **File:** `docs/planning/architecture.html` (2794 lines, hand-crafted HTML + CSS — no Mermaid, no SVG, no build step)

---

## Task summary

The codebase now ships:
1. **Canary tripwire** in `interpret_node` — a per-run random nonce embedded in the INTERPRET bundle; if the LLM echoes it, the instruction/data boundary leaked → `CANARY_LEAK` audit entry + run halt.
2. **Slice 5 full stack shipped** — capability tokens, dual-channel evidence handler, and repeat-guard + fresh-context primitives are all ✅ (they were `wip` when this HTML was last touched).

`architecture.html` still shows all three as `.chip wip`. Update the HTML to reflect reality, and add a chip for the canary tripwire. **Do not redesign the page.** Only extend existing patterns.

---

## Context (where the canary is wired — for understanding, not editing)

- Mechanism: bundle gains a top-level `_canary: "canary_<urlsafe-token>"` field; `INTERPRET_SYSTEM_PROMPT` tells the model to never reference it; `_check_canary_leak` scans the LLM response after it returns; hit → write `CANARY_LEAK` audit entry to `out/critic_disagreements.jsonl` → raise `RuntimeError` halting the run.
- Threat it defends: adversarial content inside evidence persuading the defender LLM to treat data as instructions — the prompt-injection attempt itself becomes a high-confidence forensic finding.
- Status: shipped 2026-04-24 as post-Slice-5 Tier-1 polish. 17 new tests; full suite 128/128 green.
- Reference docs already synced: `docs/planning/architecture.md`, `docs/planning/architecture-detailed.md`, `docs/runbooks/slice-5-runbook.md` Post-Close section, `docs/planning/PLAN.md` Current Status.

---

## Edits required (specific — stay inside the listed ranges)

### Edit 1 — Header date (line ~1573 area)

If the header carries a "last updated" date anywhere (search for `2026-04`), update to `2026-04-24`.

### Edit 2 — Status chip row (lines 1577–1589)

**Current state (line numbers exact):**
```html
<span class="chip live">13-rule critic</span>
<span class="chip live">structural invariants</span>
<span class="chip wip">capability tokens</span>
<span class="chip wip">evidence splitter</span>
<span class="chip wip">repeat guard + fresh context</span>
<span class="chip next">SHA-256 integrity ledger</span>
```

**Target state:**
- Flip `capability tokens`, `evidence splitter`, `repeat guard + fresh context` from `chip wip` → `chip live` (all shipped in Slice 5 — confirmed by `pipeline/mcp/tokens.py`, `pipeline/mcp/injection_scanner.py`, `pipeline/nodes.py` debounce nodes + `pipeline/graph.py` `plan_hash`).
- Add a new `<span class="chip live">canary tripwire</span>` after the `evidence splitter` chip (keep the defender-AI defenses visually adjacent).
- Leave `SHA-256 integrity ledger` as `chip next` (still Slice 6).

### Edit 3 — INTERPRET stage card (around line 1749)

Find the `<div class="name">INTERPRET</div>` block. Add one short sub-line that names the canary tripwire as a component of INTERPRET. Match the existing style of nearby sub-lines — look at neighboring stage cards (CRITIC around line 1770) to see how sub-features are rendered. Example copy if there's room: *"canary tripwire — response-scan for per-run nonce leak"*.

**If the card visual is tightly dimensioned and adding a line breaks the layout, skip this edit** and rely on the new status chip alone.

### Edit 4 — Four submission pillars (line ~1810)

Look at the four `<h3>`-labelled pillars starting near line 1810 (`Deterministic 13-rule Critic`, `Evidence splitter`, `Capability tokens bound to plan_digest`, `Linear hash chain (separate ledger)`). **Do NOT add a fifth pillar** — the four-pillar symmetry is load-bearing in the design. Instead:

- Extend the `Evidence splitter` pillar body with one sentence naming the canary tripwire as its **defender-AI integrity counterpart**. Suggested copy: *"On the defender side, a per-run canary tripwire detects if an attacker's content ever persuades the INTERPRET LLM to breach the instruction/data boundary — the attempt itself becomes a forensic finding."*

### Edit 5 — Critic deep-dive / rule list (lines 1863–~2050)

The rule list shows 13 rules and three `dest` classes (`retry INTERPRET`, `retry PLAN`, `escalate`). The canary tripwire is **not a Critic rule** — it runs inside `interpret_node` before Critic. Do not add it to the rule list.

Optionally, if there's a natural place in this section (e.g., a paragraph about what runs around Critic), add one sentence: *"A parallel tripwire runs before Critic: `interpret_node` embeds a per-run canary nonce in the bundle, and any leak of that nonce in the LLM response halts the run with a `CANARY_LEAK` audit entry — targeting adversarial prompt-injection at the defender LLM itself."* Omit if it doesn't land naturally — better to omit than to wedge.

---

## Style constraints — non-negotiable

1. **No new CSS classes.** Every edit must reuse an existing class (`chip live`, `chip wip`, `chip next`, stage-card structure, pillar `<h3>` formatting). If you feel a new class is needed, stop and flag that instead — it likely means the edit doesn't fit.
2. **No layout changes.** Don't move elements, don't change flex/grid properties, don't adjust widths/margins. Add content inside existing containers only.
3. **No new script/style blocks.** The file has 8 incidental matches for `mermaid|<svg|<script` but is not wired to any external renderer. Keep it that way.
4. **No color palette changes.** The palette (#1a1a2e, #3b82f6, #d1fae5, #fef3c7, #f3f4f6, #6ee7b7, #fcd34d, #d1d5db) is consistent and deliberate.
5. **Match the existing prose register.** Short, terse, imperative. Lower-case stage labels (`retry INTERPRET` not `Retry Interpret`). Monospace for code symbols (`_canary`, `CANARY_LEAK`, `interpret_node`).
6. **Don't redate anything except the header's own "last updated" field.** The Critic-rule examples have historical copy; leave them alone.
7. **Preserve the `margin-left: auto` legend** on line 1584–1588. It's the shipped/in-progress/planned legend; don't break it.

---

## Don't-touch zones

- All lines outside the ranges listed in "Edits required" above.
- The entire `<style>` block (lines 1–~1560 — CSS definitions).
- The Critic rule-list items R_01 through R_13 (historical content with working examples).
- The integrity-ledger section (lines 2053+) — that's Slice 6 territory.
- Any JavaScript (there shouldn't be any beyond Google Fonts link).

---

## Acceptance criteria

- [ ] The 3 `wip` chips listed in Edit 2 are now `live`.
- [ ] A new `canary tripwire` chip exists, class `live`, positioned after `evidence splitter`.
- [ ] The "Evidence splitter" pillar body now names the canary tripwire as defender-AI integrity counterpart.
- [ ] Visually opening the HTML in a browser shows no broken layout (no overflow, no misaligned rows, no missing chips, no double-rendered content).
- [ ] `git diff docs/planning/architecture.html` is surgical — additions only, no whitespace reflow, no re-indentation of unrelated blocks.
- [ ] No new CSS classes were introduced. Run: `diff <(grep -oE 'class="[^"]*"' docs/planning/architecture.html | sort -u)` before and after; only existing classes appear.
- [ ] The four-pillar symmetry is preserved (no fifth `<h3>` pillar added).

---

## Where to look for extra context (read-only, don't edit)

- **What the canary does end-to-end:** `experiments/slice-2-notebook/pipeline/nodes.py` — search for `_check_canary_leak` and `Canary tripwire`.
- **The prompt instruction:** same file, `INTERPRET_SYSTEM_PROMPT`, `## Canary tripwire (pipeline integrity — read first)` section.
- **Plain-English explanation:** `docs/planning/architecture.md` — the component-map row for "Canary tripwire (defender-AI integrity)" and the threat-boundary row for "Adversarial manipulation of the defender LLM itself".
- **Deep explanation:** `docs/planning/architecture-detailed.md` §3a (defender-AI integrity threat) + §4 step 10 (data-flow canary check) + §5 (`canary` field in PipelineState schema).
- **Demo narrative:** *"our pipeline detects when an attacker tries to manipulate our defender AI — the prompt-injection attempt itself becomes a high-confidence forensic finding."*

---

## If anything seems unclear

**Stop. Flag it. Don't guess.** This file is a judge-facing submission artifact. Unverified edits are more expensive than a 10-minute clarification round trip.

Rules from the user's global CLAUDE.md that apply to this task:
- Fail-fast verify before committing: visually open the HTML in a browser after edits; confirm no layout break, no missing chips, no overflow.
- Don't oversell: if Edit 3 or Edit 5 don't land cleanly, omit rather than wedge.
- Terse style: match the existing prose tone; no new jargon.
