---
created: 2026-05-09
status: approved
audience: hackathon judge skimming the demo (primary), project owner (secondary)
target_url: https://sentinel.sshub.dev/site/dashboard.html
replaces: experiments/slice-2-notebook/site/dashboard.html (current "Today's run")
---

# Today's run page: from-scratch redesign

## TL;DR

Replace the current 7-section dashboard at `/site/dashboard.html` with a 4-widget status board that tells one story: the self-correction loop is alive. Hero one-liner up top, 4 at-a-glance widgets (today's input, today's result, queued for you, live agent), and a single content section below that lists every drafted rule with full text, a plain-English "what this changes" caption, and inline approve / reject controls. The user pain point this fixes: today the user cannot understand the proposed rules markdown file or how to approve a rule, so the loop stalls at the human-review step.

## Goals

1. A judge skimming for 30 seconds learns: this agent runs, it misses, it learns, it gets better tomorrow.
2. A judge giving 60 more seconds can see today's intel sources, today's result, and a real promotion-ready rule with provenance.
3. The user (operator) can approve or reject a drafted rule from the website without pasting CLI commands.
4. The "queued for you" widget shows a non-zero number that drives the user back to the page.

## Non-goals (deferred to a follow-up spec)

- Drill-down pages for "today's input", "today's result", "live agent" widgets. The current click-target stays the existing `/site/architecture.html`, `/viewer/`, and `/api/learnings` endpoints. Lightweight drill-down pages can ship later if needed.
- A GitHub PR-based approval flow. Approve writes to the live store directly; rollback is a git revert. The PR-based flow may ship later as part of the threat-intel feedback-loop work.
- Past-runs navigation on the same page (yesterday, day-before). The existing `/viewer/` already lists past cases by date.
- Authentication on the approve/reject endpoints. Current site is public; promotion is reversible by editing `pipeline/learned_rules.jsonl` and committing. A real auth layer is a separate piece of work.

## Audience and headline

The page is a sales pitch to a hackathon judge first, an operator workbench second.

Hero one-liner: **"Last night, Sentinel ran. Tonight it gets better."** Sub-line: a single sentence summary of last night's run (sources read, patterns planted, caught vs missed, rules drafted, rules live). The headline is the project's identity per the brainstorming session: "self-correction loop, alive."

## Page structure

### 1. Top nav (unchanged)

The existing nav stays: Sift Sentinel | How it works | Today's run (active) | Past cases | For judges | UTC clock.

### 2. Hero

- 12-px uppercase label: `SELF-CORRECTION LOOP`.
- 22-px headline: `Last night, Sentinel ran. Tonight it gets better.`
- 13-px sub-line: a one-sentence narrative built from the cron output, e.g. "Read 8 sources of fresh intel. Planted 14 attacker patterns. Caught 8, missed 7. Drafted 12 rules from misses. 2 already live. Tomorrow's run picks them up automatically."
- The sub-line is server-rendered from `/api/status` + `/api/research`; if either endpoint returns no data, fall back to a static placeholder.

### 3. Four-widget status board

Four cards in a `1fr 1fr 1fr 1fr` grid. Each card has: small uppercase label, big number, one-line caption, optional second-line caption.

| Widget | Label | Number | Caption | Source |
|---|---|---|---|---|
| 1 | today's input | count of `intel_sources` | "intel sources read" + N "patterns planted" | `/api/research` |
| 2 | today's result | "X / Y" (caught / missed) | "caught / missed" + accuracy percent | `/api/status.latest_cron.extension_pass` and `extension_miss` |
| 3 | queued for you | count of staged rules | "rules awaiting your call" + "scroll down to review" | new endpoint `/api/proposed-rules` (see "New endpoints" below) |
| 4 | live agent | count of promoted rules | "rules promoted" + "since YYYY-MM-DD" | `/api/learnings` (existing) |

Widget 3 ("queued for you") is visually distinguished: 1px purple border + a subtle 2px purple glow ring. It is the action item; the rest are status.

Click behavior on widgets 1, 2, 4: navigate to the existing pages noted in "Non-goals" above. Specifically:
- Widget 1 (today's input) currently has no dedicated page; click is a no-op or expands a `<details>` panel inline showing the raw `/api/research` JSON in a `<pre>` block. Pick the no-op for the first cut.
- Widget 2 (today's result) navigates to `/viewer/` with a query string `?date=YYYY-MM-DD` if the viewer supports it; otherwise no-op.
- Widget 4 (live agent) navigates to `/api/learnings` (the existing JSON view), or expands a `<details>` panel inline showing the rules in a readable format. Pick `<details>` inline for the first cut.

Widget 3 ("queued for you") scrolls smoothly to the drafted-rules section below.

### 4. Drafted rules section

Heading: `Drafted rules awaiting your call`. Sub-line: explains in one sentence that each rule was drafted by Haiku from a miss in last night's run; click approve to promote, reject to feed the drafter a reason.

For each rule, render a card with:

- **Kind badge** (top-left, color-coded):
  - `counter_rule` blue, sub-text "teaches INTERPRET to flag this TTP as malicious"
  - `extract_location` cyan, sub-text "tells EXTRACT to also scan this directory"
  - `planner_hint` amber, sub-text "teaches PLAN to enumerate this tool/arg combination"
- **Source-miss id** (top-right, monospace, muted): the `source_miss_id` field from the staged rule.
- **Rule text** (full text from `rule_text` field, no truncation).
- **Rationale** (full text from `rationale` field, in a left-bordered quote block, secondary text color).
- **Approve button** (green, primary).
- **Reject button** (red, secondary outline, label "Reject with reason").
- **Meta line** (bottom-right, muted): "drafted by `<generated_by_model>` at `<HH:MM>` UTC, from miss `<source_miss_id>`".

### 5. Approve interaction

Click "Approve" -> open a modal containing:

- Rule kind label.
- Full rule text.
- A 1-sentence summary of what this rule changes in the live agent (same plain-English caption as the badge sub-text).
- A "Confirm: promote this rule into the live agent" primary button.
- A "Cancel" secondary button.

Confirm: client POSTs `/api/promote-rule` with `{date: <date>, rule_id: <id>}`. Server:

1. Looks up the staged rule in `LOOP_RUNS_DIR/<date>/learned_rules.staged.jsonl`.
2. Runs `regression_gate.py --staged ... --live pipeline/learned_rules.jsonl --mode promote --promote-id <id>`. Capture stdout/stderr.
3. If exit 0: returns `{ok: true, promoted: <rule>}`.
4. If non-zero: returns `{ok: false, error: <stderr>}`.

On success, the client:

- Removes the rule card from the drafted-rules list.
- Decrements widget 3 count.
- Increments widget 4 count.
- Shows a toast: "Promoted: `<rule_id>`. Tomorrow's 22:30 UTC run picks it up."

On failure, the client shows the error in a small red banner above the rule card and leaves the card in place.

### 6. Reject interaction

Click "Reject with reason" -> the card expands inline to show:

- A small textarea labelled "Why are you rejecting this rule? (one sentence)".
- A "Submit rejection" primary button.
- A "Cancel" secondary button.

Submit: client POSTs `/api/reject-rule` with `{date: <date>, rule_id: <id>, reason: <text>}`. Server:

1. Appends the rejection to a new file at `LOOP_RUNS_DIR/<date>/learned_rules.rejected.jsonl`. Each line is `{rule_id, source_miss_id, rule_kind, reason, rejected_at, rejected_by: "site-user"}`.
2. Returns `{ok: true}`.

On success, the client removes the rule card from the list and decrements widget 3 count. The drafter (next cron's `learn_from_misses.py` run) is expected to read `learned_rules.rejected.jsonl` and:

- Skip drafting any new rule for the same `source_miss_id` if a rejection already exists for that miss.
- Pass the rejection reason to Haiku as a "do not draft like this" signal in the prompt.

The drafter integration is a small follow-up change to `scripts/learn_from_misses.py`; out of scope for this spec but the rejection file format is locked here so the drafter has a stable contract.

## Server endpoints (new + changed)

### New: `GET /api/proposed-rules?date=YYYY-MM-DD`

- If `date` omitted, defaults to the latest cron date (newest dated subdir under `LOOP_RUNS_DIR`).
- Reads `LOOP_RUNS_DIR/<date>/learned_rules.staged.jsonl`.
- Filters out rules whose ids appear in `LOOP_RUNS_DIR/<date>/learned_rules.rejected.jsonl`.
- Filters out rules whose ids already appear in the live `pipeline/learned_rules.jsonl` (already-promoted, idempotent).
- Returns `{date, count, rules: [...]}` where each rule is the full staged record (id, source_miss_id, rule_kind, rule_text, rationale, generated_by_model, generated_at).
- 404 if `date` directory does not exist.

### New: `POST /api/promote-rule`

- Body: `{date: YYYY-MM-DD, rule_id: string}`. Both required.
- Validates the rule_id exists in the staged file for that date.
- Calls `regression_gate.py --staged ... --live ... --mode promote --promote-id <id>` via `subprocess.run`. The script lives at `scripts/regression_gate.py`.
- Returns `{ok: true, promoted: <full rule record>, stdout: <captured>}` on exit 0.
- Returns `{ok: false, error: <stderr>}` with status 500 otherwise.
- Logs every promotion to a server-side append-only log at `LOOP_RUNS_DIR/promotions.audit.jsonl` with `{rule_id, date, promoted_at, source_ip}`. Source IP is the X-Forwarded-For header set by Cloudflare; falls back to direct remote_addr.

### New: `POST /api/reject-rule`

- Body: `{date, rule_id, reason}`. All required. Reason is trimmed to 500 characters.
- Appends to `LOOP_RUNS_DIR/<date>/learned_rules.rejected.jsonl`.
- Returns `{ok: true}` always (rejection is idempotent: a second rejection of the same rule_id overwrites the previous reason).
- Logs to `LOOP_RUNS_DIR/promotions.audit.jsonl` with action=reject.

### Changed: dashboard.html

- Drop the existing 7-section structure.
- Replace with hero + 4 widgets + drafted-rules section as specified.
- Drop the existing fetch logic for the old sections; add new fetch logic for `/api/proposed-rules`.
- Reuse the existing CSS variables and font stack. No new color palette.

## Data sources

- `LOOP_RUNS_DIR/<date>/learned_rules.staged.jsonl`: existing, written by the daily cron's Phase G.
- `LOOP_RUNS_DIR/<date>/learned_rules.rejected.jsonl`: NEW, written by `/api/reject-rule`.
- `LOOP_RUNS_DIR/promotions.audit.jsonl`: NEW, written by `/api/promote-rule` and `/api/reject-rule`.
- `pipeline/learned_rules.jsonl`: existing, the live store; appended to by `regression_gate.py`.

## Components and isolation

The redesign affects exactly two files:

- `experiments/slice-2-notebook/site/dashboard.html`: full rewrite of the body and inline JS. Top nav and CSS variables stay.
- `experiments/slice-2-notebook/pipeline/site.py`: three new endpoint handlers (`/api/proposed-rules`, `/api/promote-rule`, `/api/reject-rule`), plus a small helper `_run_promote_subprocess()` that wraps the regression_gate.py call.

No changes to `pipeline/nodes.py` (the live agent reads `learned_rules.jsonl` already; the promotion appends a line, no schema change). No changes to the cron loop. No changes to the viewer.

The drafter integration (read `learned_rules.rejected.jsonl` in the drafting prompt) is OUT of scope for this spec; it is a follow-up to `scripts/learn_from_misses.py` that consumes the contract this spec defines.

## Error handling

- `/api/proposed-rules` with a date dir that doesn't exist: 404 with `{detail: "no run for date <X>"}`.
- `/api/promote-rule` with an invalid rule_id: 400 with `{detail: "rule_id not in staged file for date <X>"}`.
- `/api/promote-rule` when `regression_gate.py` exits non-zero: 500 with the captured stderr in the body.
- `/api/reject-rule` with empty reason: 400. Reason is required and the field width is 500 chars max.
- Frontend: every fetch wraps in try/catch and renders a small red banner above the section if the fetch fails. The page never shows a blank screen.

## Testing

- Probe `/api/proposed-rules?date=2026-05-08` after deploy: expect 200, count=12 (all 12 currently staged for 2026-05-08).
- Probe `/api/promote-rule` with a known rule_id: expect ok=true, expect `pipeline/learned_rules.jsonl` to have one new line, expect a new entry in `promotions.audit.jsonl`.
- Probe `/api/reject-rule` with a reason: expect ok=true, expect `learned_rules.rejected.jsonl` to have a new line.
- Re-call `/api/proposed-rules?date=2026-05-08`: count should be 10 (12 minus 1 promoted minus 1 rejected). Idempotency check.
- Browser smoke: load the redesigned page, click approve on one card, confirm in modal, watch the card disappear and widget counts adjust. Click reject on another card, type a reason, watch the card disappear.

## Out of scope (already named above, repeated here for the spec's own audit trail)

- Drill-down pages for widgets 1, 2, 4.
- Authentication on the approve/reject endpoints.
- The drafter integration that reads `learned_rules.rejected.jsonl`.
- A GitHub PR-based promotion flow.
- Past-runs navigation on the same page.

## Open questions

None at this point. The brainstorming session settled the audience (judge skimming demo), the headline (self-correction loop, alive), the page shape (4 widgets), the below-fold content (drafted rules), the approve flow (confirm modal, immediate promotion), and the reject flow (reason text, fed back to drafter). All four answers are in the conversation log of session 2026-05-09.
