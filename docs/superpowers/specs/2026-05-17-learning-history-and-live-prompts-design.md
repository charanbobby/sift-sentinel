# Learning history strip + live agent prompts panel

**Date:** 2026-05-17
**Status:** Draft, awaiting user review
**Surface:** Today's run dashboard at `experiments/slice-2-notebook/site/dashboard.html`, served by `experiments/slice-2-notebook/pipeline/site.py`

## Why

Today's dashboard surfaces the rule approval queue but loses every trace once a rule is approved or rejected. The user has three open questions that this surface does not answer:

1. **Wiring check.** When I click Approve, does that rule actually land in the agent's system prompt at runtime? We have never visually confirmed it.
2. **History scan.** What have I approved and rejected over the past few runs? Right now the cards just vanish.
3. **Trend signal.** Even with limited data, is the agent's HIT rate moving as I tune the rule store?

Audit data already exists for all three asks; we just have not been reading it back.

## Non-goals

- No per-approval verification flow ("did the rule fire on the very next run"). The user is not interested in immediate confirmation; the once-after-approval scan is enough.
- No behavioral replay. We do not re-run the historical miss against the new rule to prove it would have caught the original artifact. That belongs in a future regression-gate iteration, not in the dashboard.
- No charting library. Trend is a one-line text statement above the strip.
- No write actions in the new surface. Both endpoints are read-only.

## Data sources (all on disk today)

| Path | Used for |
|---|---|
| `LOOP_RUNS_DIR/{date}/score_{date}.json` | HIT / MISS / PARTIAL totals per date for the strip |
| `LOOP_RUNS_DIR/promotions.audit.jsonl` | per-day promoted / rejected counts and timestamps |
| `LOOP_RUNS_DIR/{date}/learned_rules.staged.jsonl` | original `rule_text` + `rule_kind` for any rule_id referenced in the audit log |
| `LOOP_RUNS_DIR/{date}/learned_rules.rejected.jsonl` | reject reasons + timestamps for fallback when audit log is missing |
| `pipeline/learned_rules.jsonl` | live store, used by the live-prompts panel |
| `pipeline/nodes.py` (builder functions) | render the actual rendered INTERPRET / EXTRACT / PLAN prompts so the panel shows what the agent literally saw |

No new persistent state is introduced.

## Backend

### New endpoint: `GET /api/history`

Returns the last N (default 14, override with `?limit=`) dated loop-runs, newest first.

Response shape:

```json
{
  "runs": [
    {
      "date": "2026-05-09",
      "score": { "hit": 14, "miss": 6, "partial": 0, "total": 20 },
      "promoted": [
        {
          "rule_id": "akira_credential_enumeration_task-5e142c7bd2",
          "rule_kind": "counter_rule",
          "rule_text": "Scheduled tasks executing credential-extraction utilities...",
          "promoted_at": "2026-05-03T11:55:22+00:00"
        }
      ],
      "rejected": [
        {
          "rule_id": "wmi_credential_enum_task-070502cacf",
          "rule_kind": "planner_hint",
          "rule_text": "Extract Windows scheduled task XML from C:\\Windows\\System32\\Tasks\\...",
          "reason": "duplicates existing scheduled-task planner guidance",
          "rejected_at": "2026-05-09T18:02:10+00:00"
        }
      ],
      "pending_count": 1
    }
  ],
  "trend": {
    "hit_rate_last_7": 0.68,
    "delta_vs_prior_7": 0.12,
    "has_enough_data": true
  }
}
```

Implementation notes:

- Walks `LOOP_RUNS_DIR` newest-first, filters for `\d{4}-\d{2}-\d{2}$` dirs, takes up to `limit` (default 14).
- For each date, reads `score_{date}.json` for the HIT / MISS counts. Missing file is allowed; score becomes `null` and the card shows "no scoring on this date".
- Joins `promotions.audit.jsonl` filtered by `date` field to produce the `promoted` and `rejected` lists. Each entry's `rule_text` and `rule_kind` come from joining against `learned_rules.staged.jsonl` for that date.
- If audit log is missing entirely, returns empty `promoted` and `rejected` lists for every date. (Spec originally called for a disk-scan fallback; the implementation simplified this to empty lists. Pre-audit-log historical dates will show "+0 -0" on their card. Track in follow-up if backfill becomes important.)
- `pending_count` uses the same dedup-against-live logic that `/api/proposed-rules/dates` already uses (kind + normalized text).
- `trend.has_enough_data` is false when fewer than 5 dated runs exist; UI uses this to suppress the trend line.
- Trend rate is computed as `HIT / (HIT + MISS)`, not `HIT / total`. PARTIAL is informational and not counted in the denominator. (Spec originally said only "HIT rate"; implementation chose HIT+MISS so PARTIAL credit does not depress the rate.)

### New endpoint: `GET /api/live-prompts`

Returns the three currently-rendered system prompts with the promoted-rules block surfaced separately so the UI can highlight it.

Probe of `pipeline/nodes.py` confirms the existing pattern: `_load_learned_rules()` returns a dict keyed by `rule_kind`, and `_format_learned_rules_block(rules, header)` produces the appendable block. The three call sites are:
- INTERPRET: spliced into `INTERPRET_SYSTEM_PROMPT` at the message-build site (around line 2219).
- EXTRACT: spliced inside `_build_extract_prompt(host_type, host_description, has_memory, has_disk)` at line ~1125.
- PLAN: spliced inside `_plan_system_prompt(...)` at line ~534.

PLAN and EXTRACT take per-request arguments (host type, available tools). The panel does not have a real case to render against, so it renders both with canonical defaults: `host_type="windows-workstation"`, `host_description="<canonical workstation>"`, `has_memory=True`, `has_disk=True` and an equivalent canonical context for PLAN. A banner in each tab states "Rendered with canonical host args for display; the rules-block is identical to what the agent sees at runtime."

Response shape:

```json
{
  "prompts": [
    {
      "agent": "INTERPRET",
      "rendered_with": { "context": "verbatim, no args needed" },
      "base_text": "You are a DFIR analyst...",
      "appended_block": "\n\n## Counter-rules (auto-generated, see pipeline/learned_rules.jsonl)\n- Scheduled tasks executing credential-extraction utilities...",
      "appended_rules": [
        {
          "rule_id": "akira_credential_enumeration_task-5e142c7bd2",
          "rule_text": "Scheduled tasks executing credential-extraction utilities...",
          "promoted_at": "2026-05-03T11:55:22+00:00",
          "source_date": "2026-05-02"
        }
      ]
    },
    {
      "agent": "EXTRACT",
      "rendered_with": { "host_type": "windows-workstation", "has_memory": true, "has_disk": true },
      "base_text": "...",
      "appended_block": "...",
      "appended_rules": [...]
    },
    {
      "agent": "PLAN",
      "rendered_with": { "context": "canonical defaults" },
      "base_text": "...",
      "appended_block": "...",
      "appended_rules": [...]
    }
  ]
}
```

Implementation notes:

- Imports `_load_learned_rules`, `_format_learned_rules_block`, `INTERPRET_SYSTEM_PROMPT`, `_build_extract_prompt`, and `_plan_system_prompt` directly from `pipeline.nodes`. No refactor required; the helpers exist as importable callables today.
- For each agent, `base_text` is the prompt with the rules block stripped; `appended_block` is what the rules-block helper produced for that rule_kind. UI shows them concatenated with the appended block tinted.
- `appended_rules` enumerates the rules in order so the UI can render per-rule chips alongside the block.
- Builder import or call failure returns HTTP 500 with the error message in the body. UI shows "Could not render live prompts: <error>" with a copy button.

## UI

Two new pieces on `dashboard.html`, grouped under a new section header titled **"What sentinel has learned"**, placed directly below the existing "Drafted rules awaiting review" section.

### Piece A: "View live agent prompts" button

- Single button at the top of the new section.
- Click opens a modal with three tabs: INTERPRET, EXTRACT, PLAN.
- Each tab renders `base_text` + `appended_block` as a single monospace block; the appended block has a soft tinted background.
- Above the prompt, a small caption shows the `rendered_with` args for that agent (e.g. "Rendered with host_type=windows-workstation, has_memory=true, has_disk=true") so the user knows EXTRACT and PLAN were rendered with canonical defaults, not a real case.
- Per-rule chips above the prompt list each rule_id + source date in the order they appear in `appended_block`. Clicking a chip scrolls the prompt to the matching line.
- If `appended_rules` is empty for an agent, the tab shows the base prompt with the caption "No promoted rules of this kind yet; this is the base prompt the agent uses."
- Read-only. No remove or edit affordance in v1. If the user needs to remove a promoted rule, they edit `pipeline/learned_rules.jsonl` manually and redeploy.

### Piece B: "Learning history" strip

- Caption: "Each card is one nightly loop-run. Numbers show how well sentinel scored on the day's planted artifacts and what rules you promoted or rejected on that date."
- One-line trend note above the strip when `trend.has_enough_data` is true: e.g. "HIT rate up 12 points vs the prior week" (positive) or "HIT rate flat vs the prior week" (zero / negative). Suppressed when false.
- Horizontal strip of cards, newest left, horizontal scroll when width is tight. Default render shows up to 14 cards.

Per-card layout:

```
+----------------+
| 2026-05-09     |   <- date header
| HIT 14/20      |   <- color: green >=70%, amber 40-70, red <40
| +0 -2 promoted |   <- chips: +N promoted, -M rejected
| pend 1         |   <- only when pending_count > 0
| [view v]       |   <- expander
+----------------+
```

Expander body:

- Promoted rules: green left-border, rule_kind chip, rule_text, footer caption "landed in INTERPRET prompt" / "EXTRACT catalog" / "PLAN soft rules" derived from rule_kind.
- Rejected rules: muted left-border, rule_kind chip, rule_text, reason on a second line.

Empty states:

- Zero loop-runs: the whole "What sentinel has learned" section is hidden so the dashboard does not render an empty panel.
- Fewer than 5 loop-runs: strip renders, trend note replaced by "Not enough runs yet to show a trend."

## Edge cases

| Situation | Behavior |
|---|---|
| `score_{date}.json` missing | Card renders with "no scoring on this date" instead of HIT/N; promo and reject chips still render |
| Audit row references a rotated staged file | Rule row shows `rule_id` plus "(rule text no longer on disk)" in muted text; row is not dropped |
| `promotions.audit.jsonl` missing | Endpoint falls back to scanning rejected.jsonl + diffing staged vs live; timestamps lost, counts preserved |
| Prompt builder import failure | `/api/live-prompts` returns 500 with import error; UI shows "Could not render live prompts: <error>" with copy button |
| Fewer than 5 dated runs | Trend note replaced with "Not enough runs yet to show a trend" |
| Zero dated runs | Section hidden entirely |
| Unknown `rule_kind` in live store | `/api/live-prompts` skips it with a warning to stderr; rule does not appear in any tab |

## Testing

- Unit tests for `/api/history` against a temp `LOOP_RUNS_DIR` covering: full score + audit; missing score file; missing staged file (rotated); fewer than 5 dates; zero dates. One test asserts trend math on 8 dates.
- Unit tests for `/api/live-prompts` against a temp `learned_rules.jsonl` covering: zero promoted rules of any kind; one of each kind; an unknown `rule_kind` (skipped with warning).
- One smoke test that hits both endpoints on the running container and asserts response shape and HTTP 200.
- No automated browser test. The user walks through it once manually on `sentinel.sshub.dev` after deploy. The strip is presentational and stable enough that visual regression is not worth the maintenance.

## Files touched

- `experiments/slice-2-notebook/pipeline/site.py` adds `/api/history` and `/api/live-prompts`.
- `experiments/slice-2-notebook/pipeline/nodes.py` no refactor required; the existing `_load_learned_rules`, `_format_learned_rules_block`, `INTERPRET_SYSTEM_PROMPT`, `_build_extract_prompt`, and `_plan_system_prompt` are already importable.
- `experiments/slice-2-notebook/site/dashboard.html` adds the new section, the live-prompts modal, and the history strip. Pure additions; no removals.
- `experiments/slice-2-notebook/tests/test_site_history.py` new file for the endpoint unit tests.
- `experiments/slice-2-notebook/tests/test_site_live_prompts.py` new file for the live-prompts endpoint unit tests.

## Open questions

None at design time. Implementation will surface naming questions for the new helper functions in `nodes.py`, which can be resolved during the plan phase.
