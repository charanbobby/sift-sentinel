# Sentinel Threat-Intel Feedback Loop (Design)

**Status:** DESIGN ONLY. No code yet. Charan reviews and approves before any commit.

**TL;DR:** New public threat intel (CISA KEV, MITRE ATT&CK updates, abuse.ch IOC drops, vendor advisories) is already being implicitly consumed by `research.py` and the daily synthetic manifest. We extend that with an explicit "propose-then-review" loop: a sidecar fetches public RSS/JSON feeds daily, drafts a markdown summary plus a candidate Critic rule per new IOC family, and surfaces the proposals on a new `/proposed-rules` page on `sentinel.sshub.dev` with Approve/Reject buttons. Approval writes the rule into `pipeline/learned_rules.jsonl` via a GitHub branch + PR that Charan merges manually. **MVP = ingest CISA RSS, draft prose summary, ping Telegram, human edits the rule by hand.** Auto-rule-PR-bot is a follow-up.

---

## What is already partly built

- `experiments/synthetic-ai-workstation/research.py` calls Claude Code with WebSearch/WebFetch to ground the daily manifest in current intel. It is producing real signal: the 2026-05-08 manifest cited Rapid7, GitGuardian, StepSecurity, THN, CISA KEV, Ciphers Security, and CISA AA24-190A. So we already have an upstream that finds new TTPs.
- The Phase G' pipeline (`scripts/learn_from_misses.py` + `scripts/cron_phase_g_hook.sh`) already drafts candidate rules from misses, lints + dedupes, and writes a `learned_rules.proposed.md` sidecar. As of 2026-05-08 it produced 12 staged rules (counter_rule, planner_hint, extract_location), all dedupe-clean against a live store of 2 promoted rules.
- Promotion is the gap. There is currently no UI; promotion is a CLI command (`scripts/regression_gate.py --mode promote --promote-id <id>`).

We close the gap with a review surface, not a new ingest pipeline.

## The full loop (target end state)

```
   Public threat intel feeds (RSS/JSON)
            │
            ▼
   Sidecar: fetch + classify (CISA KEV, MITRE, abuse.ch, vendor advisories)
            │
            ▼  staged proposals: rule diff + provenance + IOC text
   Daily cron: research.py + Phase G'  (existing)
            │
            ▼
   /proposed-rules page on sentinel.sshub.dev
   ─────────────────────────────────────────
   - 12 pending diffs, severity, provenance citation
   - Approve / Reject buttons
            │
   ┌────────┴────────┐
   ▼                 ▼
 Approve            Reject
   │                 │
   ▼                 ▼
 Branch + PR    Drop, log to ledger
 charan merges
   │
   ▼
 pipeline/learned_rules.jsonl (live)
   │
   ▼
 Next cron cycle picks it up automatically
```

The whole loop converges on `learned_rules.jsonl` on `main`, which the VPS pulls during the cron's `git pull --ff-only`. No second source of truth.

## What "Sentinel proposes" means

Two paths feeding the same review surface:

### Path A (already shipping): Phase G' miss-driven proposals

Today's `learned_rules.staged.jsonl` per cron run already contains 1-3 candidate rules per missed artifact. We just need to surface them.

### Path B (new sidecar): feed-driven proposals

A small daily script that runs **before** the cron (e.g. 22:00 UTC) and writes its proposals into the same staged file format Phase G' produces. Sources:

- **CISA KEV (free, JSON):** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. New CVE rows since the previous fetch become candidate `extract_location` or `counter_rule` proposals (e.g. SimpleHelp KEV in the 2026-05-08 manifest).
- **CISA cyber advisories (free, RSS):** `https://www.cisa.gov/cybersecurity-advisories/all.xml`. New advisories become prose summaries the human reads, not auto-rules.
- **MITRE ATT&CK STIX bundle (free, JSON):** GitHub `mitre-attack/attack-stix-data`. Diff against last fetch to find new sub-techniques and procedure examples.
- **abuse.ch URLhaus (free, JSON):** `https://urlhaus.abuse.ch/downloads/json_recent/`. New malware-hosting URL families. Useful when the pipeline flags a URL we have no rule for.
- **abuse.ch ThreatFox (free, JSON):** `https://threatfox.abuse.ch/export/json/recent/`. Fresh IOCs by malware family.

All free, all non-paid. No commercial feeds.

Output of the sidecar is a `proposals/<date>.staged.jsonl` file in the same schema Phase G' uses, so the review surface only needs to know one format.

## Surface: `/proposed-rules` page

Add to the existing FastAPI site at `experiments/slice-2-notebook/pipeline/site.py`:

- `GET /api/proposed-rules` returns a JSON list of pending proposals, each with: `id`, `kind` (counter_rule/planner_hint/extract_location), `summary`, `provenance` (URL + date), `staged_path`, `source` (phase_g_misses or feed_<name>), `created_at`.
- `GET /proposed-rules/` returns an HTML page with a card per proposal: rule body, provenance link, two buttons (Approve / Reject).
- `POST /api/proposed-rules/{id}/approve` writes the rule into a new branch on the repo (`learned-rule/<id>`), commits, and pushes to GitHub via the deploy key already on the VPS. Returns the PR URL.
- `POST /api/proposed-rules/{id}/reject` removes the entry from the staged file and appends a one-line note to a `proposals/rejected.log`.

The Approve action must be **gated**. Either:

1. A shared bearer token in the `Authorization` header (Charan stores it locally, sets it via a browser-extension), OR
2. Behind nginx basic auth (one extra location block with `auth_basic`).

We default to (2) because nginx already terminates TLS for the site.

## Honest constraints

- This is BIG scope. The full loop touches: a new sidecar fetcher, the site UI, a write path to GitHub from the VPS, schema design for the staged file, an audit log, and a security boundary on the Approve endpoint.
- Phase G' already drafts plausible rules. The bottleneck is **review**, not generation. So MVP-first means: ship the review surface; postpone the auto-PR-bot.
- The pipeline is already costing tokens daily for `research.py` (Claude Code, Max plan = $0 to user) and per-run for the Sonnet pipeline calls. Adding a daily ingest sidecar **must** stay LLM-free or use Haiku with prompt caching, never Sonnet. CLAUDE.md "Print pricing" rule applies.
- Telegram is the cheapest review surface (one button-tap to approve via inline keyboard). The web UI can come later.

## MVP scope (build now)

In this order, smallest first:

1. **Daily prose summary, no rules yet.** A Python script (`scripts/intel_daily_summary.py`) fetches CISA KEV + CISA advisories diff since yesterday, writes a markdown summary to `out/loop-runs/<date>/intel_summary.md`, and the daily Telegram message (see `daily-cron-notification-design.md`) appends a 3-line teaser plus a link to the file in the viewer. **Cost: zero LLM calls; pure RSS/JSON parse.**
2. **Surface staged rules in the existing site.** Add a "Proposed rules" panel on the `sentinel.sshub.dev` landing page that lists today's `learned_rules.staged.jsonl` rows with provenance. Read-only. No buttons.
3. **Telegram inline-keyboard approve.** When the daily notification fires, include one "approve all sane proposals" callback button per category. The handler appends approved IDs to `out/loop-runs/<date>/approvals.log`. Charan still runs `regression_gate.py --mode promote` by hand the next morning.
4. **Web Approve/Reject buttons (later).** Once steps 1-3 prove out, add the `/proposed-rules` page with the GitHub-PR write path. Authenticated via nginx basic auth.

Each MVP step is independently shippable; we should not bundle them into one PR.

## Out of scope (write this clearly)

- **No auto-merging of proposed rules.** Approval creates a PR; Charan merges manually. This stays true even after step 4.
- **No paid feeds.** No Recorded Future, no Mandiant Advantage, no Mandiant tactics, no Crowdstrike Falcon X.
- **No sub-second freshness.** Daily fetch is enough. We are not building a SOC.
- **No rule generation from raw advisory prose via Sonnet.** That is research.py's job and runs once per day already; we do not duplicate it.
- **No write access from the site to anywhere except a local staged file and a GitHub branch.** The site never edits `pipeline/learned_rules.jsonl` directly.
- **No replacement of `regression_gate.py`.** That CLI stays the only path that mutates the live store. The web UI just enqueues PRs that, when merged, deliver the same effect.

## Risks

- **Feed-fetcher hangs a long time.** Mitigation: 10s timeout per feed, 60s overall.
- **CISA KEV adds 30 entries on a single day** (it has happened). Mitigation: cap to top 10 by CVSS in the Telegram teaser; the full diff lives in the markdown file.
- **Charan misses a day.** Mitigation: the `intel_summary.md` is dated and persistent; nothing is auto-deleted. Catch-up on Saturday is fine.
- **Bad rule passes review.** Mitigation: regression_gate.py runs the lint+dedup AND (when wired) the regression-replay gate before promotion.

## Files to add (when MVP is approved)

- `scripts/intel_daily_summary.py` (new)
- `scripts/notify_daily_render.py` extended with intel section (see notification design)
- `experiments/slice-2-notebook/pipeline/site.py` extended with `/api/proposed-rules` + landing-page panel (read-only first)
- No changes to `pipeline/learned_rules.jsonl` directly. Promotion stays via `regression_gate.py`.
