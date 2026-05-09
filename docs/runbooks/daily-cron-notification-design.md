# Daily Cron Notification (Design)

**Status:** DESIGN ONLY. No code yet. Charan reviews and approves before any commit.

**TL;DR:** After the 22:30 UTC cron loop finishes on the VPS, send Charan one Telegram message summarizing the run: terminal status, finding counts, the top 5 findings by severity, the count of staged learned-rule proposals, and a deep link to `sentinel.sshub.dev`. One message per day, suppressed on hard failure (with a separate failure ping). Implemented as a small bash script invoked from the existing `cron_phase_g_hook.sh` post-step. No changes to the pipeline, no LLM calls, no extra cost.

---

## Why we need this

The cron has been running clean for a week (last 4 cycles produced fresh manifests + REPORT.md + staged rules). Charan has zero visibility unless he SSHs in or refreshes `sentinel.sshub.dev`. The intelligence the loop is generating (CISA KEV coverage, fresh APT TTPs, new supply-chain artifacts) is silently piling up. We need a once-a-day push so that:

1. Charan knows whether the cron ran.
2. Charan can see at a glance whether anything new and interesting landed.
3. The link in the message lands him on the run page that needs review.

## Trigger

End of the cron run, after Phase G' (`learn from misses`) writes `learned_rules.proposed.md`.

Concretely: append a `phase_h_notify` step inside `experiments/synthetic-ai-workstation/run_loop.py` that fires after `phase_learn_from_misses` returns, **inside** the same `try` block. Soft-fails like Phase G' (a notification glitch must never block cleanup).

Alternative trigger location (simpler, no Python edit): add a final line to `scripts/cron_phase_g_hook.sh` that invokes `scripts/notify_daily.sh "$RUN_DIR"`. We prefer this for the MVP because the hook already has the run dir in scope and we keep the notification a separate concern.

## Channel

**Primary: Telegram bot.**

- Charan already uses Telegram for the Stop-hook (`feedback_telegram_hook_question_detection.md`).
- The bot can be a fresh project-specific bot (`@findevil_sentinel_bot` or similar) or reuse the existing one if Charan is fine with it.
- Secrets land in `/opt/find-evil/.env.notify` on the VPS, mode `0600`, owner `sri`. Two vars: `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`. Never committed to git.

**Fallback: email via `mail`/`sendmail`.** Simpler if the Telegram bot setup proves annoying; the same payload renders fine as plain text. Default to Telegram unless Charan opts out.

**Not a webhook to Discord/Slack.** Charan does not run those for this project.

## Payload

Plain text, Markdown-light (Telegram supports it). Single message, target ~1500 chars.

```
Sentinel daily, 2026-05-08 22:51 UTC

Cron status: PASS (1287s)
Regression: 2/2 baseline re-detected
Extension:  6/13 fresh artifacts detected (1 bonus)
Findings:   10 (terminal: HUMAN_REVIEW)
  - high:    8
  - medium:  2

Top 5 by severity:
  1. [high] registry_run_key   mshta.exe https://cdn-assets.example.invalid/...
  2. [high] registry_run_key   C:\ProgramData\OneDriveService\sync_agent.exe
  3. [high] registry_run_key   powershell -Command Set-MpPreference -DisableRealtimeMonitoring
  4. [high] service            C:\ProgramData\RDPTools\tunnel_mgr.exe
  5. [high] service            %COMSPEC% /c echo b6a1458f396 > \\.\pipe\334485

Staged learned-rule proposals: 12
  Categories: counter_rule (8), extract_location (3), planner_hint (2)

Review:
  - Site:     https://sentinel.sshub.dev/?date=2026-05-08
  - Run:      https://sentinel.sshub.dev/viewer/?case=synthetic-2026-05-08
  - Proposed: https://sentinel.sshub.dev/proposed-rules/?date=2026-05-08
```

The deep links assume the site router accepts `?date=` and `?case=` query params (the case viewer already does; `?date=` and `/proposed-rules/` are upcoming work tracked in the feedback-loop design doc).

If the cron failed (any non-zero exit before the score step), send a **smaller** failure message instead:

```
Sentinel daily, 2026-05-08 22:51 UTC

Cron status: FAIL at phase_e_pipeline (exit 3)
Last 20 log lines:
  ...
Tail: ssh sri@46.62.255.66 'tail -200 /opt/find-evil/out/loop-runs/cron-2026-05-08T22-30-01Z.log'
```

## Frequency and de-duplication

- One message per cron cycle. The cron fires once at 22:30 UTC and the script invokes the notify hook exactly once at the end.
- If two cron invocations collide (the `flock` already prevents this for the loop itself), the second one writes to `skipped.log` and never reaches the notify step, so no double ping.
- If `phase_h_notify` fails inside Python (network glitch, bot rate-limit), it logs and exits 0. Missing one day's ping is fine; the user can SSH in. Do not retry on failure.

## Suppression rules

- Suppress on hard FAIL when no `score_<date>.json` exists (we have nothing useful to summarize).
- Suppress when `skipped.log` was written for "today already has REPORT.md" (idempotent re-fire after a successful day).
- Send the FAIL variant on any other non-zero exit before the score step, so Charan knows the cron broke.

## Implementation sketch

`scripts/notify_daily.sh`:

```bash
#!/usr/bin/env bash
# Reads <run_dir>/score_<date>.json, <run_dir>/REPORT.md, and the day's
# pipeline findings.json; renders a Telegram message; POSTs to bot API.
# Soft-fails on any error.
set -uo pipefail
RUN_DIR="${1:-}"
[ -d "$RUN_DIR" ] || { echo "no run dir"; exit 0; }
. /opt/find-evil/.env.notify || { echo "no env"; exit 0; }
PAYLOAD=$(python3 /opt/find-evil/repo/scripts/notify_daily_render.py "$RUN_DIR") || { echo "render failed"; exit 0; }
curl -s --max-time 10 -X POST \
  "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
  -d "chat_id=${TELEGRAM_CHAT_ID}" \
  -d "parse_mode=Markdown" \
  --data-urlencode "text=${PAYLOAD}" > /dev/null
```

`scripts/notify_daily_render.py`: a ~150-line Python file that loads `score_<date>.json`, the day's `findings.json`, and `learned_rules.proposed.md`; returns the formatted body to stdout. No external deps beyond `json` and `pathlib`.

Wire it in by adding one line at the end of `cron_phase_g_hook.sh`:

```bash
bash "$REPO_ROOT/scripts/notify_daily.sh" "$RUN_DIR" || true
```

## Test plan (before enabling)

1. Build the renderer locally against `/opt/find-evil/out/loop-runs/2026-05-08/` (rsync to local, run renderer, eyeball the output).
2. Set up the bot, save creds in `/opt/find-evil/.env.notify` on the VPS.
3. Probe end-to-end: SSH to VPS, `bash /opt/find-evil/repo/scripts/notify_daily.sh /opt/find-evil/out/loop-runs/2026-05-08/`. Charan confirms the message arrives.
4. Wire into `cron_phase_g_hook.sh`, push, wait one cron cycle, observe.

## Out of scope

- Real-time alerting on individual findings during the run. The loop is short (~20 min); end-of-run is enough.
- Multi-recipient. One chat ID is enough for now.
- HTML email styling. Plain text is fine.
- Two-way Telegram bot interactions. The MVP is one-way push; the feedback loop (approve/reject) is the separate `sentinel-threat-intel-feedback-loop.md` design.
