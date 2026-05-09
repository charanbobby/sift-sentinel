# Tracks registry

Single page of every active track. Updated on every significant event by Claude. Query "status of <track-name>" to get the 5 lines from that track's section instead of a full recap.

## Conventions

- One section per active track, headed by `## <short-name>`.
- Each track lists: branch, goal, state, waiting on, last update timestamp.
- Branch name is `track/<short-name>` for new tracks. Tracks that started on `main` before this convention say `Branch: main`.
- When a track is DONE: move its section to the bottom under `# Closed tracks`.

---

# Active tracks

## ui-redesign

- **Branch:** main (started before the branch convention; remaining tasks stay on main)
- **Goal:** Replace `experiments/slice-2-notebook/site/dashboard.html` with a 4-widget status board plus a drafted-rules section that lets the user approve or reject staged learned rules from the website without CLI commands. Spec at `docs/superpowers/specs/2026-05-09-todays-run-redesign-design.md`. Plan at `docs/superpowers/plans/2026-05-09-todays-run-redesign.md`.
- **State:** implementing under subagent-driven-development. Task 1 of 8 done (commit `fa6d072`: failing test for `/api/proposed-rules`). Spec compliance review and code quality review queued for Task 1.
- **Waiting on:** nothing (auto mode running).
- **Last update:** 2026-05-09 (right after Task 1 completed).

## memory-sweep

- **Branch:** main
- **Goal:** Complete dataset coverage on `sentinel.sshub.dev/viewer/`. Every host in `docs/reference/hackathon/dataset_manifest.md` should have at least one curated run.
- **State:** 7 memory-only pipeline runs in flight in parallel (file, rd-02, wkstn-01, dc, mail, hunt, sp). Adjudication agent already landed 8 APPROVED + 4 REJECTED for the existing uncurated runs. keep_runs.json now has 32 entries.
- **Waiting on:** 7 background bash IDs to finish. ETAs 5 to 60 min each; mail (18 GB memory) likely the longest.
- **Last update:** 2026-05-09 (after the 7 runs were launched).

---

# Backlog (named tracks not yet started)

## critic-r14-attck-emit

- **Branch:** track/critic-r14-attck-emit (will create when started)
- **Goal:** Fix the `INJ_ATTCK_EMIT` injection-scanner false positive that triggers on raw regf binary bytes matching `t\d{4}` substrings. Two QUARANTINED terminals on the SRL-2015 sweep were caused by this single false-positive class.
- **State:** not started. Refinement option in `docs/submission/adjudication-srl-2015-bulk-2026-05-09.md`.

## planner-os-drift

- **Branch:** track/planner-os-drift (will create when started)
- **Goal:** Add OS-version-aware path branching to PLAN so XP gets `Documents and Settings\Administrator` and `WINDOWS\Tasks` while Win7+ gets `Users\Administrator` and `System32\Tasks`. Caught on the SRL-2015 XP run, recovered via Run-key check.
- **State:** not started.

## daily-telegram-notification

- **Branch:** track/daily-telegram-notification (will create when started)
- **Goal:** Implement the daily Telegram notification design at `docs/runbooks/daily-cron-notification-design.md`. Trigger after the 22:30 UTC cron, payload = run status + finding counts + top-5 by severity + deep links to sentinel.sshub.dev.
- **State:** designed, not implemented.

## threat-intel-feedback-loop

- **Branch:** track/threat-intel-feedback-loop (will create when started)
- **Goal:** Implement the threat-intel feedback loop design at `docs/runbooks/sentinel-threat-intel-feedback-loop.md`. MVP = daily CISA KEV summary attached to the Telegram message; later add a `/proposed-rules` web page (now being built under ui-redesign) and the per-rule approve flow.
- **State:** designed, partially overlaps with `ui-redesign`. Reassess after `ui-redesign` ships.

## drafter-rejection-feedback

- **Branch:** track/drafter-rejection-feedback (will create when started)
- **Goal:** Update `scripts/learn_from_misses.py` so the daily drafter reads `learned_rules.rejected.jsonl` and skips drafting another rule for the same `source_miss_id`, plus passes the rejection reason to Haiku as a "do not draft like this" signal. Out of scope for the `ui-redesign` spec, but the rejection file format is locked there as the contract.
- **State:** not started; depends on `ui-redesign` Task 3 (the `/api/reject-rule` endpoint that creates the file).

---

# Closed tracks

(none yet)
