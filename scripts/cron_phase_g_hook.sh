#!/usr/bin/env bash
# Phase G: synthesise staged learning rules from the day's misses.
#
# Invoked by the daily cron after the score step writes
# `score_<date>.json`. Stages proposals to `<run_dir>/learned_rules.staged.jsonl`.
#
# DOES NOT auto-promote. Promotion into the live store
# (pipeline/learned_rules.jsonl) is a human-in-loop decision via
# `scripts/regression_gate.py --mode promote --promote-id <id>`.
# The live regression-replay gate (run pipeline against planted disk
# with/without rule, confirm catches miss + 0 new FP on baseline) is a
# follow-up; until it lands, lint+dedup is the only automated gate.
#
# Usage (cron-side):
#   bash scripts/cron_phase_g_hook.sh /opt/find-evil/out/loop-runs/2026-05-03
set -uo pipefail

RUN_DIR="${1:-}"
if [ -z "$RUN_DIR" ] || [ ! -d "$RUN_DIR" ]; then
  echo "FAIL: usage: cron_phase_g_hook.sh <run_dir>" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Synthesis (ALWAYS runs, even if score was perfect: learn-from-misses
# itself decides if there is anything to do).
STAGED="$RUN_DIR/learned_rules.staged.jsonl"
echo "[$(date -u +%FT%TZ)] Phase G: synthesising staged rules into $STAGED"
python3 "$REPO_ROOT/scripts/learn_from_misses.py" \
  --run-dir "$RUN_DIR" \
  --out-staged "$STAGED" \
  || { echo "  Phase G synthesis FAILED" >&2; exit 3; }

# Lint pass (always print so the day's REPORT.md can append it).
LIVE="$REPO_ROOT/experiments/slice-2-notebook/pipeline/learned_rules.jsonl"
echo
echo "[$(date -u +%FT%TZ)] Phase G: lint+dedup against live store $LIVE"
python3 "$REPO_ROOT/scripts/regression_gate.py" \
  --staged "$STAGED" \
  --live "$LIVE" \
  --mode lint \
  > "$RUN_DIR/learned_rules.lint.txt" \
  || true   # non-zero just means 0 survivors, not an error

# Write the lint summary as a sidecar file next to REPORT.md.
# REPORT.md is root-owned (Docker writes it) on the VPS, so direct append
# from the unprivileged cron user fails. Sidecar keeps the proposal visible
# in the same directory the human reviews each morning, without permission
# elevation. If/when score.py is changed to write REPORT.md as the cron
# user, this can be switched back to a direct append.
SIDECAR="$RUN_DIR/learned_rules.proposed.md"
if [ -s "$RUN_DIR/learned_rules.lint.txt" ]; then
  {
    echo "# Proposed learned rules ($(date -u +%F)) (Phase G, staged only; review before promotion)"
    echo
    echo '```'
    cat "$RUN_DIR/learned_rules.lint.txt"
    echo '```'
    echo
    echo "To promote a rule: \`bash scripts/regression_gate.py --staged $STAGED --mode promote --promote-id <id>\`"
  } > "$SIDECAR" \
    && echo "  proposals written to $SIDECAR" \
    || echo "  WARN: failed to write $SIDECAR" >&2
fi

echo
echo "[$(date -u +%FT%TZ)] Phase G done."
