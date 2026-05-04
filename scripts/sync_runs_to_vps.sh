#!/usr/bin/env bash
# Sync experiments/slice-2-notebook/out/runs/ from local to VPS.
#
# Why this exists: out/runs/ is in .gitignore (run outputs are large and
# regenerable), so `scripts/sync_to_vps.sh` (which only pushes committed code)
# never propagates run outputs. The unified site at sentinel.sshub.dev reads
# from this directory, so without this wrapper the VPS viewer drifts behind
# local as new runs land.
#
# This is a one-way push (local -> VPS). It uses tar-over-ssh because
# rsync is not always available in Git Bash on Windows. Excludes large
# binaries (.img/.dd/.raw) and the pre-step-0 staging dir, which contain
# either source images or intermediate files that don't need replicating.
#
# Usage (from any cwd inside the repo):
#   bash scripts/sync_runs_to_vps.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_RUNS="$REPO_ROOT/experiments/slice-2-notebook/out/runs"
VPS_RUNS="/opt/find-evil/repo/experiments/slice-2-notebook/out/runs"
SSH_KEY="$HOME/.ssh/id_hetzner"
VPS_HOST="sri@46.62.255.66"

if [[ ! -d "$LOCAL_RUNS" ]]; then
  echo "ERROR: local runs dir not found: $LOCAL_RUNS" >&2
  exit 1
fi

if [[ ! -f "$SSH_KEY" ]]; then
  echo "ERROR: ssh key not found: $SSH_KEY" >&2
  exit 1
fi

echo "=== Local runs ==="
( cd "$LOCAL_RUNS" && ls -1 | wc -l ) | xargs printf "  case dirs: %s\n"
du -sh "$LOCAL_RUNS" 2>/dev/null | awk '{print "  size on disk: " $1}'
echo

echo "=== VPS runs (before sync) ==="
ssh -i "$SSH_KEY" "$VPS_HOST" "cd $VPS_RUNS 2>/dev/null && ls -1 | wc -l && du -sh ." \
  | awk 'NR==1 {print "  case dirs: " $1} NR==2 {print "  size on disk: " $1}'
echo

echo "=== Pushing runs/ via tar-over-ssh ==="
( cd "$LOCAL_RUNS/.." && \
  tar czf - \
    --exclude='*.img' \
    --exclude='*.dd' \
    --exclude='*.raw' \
    --exclude='pre-step-0' \
    runs/ \
  | ssh -i "$SSH_KEY" "$VPS_HOST" \
      "cd $(dirname $VPS_RUNS) && tar xzf -" )
RC=$?
echo

if [[ $RC -ne 0 ]]; then
  echo "ERROR: tar pipeline returned $RC" >&2
  exit $RC
fi

echo "=== VPS runs (after sync) ==="
ssh -i "$SSH_KEY" "$VPS_HOST" "cd $VPS_RUNS && ls -1 | wc -l && du -sh ." \
  | awk 'NR==1 {print "  case dirs: " $1} NR==2 {print "  size on disk: " $1}'
echo

echo "=== Terminal markers on VPS (sanity check) ==="
ssh -i "$SSH_KEY" "$VPS_HOST" \
  "find $VPS_RUNS -maxdepth 3 -name 'TERMINAL_*' -type f 2>/dev/null | sed 's|.*/||' | sort | uniq -c"

echo
echo "Done."
