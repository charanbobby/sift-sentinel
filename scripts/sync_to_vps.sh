#!/usr/bin/env bash
# Push local committed changes to the VPS working tree.
#
# Setup: VPS at /opt/find-evil/repo is a git repo with
# `receive.denyCurrentBranch=updateInstead`, so a push to its `main` branch
# updates the checked-out working tree in place. The local has remote `vps`
# pointing at `sri@46.62.255.66:/opt/find-evil/repo`.
#
# This wrapper is intentionally narrow: it pushes what is already committed,
# does NOT auto-commit dirty work, and prints VPS HEAD afterwards as proof.
#
# Usage (from any cwd inside the repo):
#   bash scripts/sync_to_vps.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== Local status (uncommitted will NOT be pushed) ==="
git status --short
echo

echo "=== Local HEAD ==="
git log --oneline -3
echo

echo "=== Pushing committed main to vps remote ==="
GIT_SSH_COMMAND="ssh -i $HOME/.ssh/id_hetzner" git push vps main
echo

echo "=== VPS HEAD after push ==="
ssh -i ~/.ssh/id_hetzner sri@46.62.255.66 \
  "cd /opt/find-evil/repo && git log --oneline -3 && echo && echo 'working tree status:' && git status --short"
