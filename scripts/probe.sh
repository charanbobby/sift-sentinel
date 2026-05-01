#!/usr/bin/env bash
# Fail-fast probe wrapper.
#
# Usage: scripts/probe.sh <target_file_relative_to_repo_root> -- <probe-command...>
#
# On exit 0 from the probe command, writes a marker file at
# .probes/<sanitized-target>.lastrun. The pre-tool-use Claude hook and the
# pre-commit git hook check that marker before allowing edits / commits to
# enforce-listed runtime files.

set -euo pipefail

if [ $# -lt 3 ] || [ "$2" != "--" ]; then
  echo "usage: $0 <target_file_relative_to_repo_root> -- <probe-command...>" >&2
  echo "example: $0 experiments/slice-2-notebook/pipeline/nodes.py -- bash probe_temperature.sh" >&2
  exit 2
fi

target="$1"
shift 2

repo_root="$(git rev-parse --show-toplevel)"
mkdir -p "$repo_root/.probes"

sanitized="$(printf '%s' "$target" | tr '/' '_')"
marker="$repo_root/.probes/$sanitized.lastrun"

echo "[probe] target=$target"
echo "[probe] command: $*"
echo "[probe] running ..."

if "$@"; then
  date +%s > "$marker"
  echo "[probe] PASS  marker: .probes/$sanitized.lastrun"
  exit 0
fi

rc=$?
echo "[probe] FAIL exit=$rc  no marker written" >&2
exit "$rc"
