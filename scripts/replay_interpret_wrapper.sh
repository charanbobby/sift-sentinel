#!/usr/bin/env bash
# Host-side wrapper for replay_interpret.py.
#
# replay_interpret.py needs the `pipeline` package which is only present
# inside the sift-sentinel container's venv at /workspace/.venv. The host
# has neither the venv nor /opt/find-evil/out/loop-runs visible to the
# container. So this wrapper docker-cp's the inputs to /tmp inside the
# container, runs the script there, and prints the result.
#
# Usage:
#   bash scripts/replay_interpret_wrapper.sh \\
#       <run_dir> \\
#       <staged_rule_jsonl_id> \\
#       <target_miss_id>
#
# Example (after the next loop run preserves evidence):
#   bash scripts/replay_interpret_wrapper.sh \\
#       /opt/find-evil/out/loop-runs/2026-05-04 \\
#       ofbiz_cve_2024_38856_jsp-abc123def0 \\
#       ofbiz_cve_2024_38856_jsp
set -uo pipefail

RUN_DIR="${1:-}"
RULE_ID="${2:-}"
TARGET_MISS="${3:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "$RUN_DIR" ] || [ -z "$RULE_ID" ] || [ -z "$TARGET_MISS" ]; then
  echo "FAIL: usage: replay_interpret_wrapper.sh <run_dir> <rule_id> <target_miss_id>" >&2
  exit 2
fi
if [ ! -d "$RUN_DIR/pipeline_output" ]; then
  echo "FAIL: $RUN_DIR/pipeline_output not found (loop run before evidence-preservation)" >&2
  exit 2
fi
if [ ! -f "$RUN_DIR/pipeline_output/04_execute_evidence.jsonl" ]; then
  echo "FAIL: 04_execute_evidence.jsonl not present in pipeline_output. Re-run the loop after evidence-preservation shipped (commit de765a4 or later)." >&2
  exit 2
fi

STAGED="$RUN_DIR/learned_rules.staged.jsonl"
if [ ! -f "$STAGED" ]; then
  echo "FAIL: $STAGED not found (Phase G never ran for this date)" >&2
  exit 2
fi
RULE_JSON="$(grep "\"id\": \"$RULE_ID\"" "$STAGED" | head -1)"
if [ -z "$RULE_JSON" ]; then
  echo "FAIL: rule id $RULE_ID not in $STAGED" >&2
  exit 2
fi

MANIFEST="$(ls "$RUN_DIR"/manifest_*.json 2>/dev/null | head -1)"
if [ -z "$MANIFEST" ]; then
  echo "FAIL: no manifest_*.json in $RUN_DIR" >&2
  exit 2
fi

# Prepare a tmp staging area inside the container.
SBOX="/tmp/replay_${RULE_ID}_$$"
docker exec sift-sentinel mkdir -p "$SBOX/pipeline_output" || { echo "FAIL: docker exec mkdir" >&2; exit 3; }
docker cp "$SCRIPT_DIR/replay_interpret.py" "sift-sentinel:$SBOX/replay_interpret.py"
docker cp "$RUN_DIR/pipeline_output/." "sift-sentinel:$SBOX/pipeline_output/"
docker cp "$MANIFEST" "sift-sentinel:$SBOX/manifest.json"

# Run.
docker exec sift-sentinel bash -c "
  cd /workspace && \
  uv run python $SBOX/replay_interpret.py \
    --pipeline-output $SBOX/pipeline_output \
    --manifest $SBOX/manifest.json \
    --staged-rule '$RULE_JSON' \
    --target-miss-id $TARGET_MISS
"
RC=$?

# Cleanup.
docker exec sift-sentinel rm -rf "$SBOX" || true

exit $RC
