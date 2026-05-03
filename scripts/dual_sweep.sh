#!/usr/bin/env bash
# dual_sweep.sh — overnight dual-channel sweep of disk-paired SRL-2018 hosts.
# Per host: stage memory dump to /tmp inside sift-mcp, detect profile if unknown,
# run the dual-channel pipeline, log to a per-host file. Continue on error.
#
# Usage (run on Windows host with Docker Desktop):
#   bash scripts/dual_sweep.sh
#
# Each host's log goes to: out/dual-sweep-2026-05-02/<host>.log
# Aggregate progress goes to:   out/dual-sweep-2026-05-02/sweep.log

set -uo pipefail

LOG_DIR="out/dual-sweep-2026-05-02"
mkdir -p "$LOG_DIR"
SWEEP_LOG="$LOG_DIR/sweep.log"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
# log writes to sweep.log AND stderr (NOT stdout) so $() captures of function
# return values are not polluted by log lines emitted from inside the function.
log() { echo "[$(ts)] $*" | tee -a "$SWEEP_LOG" >&2; }

# Each row: case_id|e01_path_in_sift_mcp|memory_basename|memory_src_path_in_sift_mcp|profile_or_AUTO
# 2026-05-02 03:05Z restart: dc + file already done in this sweep; rd-01 profile
# was detected during the first attempt as Win10x64_17134 so it's pinned now.
HOSTS=(
  "srl-2018-base-rd-01-dual|/mnt/hackathon/base-rd-01-cdrive.E01|base-rd01-memory.img|/mnt/hackathon/base-rd01-memory/base-rd01-memory.img|Win10x64_17134"
  "srl-2018-base-rd-02-dual|/mnt/hackathon/base-rd-02-cdrive.E01|base-rd-02-memory.img|/mnt/hackathon/base-rd-02-memory/base-rd-02-memory.img|AUTO"
  "srl-2018-base-wkstn-01-dual|/mnt/hackathon/base-wkstn-01-c-drive.E01|base-wkstn-01-mem.img|/mnt/hackathon/base-wkstn-01-memory/base-wkstn-01-mem.img|AUTO"
)

stage_memory() {
  local mem_basename="$1"
  local mem_src="$2"
  if MSYS_NO_PATHCONV=1 docker exec sift-mcp test -s "/tmp/$mem_basename"; then
    log "  [stage] /tmp/$mem_basename already present, skipping cp"
    return 0
  fi
  log "  [stage] cp $mem_src -> /tmp/$mem_basename (may take ~30 min via bind mount)"
  if MSYS_NO_PATHCONV=1 docker exec sift-mcp cp "$mem_src" "/tmp/$mem_basename"; then
    log "  [stage] cp done"
    return 0
  fi
  log "  [stage] cp FAILED"
  return 1
}

detect_profile() {
  local mem_basename="$1"
  local case_log="$2"
  log "  [profile] running vol.py imageinfo on /tmp/$mem_basename"
  local out_file="/tmp/${mem_basename%.img}-imageinfo.txt"
  if ! MSYS_NO_PATHCONV=1 docker exec sift-mcp bash -c \
      "vol.py -f /tmp/$mem_basename imageinfo > $out_file 2>&1"; then
    log "  [profile] imageinfo FAILED"
    return 1
  fi
  # Parse the first profile from "Suggested Profile(s) : Win7SP1x64, ..."
  local profile
  profile=$(MSYS_NO_PATHCONV=1 docker exec sift-mcp bash -c \
    "grep 'Suggested Profile' $out_file | head -1 | sed 's/.*: //' | cut -d',' -f1 | xargs")
  if [ -z "$profile" ]; then
    log "  [profile] could not parse profile from imageinfo output; head of file:"
    MSYS_NO_PATHCONV=1 docker exec sift-mcp head -20 "$out_file" | tee -a "$case_log"
    return 1
  fi
  echo "$profile"
}

run_pipeline() {
  local case_id="$1"
  local e01="$2"
  local mem_basename="$3"
  local profile="$4"
  local case_log="$5"
  log "  [pipeline] running $case_id with profile=$profile"
  if MSYS_NO_PATHCONV=1 docker exec sift-sentinel bash -c \
      "cd /workspace && uv run python run_case.py --case $case_id --e01 $e01 --memory-image /tmp/$mem_basename --memory-profile $profile" \
      >> "$case_log" 2>&1; then
    log "  [pipeline] $case_id SUCCESS"
    return 0
  else
    log "  [pipeline] $case_id FAILED (see $case_log)"
    return 1
  fi
}

log "=== Dual sweep started ==="
log "Hosts in queue: ${#HOSTS[@]}"

for entry in "${HOSTS[@]}"; do
  IFS='|' read -r case_id e01 mem_basename mem_src profile <<< "$entry"
  case_log="$LOG_DIR/${case_id}.log"
  log ""
  log "--- $case_id ---"
  log "  e01:        $e01"
  log "  memory_src: $mem_src"
  log "  profile:    $profile"
  log "  case_log:   $case_log"

  if ! stage_memory "$mem_basename" "$mem_src" >> "$case_log" 2>&1; then
    log "  SKIP $case_id (staging failed)"
    continue
  fi

  if [ "$profile" = "AUTO" ]; then
    profile=$(detect_profile "$mem_basename" "$case_log")
    if [ -z "$profile" ]; then
      log "  SKIP $case_id (profile detection failed)"
      continue
    fi
    log "  [profile] detected: $profile"
  fi

  run_pipeline "$case_id" "$e01" "$mem_basename" "$profile" "$case_log" || continue
done

log ""
log "=== Dual sweep finished ==="
log "Per-host logs in $LOG_DIR/"
