#!/usr/bin/env bash
# standalone_memory_sweep.sh
#
# Sweep standalone-memory hosts (no disk image) through the memory-only
# pipeline. For each host: ensure .img is extracted, stage to /tmp inside
# sift-mcp, detect Volatility profile if not pinned, run run_case.py.
#
# Continues on per-host error so one bad host does not abort the sweep.
#
# Usage (run on Windows host with Docker Desktop, Git Bash):
#   bash scripts/standalone_memory_sweep.sh
#
# To limit hosts, comment out rows in the HOSTS array below.
#
# Per-host log:    out/standalone-memory-sweep-<date>/<case>.log
# Aggregate log:   out/standalone-memory-sweep-<date>/sweep.log

set -uo pipefail

DATE_STAMP="$(date -u +%Y-%m-%d)"
LOG_DIR="out/standalone-memory-sweep-${DATE_STAMP}"
mkdir -p "$LOG_DIR"
SWEEP_LOG="$LOG_DIR/sweep.log"
LOCK_FILE="$LOG_DIR/sweep.lock"

# Concurrent-sweep guard. The 2026-05-03 incident: a second copy of this
# script was launched while the first was still running (Cygwin had also hit
# fork-resource exhaustion, making the first sweep look hung). The two sweeps
# raced on the same case_id, both run_case.py invocations crashed during the
# EXECUTE phase, and the case logs got clobbered. Refuse to start if another
# instance is alive on this host.
if [ -f "$LOCK_FILE" ]; then
  prev_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
  if [ -n "$prev_pid" ] && kill -0 "$prev_pid" 2>/dev/null; then
    echo "ERROR: another sweep is running (pid $prev_pid). Wait or rm $LOCK_FILE." >&2
    exit 1
  fi
  echo "WARN: stale lock file at $LOCK_FILE, removing" >&2
  rm -f "$LOCK_FILE"
fi
echo $$ > "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"' EXIT

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { echo "[$(ts)] $*" | tee -a "$SWEEP_LOG" >&2; }

# Each row: case_id|sevenzip_basename|extracted_dirname|memory_basename|profile_or_AUTO
#
# `case_id`             becomes the run case_id and output dir name.
# `sevenzip_basename`   .7z under /mnt/hackathon/. Empty if the dump is
#                       already extracted (no 7z extraction needed).
# `extracted_dirname`   directory under /mnt/hackathon/ holding the .img.
# `memory_basename`     filename of the .img inside that dir.
# `profile_or_AUTO`     Volatility 2 profile string, or AUTO for imageinfo.
#
# Ordering note (2026-05-03 fourth attempt): rd01 SUCCESS in 60min total (17min
# imageinfo + 43min pipeline). The earlier "all SRL 2018 workstations and RDP
# gateways are Win10 1803/17134" assumption was wrong. probe_memory_profiles.sh
# (run 2026-05-03 after the contaminated wkstn-06 sweep) confirmed:
#   PASS Win10x64_17134: rd01, rd-03, rd-04, wkstn-02, wkstn-03, wkstn-04, dc
#   PASS Win7SP1x64    : rd-05, wkstn-05, wkstn-06
#   PENDING            : mail (imageinfo still running 2026-05-03 14:00)
# dc imageinfo landed at 13:58 with Win10x64_17134 as top match (modern Server
# kernel shares the Win10x64 base, so the workstation default works for it).
# rd-06 dropped: no source data in /mnt/hackathon/.
# rd01 already completed and is dropped from the queue.
HOSTS=(
  "srl-2018-base-rd-03-memonly|base-rd-03-memory.7z|base-rd-03-memory|base-rd-03-memory.img|Win10x64_17134"
  "srl-2018-base-rd-04-memonly|base-rd-04-memory.7z|base-rd-04-memory|base-rd-04-memory.img|Win10x64_17134"
  "srl-2018-base-rd-05-memonly|base-rd-05-memory.7z|base-rd-05-memory|base-rd-05-memory.img|Win7SP1x64"
  "srl-2018-base-wkstn-02-memonly|base-wkstn-02-memory.7z|base-wkstn-02-memory|base-wkstn-02-memory.img|Win10x64_17134"
  "srl-2018-base-wkstn-03-memonly|base-wkstn-03-memory.7z|base-wkstn-03-memory|base-wkstn-03-memory.img|Win10x64_17134"
  "srl-2018-base-wkstn-04-memonly|base-wkstn-04-memory.7z|base-wkstn-04-memory|base-wkstn-04-memory.img|Win10x64_17134"
  "srl-2018-base-wkstn-06-memonly|base-wkstn-06-memory.7z|base-wkstn-06-memory|base-wkstn-06-memory.img|Win7SP1x64"
)

extract_if_needed() {
  local sevenzip_basename="$1"
  local extracted_dir="$2"
  local mem_basename="$3"
  if MSYS_NO_PATHCONV=1 docker exec sift-mcp test -s "/mnt/hackathon/$extracted_dir/$mem_basename"; then
    log "  [extract] /mnt/hackathon/$extracted_dir/$mem_basename already present"
    return 0
  fi
  if [ -z "$sevenzip_basename" ]; then
    log "  [extract] FAIL: .img not present and no .7z to extract"
    return 1
  fi
  log "  [extract] 7z x /mnt/hackathon/$sevenzip_basename -> /mnt/hackathon/$extracted_dir/"
  if MSYS_NO_PATHCONV=1 docker exec sift-mcp bash -c \
      "mkdir -p /mnt/hackathon/$extracted_dir && cd /mnt/hackathon/$extracted_dir && 7z x -y /mnt/hackathon/$sevenzip_basename"; then
    log "  [extract] done"
    return 0
  fi
  log "  [extract] FAILED"
  return 1
}

# Persistent staging path. /tmp inside sift-mcp is ephemeral so a container
# restart wipes ~80 GB of staged .img files. /mnt/derived is a host bind
# mount (D:/.../HACKATHON-2026/derived inside Windows Docker Desktop, or
# /opt/find-evil/HACKATHON-2026/derived on the VPS) so memory images survive
# restarts. Switched 2026-05-03 after the cost of one re-stage made the
# learning-loop deployment risk visible.
STAGE_DIR="/mnt/derived/staged-memory"

stage_to_persistent() {
  local extracted_dir="$1"
  local mem_basename="$2"
  if MSYS_NO_PATHCONV=1 docker exec sift-mcp test -s "$STAGE_DIR/$mem_basename"; then
    log "  [stage] $STAGE_DIR/$mem_basename already present"
    return 0
  fi
  log "  [stage] cp /mnt/hackathon/$extracted_dir/$mem_basename -> $STAGE_DIR/$mem_basename"
  if MSYS_NO_PATHCONV=1 docker exec sift-mcp bash -c \
      "mkdir -p $STAGE_DIR && cp /mnt/hackathon/$extracted_dir/$mem_basename $STAGE_DIR/$mem_basename"; then
    log "  [stage] cp done"
    return 0
  fi
  log "  [stage] cp FAILED"
  return 1
}

detect_profile() {
  local mem_basename="$1"
  local case_log="$2"
  log "  [profile] vol.py imageinfo on $STAGE_DIR/$mem_basename"
  local out_file="$STAGE_DIR/${mem_basename%.img}-imageinfo.txt"
  if ! MSYS_NO_PATHCONV=1 docker exec sift-mcp bash -c \
      "vol.py -f $STAGE_DIR/$mem_basename imageinfo > $out_file 2>&1"; then
    log "  [profile] imageinfo FAILED"
    return 1
  fi
  local profile
  profile=$(MSYS_NO_PATHCONV=1 docker exec sift-mcp bash -c \
    "grep 'Suggested Profile' $out_file | head -1 | sed 's/.*: //' | cut -d',' -f1 | xargs")
  if [ -z "$profile" ]; then
    log "  [profile] could not parse profile"
    MSYS_NO_PATHCONV=1 docker exec sift-mcp head -20 "$out_file" | tee -a "$case_log"
    return 1
  fi
  echo "$profile"
}

run_pipeline() {
  local case_id="$1"
  local mem_basename="$2"
  local profile="$3"
  local case_log="$4"
  log "  [pipeline] $case_id memory-only profile=$profile"
  if MSYS_NO_PATHCONV=1 docker exec sift-sentinel bash -c \
      "cd /workspace && uv run python run_case.py --case $case_id --memory-image $STAGE_DIR/$mem_basename --memory-profile $profile" \
      >> "$case_log" 2>&1; then
    log "  [pipeline] $case_id SUCCESS"
    return 0
  fi
  log "  [pipeline] $case_id FAILED (see $case_log)"
  return 1
}

log "=== Standalone memory sweep started ==="
log "Hosts in queue: ${#HOSTS[@]}"

for entry in "${HOSTS[@]}"; do
  IFS='|' read -r case_id sevenzip extracted_dir mem_basename profile <<< "$entry"
  case_log="$LOG_DIR/${case_id}.log"
  log ""
  log "--- $case_id ---"
  log "  sevenzip:      ${sevenzip:-<none>}"
  log "  extracted_dir: $extracted_dir"
  log "  memory:        $mem_basename"
  log "  profile:       $profile"

  if ! extract_if_needed "$sevenzip" "$extracted_dir" "$mem_basename" >> "$case_log" 2>&1; then
    log "  SKIP $case_id (extract failed)"
    continue
  fi
  if ! stage_to_persistent "$extracted_dir" "$mem_basename" >> "$case_log" 2>&1; then
    log "  SKIP $case_id (stage failed)"
    continue
  fi
  if [ "$profile" = "AUTO" ]; then
    profile=$(detect_profile "$mem_basename" "$case_log")
    if [ -z "$profile" ]; then
      log "  SKIP $case_id (profile detect failed)"
      continue
    fi
    log "  [profile] detected: $profile"
  fi
  run_pipeline "$case_id" "$mem_basename" "$profile" "$case_log" || continue
done

log ""
log "=== Standalone memory sweep finished ==="
log "Per-host logs in $LOG_DIR/"
