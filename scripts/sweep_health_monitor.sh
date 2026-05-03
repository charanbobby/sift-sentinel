#!/usr/bin/env bash
# sweep_health_monitor.sh
#
# Comprehensive health check for the standalone-memory-sweep. Runs every
# `INTERVAL_SEC` seconds (default 300). Each iteration emits:
#   1. one [hb] heartbeat line (always)
#   2. zero or more [ALERT-N] lines per failure mode detected
#
# Failure modes (one ALERT- per iteration per detection, deduplicated by alert
# state file at /tmp/sweep_alerts_$(date +%s) so the same hang does not spam):
#   1: sweep.log silent >30 min
#   3: orphan run_case.py for a case_id NOT in current HOSTS array
#   5: vol.py imageinfo state=S with no output growth >15 min
#   6: vol.py plugin state=S with no output growth >15 min
#   8: run_case.py wall time >90 min without 07_terminal.* marker
#  17: bundle HARD-CAP triggered in per-host log
#  15: BudgetExceeded raised in per-host log
#  18: 07_terminal.QUARANTINED appeared
#  19: 07_terminal.HUMAN_REVIEW appeared
#  20: 07_terminal.FAILED appeared
#  21: sift-mcp or sift-sentinel container exited
#  22: /tmp <5 GB free in sift-mcp; out/runs disk <5 GB free on host
#
# Usage (intended for Monitor tool with persistent=true):
#   bash scripts/sweep_health_monitor.sh
#
# Env:
#   SWEEP_LOG_DIR (default: out/standalone-memory-sweep-<UTC-date>)
#   INTERVAL_SEC  (default: 300)

set -uo pipefail

INTERVAL_SEC="${INTERVAL_SEC:-300}"
TODAY="$(date -u +%Y-%m-%d)"
SWEEP_LOG_DIR="${SWEEP_LOG_DIR:-out/standalone-memory-sweep-${TODAY}}"
SWEEP_LOG="${SWEEP_LOG_DIR}/sweep.log"
ALERT_STATE="/tmp/sweep_alerts_${TODAY}.state"
mkdir -p "$(dirname "$ALERT_STATE")"
touch "$ALERT_STATE"

now_epoch() { date -u +%s; }

# Emit alert ONCE per (alert_id, key) pair. Subsequent identical alerts in this
# run are suppressed so a single hung process does not spam every 5 min.
emit_alert() {
  local id="$1"; shift
  local key="$1"; shift
  local msg="$*"
  local sig="${id}::${key}"
  if grep -qF "$sig" "$ALERT_STATE" 2>/dev/null; then
    return
  fi
  echo "$sig" >> "$ALERT_STATE"
  echo "[ALERT-$id] $msg"
}

# Iterate forever. Each pass emits a heartbeat plus any new alerts.
while true; do
  hb_parts=()
  now=$(now_epoch)

  # ---- containers up ----
  mcp_up="no"
  sentinel_up="no"
  if MSYS_NO_PATHCONV=1 docker inspect -f '{{.State.Status}}' sift-mcp 2>/dev/null | grep -qx running; then
    mcp_up="yes"
  fi
  if MSYS_NO_PATHCONV=1 docker inspect -f '{{.State.Status}}' sift-sentinel 2>/dev/null | grep -qx running; then
    sentinel_up="yes"
  fi
  if [ "$mcp_up" != "yes" ]; then
    emit_alert 21 "sift-mcp" "sift-mcp container is NOT running"
  fi
  if [ "$sentinel_up" != "yes" ]; then
    emit_alert 21 "sift-sentinel" "sift-sentinel container is NOT running"
  fi
  hb_parts+=("mcp=$mcp_up sentinel=$sentinel_up")

  # ---- sweep.log staleness ----
  if [ -f "$SWEEP_LOG" ]; then
    log_mtime=$(stat -c %Y "$SWEEP_LOG" 2>/dev/null || stat -f %m "$SWEEP_LOG")
    log_age=$((now - log_mtime))
    last_line=$(tail -1 "$SWEEP_LOG")
    if [ "$log_age" -gt 1800 ]; then
      emit_alert 1 "sweep_silent_${log_mtime}" "sweep.log silent ${log_age}s; last=\"${last_line}\""
    fi
    hb_parts+=("sweep_log_age=${log_age}s")
  else
    hb_parts+=("sweep_log=missing")
  fi

  # ---- terminal markers in run dirs ----
  done_count=0
  q_count=0
  hr_count=0
  fail_count=0
  if [ -d "experiments/slice-2-notebook/out/runs" ]; then
    while IFS= read -r marker; do
      case "$marker" in
        */07_terminal.SUCCESS)        done_count=$((done_count + 1)) ;;
        */07_terminal.QUARANTINED)    q_count=$((q_count + 1));    emit_alert 18 "$marker" "QUARANTINED: $marker" ;;
        */07_terminal.HUMAN_REVIEW)   hr_count=$((hr_count + 1));  emit_alert 19 "$marker" "HUMAN_REVIEW: $marker" ;;
        */07_terminal.FAILED)         fail_count=$((fail_count + 1)); emit_alert 20 "$marker" "FAILED: $marker" ;;
      esac
    done < <(find experiments/slice-2-notebook/out/runs -name "07_terminal.*" -type f -newer "$ALERT_STATE" 2>/dev/null)
  fi
  hb_parts+=("success=$done_count quarantined=$q_count human_review=$hr_count failed=$fail_count")

  # ---- container processes (vol.py + run_case) ----
  # Use temp files instead of <(...) process substitution because Git Bash on
  # Windows mishandles multi-line embedded heredocs in process substitution.
  long_imageinfo=0
  long_pluginrun=0
  long_runcase=0
  hung_imageinfo_pids=()
  PROCS_MCP_TMP="/tmp/sweep_health_mcp_procs.$$"
  PROCS_SENT_TMP="/tmp/sweep_health_sent_procs.$$"
  : > "$PROCS_MCP_TMP"
  : > "$PROCS_SENT_TMP"

  if [ "$mcp_up" = "yes" ]; then
    MSYS_NO_PATHCONV=1 docker exec sift-mcp sh -c 'upt=$(awk "{print int(\$1)}" /proc/uptime); for f in /proc/*/cmdline; do c=$(tr "\0" " " < "$f" 2>/dev/null); case "$c" in *vol.py*) pid=$(echo "$f" | sed -e "s|/proc/||" -e "s|/cmdline||"); st=$(awk "{print int(\$22/100)}" /proc/$pid/stat 2>/dev/null); age=$((upt - st)); echo "$pid $age $c";; esac; done' > "$PROCS_MCP_TMP" 2>/dev/null
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      pid=$(echo "$line" | awk '{print $1}')
      age=$(echo "$line" | awk '{print $2}')
      cmd=$(echo "$line" | cut -d' ' -f3-)
      case "$cmd" in
        *vol.py*imageinfo*)
          if [ -n "$age" ] && [ "$age" -gt 900 ] 2>/dev/null; then
            long_imageinfo=$((long_imageinfo + 1))
            hung_imageinfo_pids+=("$pid")
            emit_alert 5 "imageinfo_pid${pid}" "imageinfo PID=$pid age=${age}s :: $cmd"
          fi
          ;;
        *vol.py*)
          if [ -n "$age" ] && [ "$age" -gt 900 ] 2>/dev/null; then
            long_pluginrun=$((long_pluginrun + 1))
            emit_alert 6 "plugin_pid${pid}" "vol.py plugin PID=$pid age=${age}s :: $cmd"
          fi
          ;;
      esac
    done < "$PROCS_MCP_TMP"
  fi

  if [ "$sentinel_up" = "yes" ]; then
    MSYS_NO_PATHCONV=1 docker exec sift-sentinel sh -c 'upt=$(awk "{print int(\$1)}" /proc/uptime); for f in /proc/*/cmdline; do c=$(tr "\0" " " < "$f" 2>/dev/null); case "$c" in *run_case*) pid=$(echo "$f" | sed -e "s|/proc/||" -e "s|/cmdline||"); st=$(awk "{print int(\$22/100)}" /proc/$pid/stat 2>/dev/null); age=$((upt - st)); echo "$pid $age $c";; esac; done' > "$PROCS_SENT_TMP" 2>/dev/null
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      pid=$(echo "$line" | awk '{print $1}')
      age=$(echo "$line" | awk '{print $2}')
      cmd=$(echo "$line" | cut -d' ' -f3-)
      case "$cmd" in
        *run_case*)
          if [ -n "$age" ] && [ "$age" -gt 5400 ] 2>/dev/null; then
            long_runcase=$((long_runcase + 1))
            emit_alert 8 "runcase_pid${pid}" "run_case.py PID=$pid age=${age}s :: $cmd"
          fi
          ;;
      esac
    done < "$PROCS_SENT_TMP"
  fi
  rm -f "$PROCS_MCP_TMP" "$PROCS_SENT_TMP" 2>/dev/null

  hb_parts+=("imageinfo_long=$long_imageinfo plugin_long=$long_pluginrun runcase_long=$long_runcase")

  # ---- bundle cap and budget alerts in per-host logs ----
  if [ -d "$SWEEP_LOG_DIR" ]; then
    for plog in "$SWEEP_LOG_DIR"/srl-2018-*.log; do
      [ -f "$plog" ] || continue
      bn=$(basename "$plog")
      if grep -q "HARD-CAP triggered" "$plog" 2>/dev/null; then
        emit_alert 17 "$bn" "Bundle HARD-CAP triggered in $bn"
      fi
      if grep -q "BudgetExceeded\|run cost \$.* exceeded ceiling" "$plog" 2>/dev/null; then
        emit_alert 15 "$bn" "Per-host budget ceiling tripped in $bn"
      fi
    done
  fi

  # ---- /tmp free space inside sift-mcp ----
  if [ "$mcp_up" = "yes" ]; then
    tmp_free_gb=$(MSYS_NO_PATHCONV=1 docker exec sift-mcp sh -c "df -BG /tmp | tail -1 | awk '{print \$4}' | tr -d 'G'" 2>/dev/null)
    if [ -n "$tmp_free_gb" ] && [ "$tmp_free_gb" -lt 5 ] 2>/dev/null; then
      emit_alert 22 "tmp_low_${tmp_free_gb}" "sift-mcp /tmp free=${tmp_free_gb}G (<5G)"
    fi
    hb_parts+=("mcp_tmp_free=${tmp_free_gb:-?}G")
  fi

  # ---- emit heartbeat ----
  echo "[hb] $(date -u +%Y-%m-%dT%H:%M:%SZ) ${hb_parts[*]}"

  sleep "$INTERVAL_SEC"
done
