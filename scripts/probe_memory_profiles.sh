#!/usr/bin/env bash
# probe_memory_profiles.sh
#
# Fail-fast probe: for each staged memory image in sift-mcp:/tmp/, run vol.py
# pslist with a candidate profile and check whether real process rows came
# back. A profile mismatch surfaces in ~30-60s as "No valid DTB found" /
# "Incompatible profile". A correct profile prints an "Offset(V)" header row.
#
# Usage:
#   bash scripts/probe_memory_profiles.sh
#
# Output: PASS/FAIL per host with detected profile suggestion on FAIL.
#
# Built 2026-05-03 after the standalone-memory sweep ran rd-05 and wkstn-06
# with the pinned default Win10x64_17134, both produced empty pslist /
# cmdline / netscan / malfind / dlllist (parse_error), and wkstn-06's
# pipeline still reported SUCCESS with hallucinated findings.

set -uo pipefail

# Each row: img_basename|candidate_profile
# Profiles default to Win10x64_17134 unless we already know better from prior
# sweep imageinfo runs.
HOSTS=(
  "base-admin-memory.img|Win10x64_17134"
  "base-dc-memory.img|Win2012R2x64"
  "base-file-memory.img|Win2012R2x64"
  "base-hunt-memory.img|Win10x64_17134"
  "base-mail-memory.img|Win2012R2x64"
  "base-rd-02-memory.img|Win10x64_17134"
  "base-rd-03-memory.img|Win10x64_17134"
  "base-rd-04-memory.img|Win10x64_17134"
  "base-rd-05-memory.img|Win7SP1x64"
  "base-rd01-memory.img|Win10x64_17134"
  "base-sp-memory.img|Win2012R2x64"
  "base-wkstn-02-memory.img|Win10x64_17134"
  "base-wkstn-03-memory.img|Win10x64_17134"
  "base-wkstn-04-memory.img|Win10x64_17134"
  "base-wkstn-05-memory.img|Win10x64_17134"
  "base-wkstn-06-memory.img|Win10x64_17134"
)

STAGE_DIR="/mnt/derived/staged-memory"

probe_one() {
  local img="$1"
  local profile="$2"
  # Try persistent staging first; fall back to legacy /tmp during the
  # migration window so a probe run does not break before the user moves
  # files into /mnt/derived/staged-memory/.
  local stage="$STAGE_DIR"
  if ! MSYS_NO_PATHCONV=1 docker exec sift-mcp test -s "$STAGE_DIR/$img"; then
    if MSYS_NO_PATHCONV=1 docker exec sift-mcp test -s "/tmp/$img"; then
      stage="/tmp"
    else
      echo "SKIP   $img  (not staged in $STAGE_DIR or /tmp)"
      return 2
    fi
  fi
  # Scan the FULL pslist output for the first decisive marker. Wrong profiles
  # produce ~25 lines of address-space probing failures BEFORE the DTB error
  # appears, so head -N truncation gives false "unrecognised" results.
  local out
  out=$(MSYS_NO_PATHCONV=1 docker exec sift-mcp bash -c \
    "timeout 180 vol.py -f $stage/$img --profile=$profile pslist 2>&1 | grep -E -m 1 'Offset\(V\)|No suitable address space mapping found|No valid DTB found|Incompatible profile'")
  if echo "$out" | grep -q "Offset(V)"; then
    echo "PASS   $img  profile=$profile"
    return 0
  fi
  if [ -n "$out" ]; then
    echo "FAIL   $img  profile=$profile  (DTB/profile mismatch, run imageinfo)"
    return 1
  fi
  echo "FAIL   $img  profile=$profile  (no decisive marker in 180s, check container)"
  return 1
}

main() {
  echo "=== Memory profile probe $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
  local fail=0
  local pass=0
  local skip=0
  for entry in "${HOSTS[@]}"; do
    IFS='|' read -r img profile <<< "$entry"
    if probe_one "$img" "$profile"; then
      pass=$((pass+1))
    else
      rc=$?
      if [ "$rc" -eq 2 ]; then
        skip=$((skip+1))
      else
        fail=$((fail+1))
      fi
    fi
  done
  echo
  echo "=== Summary: $pass PASS, $fail FAIL, $skip SKIP ==="
}

main
