#!/usr/bin/env bash
# One-shot: copy the live /tmp memory staging into /mnt/derived/staged-memory
# so a docker-compose restart does not lose the ~80 GB of staged .img files.
#
# Run this BEFORE `docker-compose down`. Idempotent: re-running skips any
# file that is already present and identical-size at the target.
#
# Usage (from repo root, on the same host running sift-mcp):
#   bash scripts/migrate_staging_to_derived.sh
#
# After running this once, future container restarts cost zero re-staging
# because the persistent volume / bind mount keeps the .img files alive.
set -uo pipefail

SRC="/tmp"
DST="/mnt/derived/staged-memory"

if ! MSYS_NO_PATHCONV=1 docker exec sift-mcp test -d "$DST"; then
  echo "Creating $DST inside sift-mcp..."
  MSYS_NO_PATHCONV=1 docker exec sift-mcp mkdir -p "$DST" || { echo "FAIL: mkdir $DST" >&2; exit 2; }
fi

echo "=== Inventory in $SRC ==="
MSYS_NO_PATHCONV=1 docker exec sift-mcp bash -c "ls -la $SRC/*.img $SRC/*-imageinfo.txt 2>/dev/null | tail -n +1"

echo
echo "=== Copying to $DST ==="
copied=0
skipped=0
failed=0
for ext in img txt; do
  for f in $(MSYS_NO_PATHCONV=1 docker exec sift-mcp bash -c "ls $SRC/*.$ext 2>/dev/null"); do
    base=$(basename "$f")
    src_size=$(MSYS_NO_PATHCONV=1 docker exec sift-mcp stat -c %s "$f" 2>/dev/null || echo 0)
    dst_size=$(MSYS_NO_PATHCONV=1 docker exec sift-mcp stat -c %s "$DST/$base" 2>/dev/null || echo 0)
    if [ "$src_size" = "$dst_size" ] && [ "$src_size" != "0" ]; then
      echo "  SKIP   $base (already $src_size bytes at destination)"
      skipped=$((skipped+1))
      continue
    fi
    echo "  COPY   $base ($src_size bytes)"
    if MSYS_NO_PATHCONV=1 docker exec sift-mcp cp "$f" "$DST/$base"; then
      copied=$((copied+1))
    else
      echo "  FAIL   $base"
      failed=$((failed+1))
    fi
  done
done

echo
echo "=== Summary ==="
echo "  copied:  $copied"
echo "  skipped: $skipped"
echo "  failed:  $failed"
echo
echo "Verify:"
echo "  docker exec sift-mcp ls -la $DST | head"
echo
if [ "$failed" -gt 0 ]; then
  echo "WARN: some copies failed. Do NOT docker-compose down until fixed." >&2
  exit 1
fi
echo "Safe to docker-compose down/up now. Future restarts cost zero re-staging."
