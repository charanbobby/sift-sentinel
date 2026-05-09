#!/usr/bin/env bash
# scripts/demo_video/assemble_silent.sh
# Concat the 5 silent beat MP4s into a single demo_silent.mp4.
# Output: out/demo_video/demo_silent.mp4
set -euo pipefail

OUT_DIR="$(cd "$(dirname "$0")/../.." && pwd)/out/demo_video"
cd "$OUT_DIR"

LIST=demo_silent_concat.txt
> "$LIST"
for beat in beat1_open beat2_architecture beat3_case beat4_loop beat5_outro; do
  if [ ! -f "$beat.mp4" ]; then
    echo "missing $beat.mp4 in $OUT_DIR" >&2
    exit 1
  fi
  echo "file '$beat.mp4'" >> "$LIST"
done

ffmpeg -y -f concat -safe 0 -i "$LIST" -c copy demo_silent.mp4
ffprobe -v quiet -show_entries format=duration -of csv=p=0 demo_silent.mp4
rm "$LIST"
