#!/usr/bin/env bash
# scripts/demo_video/assemble_final.sh
# Concatenate beat audio files in spec order, then mux against the
# captions-burned silent video. Output: out/demo_video/final.mp4
set -euo pipefail

OUT_DIR="$(cd "$(dirname "$0")/../.." && pwd)/out/demo_video"
cd "$OUT_DIR"

if [ ! -f demo_silent_with_captions.mp4 ]; then
  echo "missing demo_silent_with_captions.mp4 (Phase D output)"
  exit 1
fi

# Build the audio track. BEATS order from captions.py.
LIST=audio_concat.txt
> "$LIST"
for beat in beat1_open beat2_architecture beat3a_findings beat3b_audit beat3c_critic beat3d_corroboration beat4_loop beat5_outro; do
  f="voice_${beat}.mp3"
  if [ ! -f "$f" ]; then echo "missing $f"; exit 1; fi
  echo "file '$f'" >> "$LIST"
done

ffmpeg -y -f concat -safe 0 -i "$LIST" -c copy audio_track.mp3
rm "$LIST"

# Mux. Use -shortest so the output stops at video end (300s).
ffmpeg -y -i demo_silent_with_captions.mp4 -i audio_track.mp3 \
  -c:v copy -c:a aac -b:a 192k -shortest final.mp4

ffprobe -v quiet -show_entries format=duration -of csv=p=0 final.mp4
ls -lh final.mp4
