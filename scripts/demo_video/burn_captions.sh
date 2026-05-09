#!/usr/bin/env bash
# scripts/demo_video/burn_captions.sh
# Burn captions.srt into demo_silent.mp4 -> demo_silent_with_captions.mp4
set -euo pipefail

OUT_DIR="$(cd "$(dirname "$0")/../.." && pwd)/out/demo_video"
cd "$OUT_DIR"

if [ ! -f demo_silent.mp4 ]; then echo "missing demo_silent.mp4"; exit 1; fi
if [ ! -f captions.srt ]; then echo "missing captions.srt"; exit 1; fi

# Caption styling: white text, semi-transparent black box, IBM Plex Sans, 24pt,
# anchored to the lower third (alignment 2 + margin V=80).
ffmpeg -y -i demo_silent.mp4 -vf \
  "subtitles=captions.srt:force_style='Fontname=IBM Plex Sans,Fontsize=24,PrimaryColour=&H00FFFFFF,BackColour=&H80000000,BorderStyle=4,Outline=2,Shadow=0,Alignment=2,MarginV=80'" \
  -c:a copy demo_silent_with_captions.mp4

ffprobe -v quiet -show_entries format=duration -of csv=p=0 demo_silent_with_captions.mp4
