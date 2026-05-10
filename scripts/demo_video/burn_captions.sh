#!/usr/bin/env bash
# scripts/demo_video/burn_captions.sh
# Burn captions.srt into demo_silent.mp4 -> demo_silent_with_captions.mp4
set -euo pipefail

OUT_DIR="$(cd "$(dirname "$0")/../.." && pwd)/out/demo_video"
cd "$OUT_DIR"

if [ ! -f demo_silent.mp4 ]; then echo "missing demo_silent.mp4"; exit 1; fi
if [ ! -f captions.srt ]; then echo "missing captions.srt"; exit 1; fi

# Caption styling. PlayResX/PlayResY pinned to 1920x1080 so Fontsize maps
# 1:1 to physical pixels at 1080p (ffmpeg's subtitles filter defaults to
# PlayResY=288 which makes Fontsize values 3.75x larger than expected, and
# the previous 18pt rendered as ~67px). With PlayResY=1080 set, Fontsize=22
# is ~22px which reads cleanly without dominating the frame.
#
# White text on FULLY OPAQUE black box, IBM Plex Sans, 32px, bottom edge.
# BackColour=&H00000000 means alpha 0x00 = fully opaque (ASS alpha is
# inverse: 00 opaque, FF transparent). Captions stand out cleanly instead
# of blending into the page background.
ffmpeg -y -i demo_silent.mp4 -vf \
  "subtitles=captions.srt:force_style='PlayResX=1920,PlayResY=1080,Fontname=IBM Plex Sans,Fontsize=32,PrimaryColour=&H00FFFFFF,BackColour=&H00000000,OutlineColour=&H00000000,BorderStyle=4,Outline=8,Shadow=0,Alignment=2,MarginV=40,MarginL=120,MarginR=120'" \
  -c:a copy demo_silent_with_captions.mp4

ffprobe -v quiet -show_entries format=duration -of csv=p=0 demo_silent_with_captions.mp4
