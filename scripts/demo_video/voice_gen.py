"""Generate ElevenLabs voice for each beat. One MP3 per beat. Run AFTER
Phase D.5 review-gate signoff. This is the only paid step in the pipeline.

Env vars required:
    ELEVENLABS_API_KEY       Charan's ElevenLabs API key
    ELEVENLABS_VOICE_ID      Charan's voice clone ID

Usage:
    python -m scripts.demo_video.voice_gen           # all beats
    python -m scripts.demo_video.voice_gen beat1_open  # one beat
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import urllib.request
import urllib.error

from .captions import BEATS
from .config import OUT_DIR


API_URL_TEMPLATE = "https://api.elevenlabs.io/v1/text-to-speech/{voice_id}"


def _generate_one(api_key: str, voice_id: str, voiceover: str, out_path: Path) -> None:
    body = {
        "text": voiceover,
        "model_id": "eleven_multilingual_v2",
        "voice_settings": {"stability": 0.5, "similarity_boost": 0.75},
    }
    import json
    req = urllib.request.Request(
        API_URL_TEMPLATE.format(voice_id=voice_id),
        method="POST",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "xi-api-key": api_key,
            "content-type": "application/json",
            "accept": "audio/mpeg",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        out_path.write_bytes(resp.read())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("beat", nargs="?", help="beat name; omit to generate all")
    args = ap.parse_args()
    api_key = os.environ.get("ELEVENLABS_API_KEY")
    voice_id = os.environ.get("ELEVENLABS_VOICE_ID")
    if not api_key or not voice_id:
        print("ELEVENLABS_API_KEY and ELEVENLABS_VOICE_ID env vars required", file=sys.stderr)
        return 2
    selected = [b for b in BEATS if (args.beat is None or b["name"] == args.beat)]
    if not selected:
        print(f"unknown beat {args.beat!r}", file=sys.stderr)
        return 1
    for b in selected:
        out_path = OUT_DIR / f"voice_{b['name']}.mp3"
        if out_path.exists():
            print(f"skip {b['name']} (already exists at {out_path}); delete to regenerate")
            continue
        print(f"generating {b['name']} -> {out_path}")
        _generate_one(api_key, voice_id, b["voiceover"], out_path)
        print(f"  wrote {out_path.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
