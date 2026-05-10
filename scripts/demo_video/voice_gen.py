"""Generate ElevenLabs voice for each PHRASE (not each beat).

Per-phrase generation gives the assembler exact audio start times: each
phrase MP3 is positioned at its phrase boundary inside the silent video,
padded with silence to fill the budget. Voice and captions stay in sync.

ElevenLabs charges by character regardless of call count, so 62 small
calls cost the same as 5 large ones. Cache-first: any existing
voice_<beat>_<idx>.mp3 is skipped, so a re-run only bills missing phrases.

Env vars required:
    ELEVENLABS_API_KEY       Charan's ElevenLabs API key
    ELEVENLABS_VOICE_ID      Charan's voice clone ID

Usage:
    python -m scripts.demo_video.voice_gen           # all phrases
    python -m scripts.demo_video.voice_gen beat1_open  # phrases of one beat
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

from .phrases import PHRASES, BEAT_ORDER
from .config import OUT_DIR


API_URL_TEMPLATE = "https://api.elevenlabs.io/v1/text-to-speech/{voice_id}"


def phrase_voice_path(beat_name: str, idx_in_beat: int) -> Path:
    """Stable per-phrase MP3 path. idx_in_beat is the phrase's 0-based
    position within its beat (00, 01, ...).
    """
    return OUT_DIR / f"voice_{beat_name}_{idx_in_beat:02d}.mp3"


def _generate_one(api_key: str, voice_id: str, text: str, out_path: Path) -> None:
    body = {
        "text": text,
        "model_id": "eleven_multilingual_v2",
        "voice_settings": {
            "stability": 0.5,
            "similarity_boost": 0.75,
            "speed": 1.0,
        },
    }
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
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            out_path.write_bytes(resp.read())
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"ElevenLabs HTTP {e.code}: {body_txt}") from None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("beat", nargs="?", help="beat name; omit to generate all phrases")
    args = ap.parse_args()
    api_key = os.environ.get("ELEVENLABS_API_KEY")
    voice_id = os.environ.get("ELEVENLABS_VOICE_ID")
    if not api_key or not voice_id:
        print("ELEVENLABS_API_KEY and ELEVENLABS_VOICE_ID env vars required", file=sys.stderr)
        return 2
    selected_beats = [b for b in BEAT_ORDER if (args.beat is None or b == args.beat)]
    if not selected_beats:
        print(f"unknown beat {args.beat!r}", file=sys.stderr)
        return 1

    total_chars = 0
    generated = 0
    skipped = 0
    for beat_name in selected_beats:
        beat_phrases = [p for p in PHRASES if p["beat"] == beat_name]
        for idx, phrase in enumerate(beat_phrases):
            out_path = phrase_voice_path(beat_name, idx)
            text = phrase["text"]
            if out_path.exists():
                skipped += 1
                continue
            print(f"generating {beat_name}[{idx:02d}] -> {out_path.name} ({len(text)} chars)")
            _generate_one(api_key, voice_id, text, out_path)
            print(f"  wrote {out_path.stat().st_size} bytes")
            total_chars += len(text)
            generated += 1
    print(f"done: generated={generated} skipped={skipped} chars_billed={total_chars}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
