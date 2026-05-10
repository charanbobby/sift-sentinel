"""Build the SRT caption file from the phrase list (phrases.py).

Each phrase becomes one SRT cue. The first cue gets a small lead-in so the
cold-open frame breathes before the first caption appears.

Source of truth: scripts/demo_video/phrases.py
"""
from __future__ import annotations

from .phrases import PHRASES, BEAT_ORDER


def _hms(seconds: float) -> str:
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    ms = int(round((seconds - int(seconds)) * 1000))
    if ms == 1000:
        ms = 0
        s += 1
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"


def build_srt(lead_in_s: float = 0.0, gap_s: float = 0.15) -> str:
    """Build the full SRT covering every phrase. Each cue starts at the
    cumulative beat-relative offset and ends `gap_s` seconds before the
    next phrase begins (so cues do not visually overlap).

    Default lead_in_s = 0: caption phrase 0 starts at video_t=0 so it
    aligns with audio phrase 0 (which assemble_voiced positions at
    audio_t=0). The earlier 1.5s lead-in caused captions to drift 1.5s
    behind audio, making each caption look like it belonged to the
    previous voice line for the dense beats.
    """
    cues: list[tuple[float, float, str]] = []
    cumulative = 0.0
    is_first = True
    for beat in BEAT_ORDER:
        for p in (q for q in PHRASES if q["beat"] == beat):
            t0 = cumulative + (lead_in_s if is_first else 0)
            t1 = cumulative + p["duration_s"] - gap_s
            cues.append((t0, t1, p["text"]))
            cumulative += p["duration_s"]
            is_first = False
    out_parts: list[str] = []
    for idx, (t0, t1, text) in enumerate(cues, start=1):
        out_parts.append(f"{idx}\n{_hms(t0)} --> {_hms(t1)}\n{text}\n")
    return "\n".join(out_parts)


if __name__ == "__main__":
    from .config import OUT_DIR
    srt_path = OUT_DIR / "captions.srt"
    srt_path.write_text(build_srt(), encoding="utf-8")
    print(f"wrote {srt_path}")
