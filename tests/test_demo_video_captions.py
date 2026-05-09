"""Tests for scripts/demo_video/captions.py SRT generator (PHRASES-based)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from demo_video.captions import build_srt
from demo_video.phrases import PHRASES, BEAT_ORDER, beat_total_seconds


def test_phrases_total_300_seconds():
    assert sum(p["duration_s"] for p in PHRASES) == 300.0


def test_each_beat_sums_to_budget():
    expected = {"beat1_open": 15, "beat2_architecture": 45, "beat3_case": 180, "beat4_loop": 45, "beat5_outro": 15}
    for b in BEAT_ORDER:
        assert beat_total_seconds(b) == expected[b], f"beat {b} mismatch"


def test_build_srt_one_cue_per_phrase():
    srt = build_srt()
    cue_count = srt.count(" --> ")
    assert cue_count == len(PHRASES), f"expected {len(PHRASES)} cues, got {cue_count}"


def test_build_srt_first_cue_has_lead_in():
    srt = build_srt(lead_in_s=1.5)
    # First cue should start at 00:00:01,500
    assert "00:00:01,500" in srt or "1\n00:00:01" in srt, \
        f"first cue should have ~1.5s lead-in, srt head: {srt[:200]!r}"


def test_each_phrase_has_text():
    for p in PHRASES:
        assert p["text"].strip(), f"phrase missing text in beat {p['beat']}"
