"""Tests for scripts/demo_video/captions.py SRT generator."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from demo_video.captions import build_srt, BEATS


def test_build_srt_has_one_cue_per_caption_line():
    srt = build_srt()
    assert "1\n00:00:" in srt
    assert " --> " in srt
    cue_count = srt.count(" --> ")
    assert cue_count >= len(BEATS), f"expected at least one cue per beat, got {cue_count}"


def test_build_srt_anchors_first_cue_to_2_seconds_in():
    srt = build_srt()
    assert "00:00:02," in srt, "first caption should appear at 2s into the cold open"


def test_build_srt_no_caption_line_over_80_chars():
    srt = build_srt()
    for line in srt.splitlines():
        if "-->" in line or line.strip().isdigit() or not line.strip():
            continue
        assert len(line) <= 80, f"caption line too long ({len(line)}): {line!r}"


def test_beats_total_300_seconds():
    total = sum(b["duration_s"] for b in BEATS)
    assert total == 300


def test_each_beat_has_voiceover_text():
    for b in BEATS:
        assert b["voiceover"].strip(), f"beat {b['name']} missing voiceover text"
