"""Build the final voiced MP4 by aligning per-phrase audio to phrase
boundaries in the captioned silent video.

For each phrase: pad the per-phrase voice MP3 with silence (or trim if too
long) so its on-screen duration equals `phrase['duration_s']`. Concatenate
all chunks in beat order to form one 324s audio track, then mux with
demo_silent_with_captions.mp4.

Run AFTER:
    python -m scripts.demo_video.voice_gen
    bash scripts/demo_video/assemble_silent.sh
    bash scripts/demo_video/burn_captions.sh

Usage:
    python -m scripts.demo_video.assemble_voiced

Output:
    out/demo_video/demo_final.mp4
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .config import OUT_DIR
from .phrases import PHRASES, BEAT_ORDER
from .voice_gen import phrase_voice_path


SILENT_CAPTIONED = OUT_DIR / "demo_silent_with_captions.mp4"
FINAL_OUT = OUT_DIR / "demo_final.mp4"


def _ffprobe_duration(path: Path) -> float:
    out = subprocess.check_output(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "default=noprint_wrappers=1:nokey=1", str(path)],
        text=True,
    )
    return float(out.strip())


def _build_phrase_chunk(voice_mp3: Path, target_s: float, out_chunk: Path) -> None:
    """Pad with silence (apad) and trim (-t) so the chunk is exactly target_s."""
    subprocess.check_call([
        "ffmpeg", "-y", "-loglevel", "error",
        "-i", str(voice_mp3),
        "-af", f"apad=whole_dur={target_s}",
        "-t", f"{target_s}",
        "-c:a", "libmp3lame", "-q:a", "4",
        str(out_chunk),
    ])


def _concat_chunks(chunk_paths: list[Path], out_path: Path) -> None:
    """Concat MP3 chunks via the concat demuxer."""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        for p in chunk_paths:
            f.write(f"file '{p.as_posix()}'\n")
        list_path = Path(f.name)
    try:
        subprocess.check_call([
            "ffmpeg", "-y", "-loglevel", "error",
            "-f", "concat", "-safe", "0",
            "-i", str(list_path),
            "-c:a", "libmp3lame", "-q:a", "4",
            str(out_path),
        ])
    finally:
        list_path.unlink(missing_ok=True)


def _mux_video_audio(video: Path, audio: Path, out: Path) -> None:
    subprocess.check_call([
        "ffmpeg", "-y", "-loglevel", "error",
        "-i", str(video),
        "-i", str(audio),
        "-c:v", "copy",
        "-c:a", "aac", "-b:a", "192k",
        "-map", "0:v:0", "-map", "1:a:0",
        "-shortest",
        str(out),
    ])


def main() -> int:
    if not SILENT_CAPTIONED.exists():
        print(f"missing {SILENT_CAPTIONED}; run assemble_silent.sh + burn_captions.sh first",
              file=sys.stderr)
        return 1

    workdir = OUT_DIR / "_voiced_chunks"
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir()

    chunk_paths: list[Path] = []
    overflow_warnings = 0
    for beat_name in BEAT_ORDER:
        beat_phrases = [p for p in PHRASES if p["beat"] == beat_name]
        for idx, phrase in enumerate(beat_phrases):
            voice_mp3 = phrase_voice_path(beat_name, idx)
            if not voice_mp3.exists():
                print(f"missing voice for {beat_name}[{idx:02d}]: {voice_mp3}", file=sys.stderr)
                return 1
            voice_dur = _ffprobe_duration(voice_mp3)
            target = float(phrase["duration_s"])
            if voice_dur > target + 0.05:
                print(f"WARN {beat_name}[{idx:02d}] voice={voice_dur:.2f}s > budget={target:.2f}s "
                      f"(text: {phrase['text'][:60]!r}); will trim to budget")
                overflow_warnings += 1
            chunk_path = workdir / f"chunk_{beat_name}_{idx:02d}.mp3"
            _build_phrase_chunk(voice_mp3, target, chunk_path)
            chunk_paths.append(chunk_path)

    full_audio = workdir / "_full_audio.mp3"
    _concat_chunks(chunk_paths, full_audio)
    audio_dur = _ffprobe_duration(full_audio)
    video_dur = _ffprobe_duration(SILENT_CAPTIONED)
    print(f"full audio: {audio_dur:.2f}s, captioned silent: {video_dur:.2f}s")

    _mux_video_audio(SILENT_CAPTIONED, full_audio, FINAL_OUT)
    final_dur = _ffprobe_duration(FINAL_OUT)
    final_size_mb = FINAL_OUT.stat().st_size / (1024 * 1024)
    print(f"wrote {FINAL_OUT} ({final_size_mb:.1f} MB, {final_dur:.2f}s)")
    if overflow_warnings:
        print(f"NOTE: {overflow_warnings} phrase(s) had voice longer than budget; "
              f"audio was trimmed. Consider lengthening those phrase durations or "
              f"shortening their text.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
