"""High-quality beat recorder using XvfbRecorder.

Replaces record_beat.py for the production pipeline. Each beat:
1. Records via xvfb + ffmpeg x11grab to a raw MP4 (target_s + 6s buffer)
2. Trims the last target_s seconds (so navigation + settle is clipped)
3. Applies a snappy Ken Burns zoom-in (1.0 -> 1.18 over 2s, then hold)

Usage:
    python -m scripts.demo_video.record_beat_xvfb beat2_architecture
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import subprocess
import sys
from pathlib import Path

from .config import OUT_DIR, DURATIONS, VIEWPORT_WIDTH, VIEWPORT_HEIGHT
from .xvfb_recorder import XvfbRecorder


# Snappy + dramatic zoom-in: ramp from 1.0 to 1.3 in ~12 frames (~0.4s
# at 30fps), then hold. d=1 makes each input frame produce one output
# frame so the increment controls speed.
ZOOM_FILTER = (
    "zoompan=z='min(zoom+0.025,1.3)':"
    "x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':"
    "d=1:s=1920x1080:fps=30"
)
# Buffer time added to capture so navigation + page settle is recorded
# but trimmed away. Keeps only the LAST target_s seconds where the
# scene's phrases actually play.
SETTLE_BUFFER_S = 6.0


async def _record(beat_name: str) -> Path:
    scene_module = importlib.import_module(f".scenes.{beat_name}", package=__package__)
    target_s = DURATIONS[beat_name]
    raw_path = OUT_DIR / f"_{beat_name}_raw.mp4"
    out_path = OUT_DIR / f"{beat_name}.mp4"

    # Phase 1: capture exactly target_s of phrase content.
    # The scene calls on_setup_done() AFTER navigation + initial scroll
    # but BEFORE the first phrase fires. We start ffmpeg in that callback,
    # so capture aligns precisely with phrase 1's start. No trim drift.
    async with XvfbRecorder(raw_path, viewport=(VIEWPORT_WIDTH, VIEWPORT_HEIGHT)) as rec:
        page = await rec.new_page()
        await page.add_init_script(
            "document.documentElement.style.backgroundColor = '#0b1020';"
            "document.documentElement.style.color = '#f8fafc';"
        )
        from .config import SITE_URL as _SITE
        await page.goto(_SITE)
        await page.wait_for_load_state("domcontentloaded")
        await asyncio.sleep(1.0)

        async def _on_setup_done() -> None:
            # Tiny settle so the first frame captured is the page in its
            # post-scroll state, not mid-scroll-animation.
            await asyncio.sleep(0.4)
            await rec.start_capture(duration_s=target_s)

        await scene_module.record(page, on_setup_done=_on_setup_done)
        await rec.wait_capture()

    # Phase 2: apply zoom + re-encode. No trim needed since capture is
    # already exactly target_s aligned to phrase start.
    subprocess.run(
        ["ffmpeg", "-y", "-i", str(raw_path),
         "-t", f"{target_s:.3f}",
         "-vf", ZOOM_FILTER,
         "-c:v", "libx264", "-preset", "medium", "-crf", "18",
         "-pix_fmt", "yuv420p",
         "-color_range", "tv", "-colorspace", "bt709",
         "-color_trc", "bt709", "-color_primaries", "bt709",
         "-an", str(out_path)],
        check=True,
    )
    raw_path.unlink(missing_ok=True)
    return out_path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("beat", help="beat name, e.g. beat1_open")
    args = ap.parse_args()
    out = asyncio.run(_record(args.beat))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    sys.exit(main())
