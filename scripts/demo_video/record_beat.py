"""Record a single beat to MP4 via Playwright.

Usage:
    python -m scripts.demo_video.record_beat beat1_open
    python -m scripts.demo_video.record_beat beat2_architecture
    ...

Output: out/demo_video/<beat_name>.mp4 (transcoded from Playwright's webm).
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import shutil
import subprocess
import sys
from pathlib import Path

from playwright.async_api import async_playwright

from .config import OUT_DIR, VIEWPORT_WIDTH, VIEWPORT_HEIGHT, DURATIONS


async def _record(beat_name: str) -> Path:
    scene_module = importlib.import_module(f".scenes.{beat_name}", package=__package__)
    raw_dir = OUT_DIR / "_raw" / beat_name
    raw_dir.mkdir(parents=True, exist_ok=True)
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
                record_video_dir=str(raw_dir),
                record_video_size={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
            )
            # Kill chromium's white default background that flashes during
            # navigation gaps. Inject a dark stylesheet into every document
            # before any user JS runs.
            await context.add_init_script(
                # Dark default body color so chromium's white default does not
                # flash during navigation gaps. NO !important so the page's
                # own stylesheet (e.g. the dashboard's radial gradient) wins
                # once it loads. Inline-styled at documentElement so the
                # color applies BEFORE the body element exists.
                "document.documentElement.style.backgroundColor = '#0b1020';"
                "document.documentElement.style.color = '#f8fafc';"
            )
            page = await context.new_page()
            try:
                await scene_module.record(page)
            finally:
                await context.close()
                await browser.close()
        webms = list(raw_dir.glob("*.webm"))
        if not webms:
            raise RuntimeError(f"no webm produced in {raw_dir}")
        webm = webms[0]
        out_path = OUT_DIR / f"{beat_name}.mp4"
        # The recording always overshoots because page load + setup happens
        # inside the recording context. Trim to keep the LAST <target> seconds
        # so the final stable frame is preserved (load + early frames go).
        target_s = DURATIONS.get(beat_name, 0)
        if target_s > 0:
            probe = subprocess.run(
                ["ffprobe", "-v", "quiet", "-show_entries", "format=duration",
                 "-of", "csv=p=0", str(webm)],
                capture_output=True, text=True, check=True,
            )
            total_s = float(probe.stdout.strip())
            start_s = max(0.0, total_s - target_s)
            subprocess.run(
                ["ffmpeg", "-y", "-ss", f"{start_s:.3f}", "-i", str(webm),
                 "-t", f"{target_s:.3f}",
                 "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
                 "-pix_fmt", "yuv420p", "-an", str(out_path)],
                check=True,
            )
        else:
            subprocess.run(
                ["ffmpeg", "-y", "-i", str(webm),
                 "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
                 "-pix_fmt", "yuv420p", "-an", str(out_path)],
                check=True,
            )
        return out_path
    finally:
        shutil.rmtree(raw_dir, ignore_errors=True)


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
