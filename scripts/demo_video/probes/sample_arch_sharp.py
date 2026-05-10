"""Screenshot-per-phrase sample for Beat 2.

For each phrase of beat 2, set up the page state (scroll + highlight)
and take a LOSSLESS PNG screenshot. Assemble the PNGs into an MP4 with
per-phrase durations, no recording-pipeline blur.

Output: out/demo_video/sample_arch_screenshots.mp4 (15-second slice
covering 3 phrases so we can compare to recording-based approach).
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from playwright.async_api import async_playwright

from demo_video.config import SITE_URL, OUT_DIR, VIEWPORT_WIDTH, VIEWPORT_HEIGHT
from demo_video.scenes._helpers import highlight, unhighlight
from demo_video.phrases import phrases_for


async def main() -> int:
    snap_dir = OUT_DIR / "_screenshots"
    if snap_dir.exists():
        shutil.rmtree(snap_dir)
    snap_dir.mkdir(parents=True)
    # Take first 3 phrases of beat 2 for the sample.
    phrases = phrases_for("beat2_architecture")[:3]
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
                device_scale_factor=2,  # super-sample for sharper screenshots
            )
            page = await context.new_page()
            await page.goto(f"{SITE_URL}/site/architecture.html")
            await page.wait_for_load_state("domcontentloaded")
            await page.evaluate(
                """() => {
                    const h2 = Array.from(document.querySelectorAll('h2'))
                        .find(h => h.textContent.includes('Five trust controls'));
                    if (h2) h2.scrollIntoView({behavior: 'instant', block: 'start'});
                }"""
            )
            await asyncio.sleep(0.6)
            for i, ph in enumerate(phrases):
                if ph["selector"]:
                    await highlight(page, ph["selector"])
                    await asyncio.sleep(0.4)  # let scroll settle
                snap = snap_dir / f"phrase_{i:03d}.png"
                await page.screenshot(path=str(snap), full_page=False)
                if ph["selector"]:
                    await unhighlight(page, ph["selector"])
            await context.close()
            await browser.close()

        # Build concat list: each PNG held for its phrase duration.
        list_path = snap_dir / "concat.txt"
        lines = []
        for i, ph in enumerate(phrases):
            png = (snap_dir / f"phrase_{i:03d}.png").as_posix()
            lines.append(f"file '{png}'")
            lines.append(f"duration {ph['duration_s']}")
        # ffmpeg concat demuxer needs the last file repeated WITHOUT duration
        last_png = (snap_dir / f"phrase_{len(phrases)-1:03d}.png").as_posix()
        lines.append(f"file '{last_png}'")
        list_path.write_text("\n".join(lines), encoding="utf-8")

        out_path = OUT_DIR / "sample_arch_screenshots.mp4"
        # Encode PNG sequence directly to H.264. Source is lossless, so
        # CRF 18 + medium preset gives a near-pristine MP4. Force 30fps
        # output by re-timing the concat.
        subprocess.run(
            ["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(list_path),
             "-vf", f"scale={VIEWPORT_WIDTH}:{VIEWPORT_HEIGHT}:flags=lanczos,fps=30",
             "-c:v", "libx264", "-preset", "medium", "-crf", "18",
             "-pix_fmt", "yuv420p",
             "-color_range", "tv", "-colorspace", "bt709",
             "-color_trc", "bt709", "-color_primaries", "bt709",
             str(out_path)],
            check=True,
        )
        print(f"wrote {out_path}")
        return 0
    finally:
        # Keep snap_dir for debug; remove only on next run.
        pass


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
