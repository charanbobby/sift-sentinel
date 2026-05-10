"""Verify XvfbRecorder works end-to-end on the architecture page.
Output: out/demo_video/probe_xvfb_recorder.mp4 (10 seconds, with zoom-in).
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from demo_video.config import OUT_DIR, SITE_URL
from demo_video.xvfb_recorder import XvfbRecorder


async def main() -> int:
    out_path = OUT_DIR / "probe_xvfb_recorder.mp4"
    # Snappy zoom: ramp from 1.0x to 1.3x in ~2 seconds (60 frames at 30fps),
    # then hold. d=60 means each zoompan input frame produces 60 output
    # frames; with z increment 0.005, zoom hits 1.3 in 60 frames = 2s.
    zoom_filter = (
        "zoompan=z='min(zoom+0.005,1.3)':"
        "x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':"
        "d=300:s=1920x1080:fps=30"
    )
    async with XvfbRecorder(out_path, zoom_filter=zoom_filter) as rec:
        page = await rec.new_page()
        await page.goto(f"{SITE_URL}/site/architecture.html")
        await page.wait_for_load_state("domcontentloaded")
        # Scroll to Five trust controls before capture.
        await page.evaluate(
            """() => {
                const h2 = Array.from(document.querySelectorAll('h2'))
                    .find(h => h.textContent.includes('Five trust controls'));
                if (h2) h2.scrollIntoView({behavior: 'instant', block: 'start'});
            }"""
        )
        await asyncio.sleep(1.5)
        await rec.start_capture(duration_s=10.0)
        await asyncio.sleep(10.5)  # let ffmpeg finish
        await rec.wait_capture()
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
