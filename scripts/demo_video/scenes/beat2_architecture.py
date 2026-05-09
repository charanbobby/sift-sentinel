"""Beat 2: architecture page slow-scroll. 45 seconds.

The existing /site/architecture.html is dense (3870 lines). For this beat
we just slow-scroll past it; the voiceover carries the meaning.
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL, DURATIONS


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/site/architecture.html")
    await page.wait_for_load_state("networkidle")
    await asyncio.sleep(1)
    # Slow scroll to bottom over 43 seconds, leaving 1s pad each side.
    duration_s = DURATIONS["beat2_architecture"] - 2
    steps = duration_s * 4  # 4 scroll ticks per second for smoothness
    await page.evaluate(
        """async ({ steps, duration_ms }) => {
            const total = document.documentElement.scrollHeight - window.innerHeight;
            const stepPx = total / steps;
            const stepMs = duration_ms / steps;
            for (let i = 0; i <= steps; i++) {
                window.scrollTo(0, i * stepPx);
                await new Promise(r => setTimeout(r, stepMs));
            }
        }""",
        {"steps": steps, "duration_ms": duration_s * 1000},
    )
    await asyncio.sleep(1)
