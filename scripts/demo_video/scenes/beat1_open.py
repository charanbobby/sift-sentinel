"""Beat 1: cold open. Dashboard hero held static for 15 seconds.

The hero shows 'Last night (2026-05-08), Sentinel ran. Tonight it gets better.'
plus the 4-widget board. Static frame for 2 seconds, then continues holding
for the remaining 13 seconds while the voiceover plays in Phase F.
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL, DURATIONS


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/site/dashboard.html?cb=demo")
    await page.wait_for_load_state("networkidle")
    # Wait for /api/status + /api/proposed-rules to populate
    await page.wait_for_function(
        "() => document.getElementById('w-queued-num')?.textContent !== ','"
    )
    await asyncio.sleep(DURATIONS["beat1_open"])
