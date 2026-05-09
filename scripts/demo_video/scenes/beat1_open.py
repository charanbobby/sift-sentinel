"""Beat 1: cold open. 15s. Static dashboard hero hold; 3 phrases, no
selectors (purely a visual hook, narrator carries the story).
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL
from ..phrases import phrases_for
from ._helpers import highlight, unhighlight


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/site/dashboard.html?cb=demo")
    await page.wait_for_load_state("networkidle")
    await page.wait_for_function(
        "() => document.getElementById('w-queued-num')?.textContent !== ','"
    )
    for phrase in phrases_for("beat1_open"):
        if phrase["selector"]:
            await highlight(page, phrase["selector"])
        await asyncio.sleep(phrase["duration_s"])
        if phrase["selector"]:
            await unhighlight(page, phrase["selector"])
