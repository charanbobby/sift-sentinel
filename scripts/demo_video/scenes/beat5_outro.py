"""Beat 5: outro end-card. 15s, 4 phrases pointing at the URL rows.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from playwright.async_api import Page

from ..phrases import phrases_for
from ._helpers import highlight, unhighlight, reset_phrase_clock, sleep_until_phrase_end

CARD = Path(__file__).resolve().parent / "end_card.html"


async def record(page: Page, on_setup_done=None) -> None:
    await page.goto(f"file:///{CARD.as_posix()}")
    await page.wait_for_load_state("networkidle")
    if on_setup_done is not None:
        await on_setup_done()
    reset_phrase_clock()
    cumulative = 0.0
    for phrase in phrases_for("beat5_outro"):
        if phrase["selector"]:
            await highlight(page, phrase["selector"])
        cumulative += phrase["duration_s"]
        await sleep_until_phrase_end(cumulative)
        if phrase["selector"]:
            await unhighlight(page, phrase["selector"])
