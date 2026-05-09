"""Beat 5: outro end-card. 15 seconds.

Static frame: project name, live URL, code URL, author. Hold for 15s.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from playwright.async_api import Page

from ..config import DURATIONS

CARD = Path(__file__).resolve().parent / "end_card.html"


async def record(page: Page) -> None:
    await page.goto(f"file:///{CARD.as_posix()}")
    await page.wait_for_load_state("networkidle")
    await asyncio.sleep(DURATIONS["beat5_outro"])
