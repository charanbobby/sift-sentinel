"""Beat 2: architecture page. 45s, 9 phrases, each pointing at a named
"Five trust controls" / "deep dive" element on /site/architecture.html.
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL
from ..phrases import phrases_for
from ._helpers import highlight, unhighlight


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/site/architecture.html")
    await page.wait_for_load_state("domcontentloaded")
    # Land on the "Five trust controls" section to set the visual context.
    await page.evaluate(
        """() => {
            const h2 = Array.from(document.querySelectorAll('h2'))
                .find(h => h.textContent.includes('Five trust controls'));
            if (h2) h2.scrollIntoView({behavior: 'instant', block: 'start'});
        }"""
    )
    await asyncio.sleep(0.4)
    for phrase in phrases_for("beat2_architecture"):
        if phrase["selector"]:
            await highlight(page, phrase["selector"])
        await asyncio.sleep(phrase["duration_s"])
        if phrase["selector"]:
            await unhighlight(page, phrase["selector"])
