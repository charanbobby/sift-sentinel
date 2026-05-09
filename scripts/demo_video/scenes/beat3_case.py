"""Beat 3: case walkthrough. 180s, 34 phrases.

The viewer is a single-page app driven by toggleCase() and loadRun(). At
specific phrase boundaries the scene calls those functions (or clicks tabs)
to advance the SPA state, then the highlight on the next phrase points at
the newly-rendered element.
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL, CASE_ID, RUN_ID, SECOND_CASE_ID, SECOND_RUN_ID
from ..phrases import phrases_for
from ._helpers import highlight, unhighlight


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/viewer/")
    await page.wait_for_load_state("domcontentloaded")
    await page.wait_for_function(
        "() => typeof toggleCase === 'function' && typeof loadRun === 'function'"
    )
    await asyncio.sleep(0.4)

    for phrase in phrases_for("beat3_case"):
        text = phrase["text"]

        # SPA state intercepts BEFORE drawing the highlight on this phrase.
        if text.startswith("The case:"):
            await page.evaluate(f"toggleCase('{CASE_ID}')")
            await asyncio.sleep(0.3)
            await page.evaluate(f"loadRun('{CASE_ID}', '{RUN_ID}')")
            try:
                await page.wait_for_function(
                    "() => document.querySelectorAll('.finding').length >= 2",
                    timeout=10000,
                )
            except Exception:
                pass
            await asyncio.sleep(0.3)
        elif text.startswith("Click the citation"):
            await page.evaluate('document.querySelector(\'[data-tab="evidence"]\')?.click()')
            await asyncio.sleep(0.3)
        elif text.startswith("Now the self-correction"):
            await page.evaluate('document.querySelector(\'[data-tab="pipeline"]\')?.click()')
            await asyncio.sleep(0.3)
        elif text.startswith("One more thing"):
            # Switch back to Findings tab so the next loadRun lands clean.
            await page.evaluate('document.querySelector(\'[data-tab="findings"]\')?.click()')
            await asyncio.sleep(0.2)
            await page.evaluate(f"toggleCase('{SECOND_CASE_ID}')")
            await asyncio.sleep(0.3)
            await page.evaluate(f"loadRun('{SECOND_CASE_ID}', '{SECOND_RUN_ID}')")
            try:
                await page.wait_for_function(
                    "() => document.querySelectorAll('.finding').length >= 1",
                    timeout=10000,
                )
            except Exception:
                pass
            await asyncio.sleep(0.3)

        if phrase["selector"]:
            await highlight(page, phrase["selector"])
        await asyncio.sleep(phrase["duration_s"])
        if phrase["selector"]:
            await unhighlight(page, phrase["selector"])
