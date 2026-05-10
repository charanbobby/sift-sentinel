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
from ._helpers import highlight, unhighlight, highlight_many, unhighlight_many, reset_phrase_clock, sleep_until_phrase_end


async def record(page: Page, on_setup_done=None) -> None:
    await page.goto(f"{SITE_URL}/viewer/")
    await page.wait_for_load_state("domcontentloaded")
    await page.wait_for_function(
        "() => typeof toggleCase === 'function' && typeof loadRun === 'function'"
    )
    await asyncio.sleep(0.4)
    if on_setup_done is not None:
        await on_setup_done()
    reset_phrase_clock()
    cumulative = 0.0

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
        elif text.startswith("And the C2 beacon"):
            # We left the Findings tab back at "Click the citation" to show
            # raw evidence. The C2 phrase points at the .finding.cls-c2_beacon
            # card, which only renders on the Findings tab; switch back so
            # the highlight has something to land on.
            await page.evaluate('document.querySelector(\'[data-tab="findings"]\')?.click()')
            await asyncio.sleep(0.3)
        elif text.startswith("Now the self-correction"):
            await page.evaluate('document.querySelector(\'[data-tab="pipeline"]\')?.click()')
            await asyncio.sleep(0.3)
        elif text.startswith("One of those rules"):
            # Open the rule reference details and scroll the R_16 card into
            # view so the highlight on #rule-R_16 lands on a visible element.
            # The phrase narrates "catches attackers using AI themselves" while
            # we point at the actual R_16 entry in the rule reference.
            await page.evaluate(
                """() => {
                    const d = document.getElementById('rule-reference-details');
                    if (d && !d.open) d.open = true;
                    const t = document.getElementById('rule-R_16');
                    if (t) t.scrollIntoView({behavior: 'smooth', block: 'center'});
                }"""
            )
            await asyncio.sleep(0.5)
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

        sel = phrase["selector"]
        if sel:
            if isinstance(sel, list):
                await highlight_many(page, sel)
            else:
                await highlight(page, sel)
        cumulative += phrase["duration_s"]
        await sleep_until_phrase_end(cumulative)
        if sel:
            if isinstance(sel, list):
                await unhighlight_many(page, sel)
            else:
                await unhighlight(page, sel)
