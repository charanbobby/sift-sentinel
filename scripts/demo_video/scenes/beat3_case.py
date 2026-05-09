"""Beat 3: case walkthrough. 180 seconds.

Four sub-beats inside one recording:
  3a (0-30s): findings overview at /viewer/ for rd-02-dual
  3b (30-75s): audit trail trace, click two cited tool_call_ids
  3c (75-135s): critic disagreement section, INJECTION_QUARANTINE
  3d (135-180s): cross-host corroboration on srl-2018-base-file
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL, CASE_ID, RUN_ID, SECOND_CASE_ID, SECOND_RUN_ID


async def _wait(s: float) -> None:
    await asyncio.sleep(s)


async def record(page: Page) -> None:
    # 3a: findings overview (0 - 30s)
    await page.goto(f"{SITE_URL}/viewer/?case={CASE_ID}&run={RUN_ID}")
    await page.wait_for_load_state("networkidle")
    await _wait(2)
    await page.evaluate("window.scrollTo({ top: 200, behavior: 'smooth' })")
    await _wait(4)
    await page.evaluate("document.querySelectorAll('[data-finding-card]')[0]?.scrollIntoView({behavior:'smooth', block:'center'})")
    await _wait(8)
    # Hover the high-confidence pill on finding 0
    pill = page.locator('[data-finding-card]').first.locator('.pill-red, .pill-amber, [class*="confidence"]').first
    try:
        await pill.hover(timeout=3000)
    except Exception:
        pass
    await _wait(15)  # total 30

    # 3b: audit trail trace (30 - 75s)
    # Click the first cited tool_call_id of finding 0
    await page.evaluate("""
        const card = document.querySelectorAll('[data-finding-card]')[0];
        if (card) {
            const cite = card.querySelector('a[href*="tool_call_id"], [data-tool-call-id]');
            if (cite) cite.click();
        }
    """)
    await _wait(2)
    await page.evaluate("window.scrollBy({ top: 400, behavior: 'smooth' })")
    await _wait(8)
    await page.evaluate("history.back()")
    await page.wait_for_load_state("networkidle")
    await _wait(2)
    # Second citation
    await page.evaluate("""
        const card = document.querySelectorAll('[data-finding-card]')[0];
        if (card) {
            const cites = card.querySelectorAll('a[href*="tool_call_id"], [data-tool-call-id]');
            if (cites[1]) cites[1].click();
        }
    """)
    await _wait(2)
    await page.evaluate("window.scrollBy({ top: 600, behavior: 'smooth' })")
    await _wait(15)
    await page.evaluate("history.back()")
    await page.wait_for_load_state("networkidle")
    await _wait(11)  # cumulative 75

    # 3c: critic disagreement (75 - 135s)
    await page.evaluate("document.querySelector('[data-section=\"critic\"], #critic-section')?.scrollIntoView({behavior:'smooth'})")
    await _wait(8)
    # Pan slowly through the critic events area
    for _ in range(10):
        await page.evaluate("window.scrollBy({ top: 80, behavior: 'smooth' })")
        await _wait(5)
    await _wait(2)  # cumulative 135

    # 3d: cross-host corroboration (135 - 180s)
    await page.goto(f"{SITE_URL}/viewer/?case={SECOND_CASE_ID}&run={SECOND_RUN_ID}")
    await page.wait_for_load_state("networkidle")
    await _wait(3)
    await page.evaluate("""
        const txt = 'Microsoft Advanced API';
        const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
        let node;
        while (node = walk.nextNode()) {
            if (node.nodeValue && node.nodeValue.includes(txt)) {
                node.parentElement.scrollIntoView({behavior:'smooth', block:'center'});
                node.parentElement.style.outline = '2px solid #34d399';
                break;
            }
        }
    """)
    await _wait(42)  # cumulative 180
