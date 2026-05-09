"""Beat 4: loop closing live. 45 seconds.

Scrolls past the hero + widgets to the drafted-rules section, hovers the
locked rule card, clicks Approve, confirms in the modal. The card disappears,
queued widget decrements, live widget increments. Recording captures the
state change in real time.

SIDE EFFECT: this actually promotes the rule in the live store. The
RULE_ID_FOR_PROMOTE in config.py is consumed by this run; pick a fresh
rule before re-recording.
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL, RULE_ID_FOR_PROMOTE


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/site/dashboard.html?cb=demo-beat4")
    await page.wait_for_load_state("networkidle")
    await page.wait_for_function(
        "() => document.querySelectorAll('[id^=\"rule-card-\"]').length > 0"
    )
    await asyncio.sleep(2)
    # Slow scroll past hero + widgets down to drafted-rules section
    await page.evaluate(
        """async () => {
            const target = document.getElementById('section-rules');
            const top = target.getBoundingClientRect().top + window.scrollY;
            const start = window.scrollY;
            const steps = 60;
            for (let i = 0; i <= steps; i++) {
                window.scrollTo(0, start + (top - start) * (i / steps));
                await new Promise(r => setTimeout(r, 100));
            }
        }"""
    )
    await asyncio.sleep(2)
    # Scroll the locked rule into view
    rule_id = RULE_ID_FOR_PROMOTE
    await page.evaluate(
        f"document.getElementById('rule-card-{rule_id}')?.scrollIntoView("
        f"{{behavior:'smooth', block:'center'}})"
    )
    await asyncio.sleep(3)
    # Click Approve
    await page.evaluate(f"openApproveModal('{rule_id}', CURRENT_DATE)")
    await asyncio.sleep(4)
    # Click Yes, promote
    await page.evaluate(f"confirmPromote('{rule_id}', CURRENT_DATE)")
    await asyncio.sleep(2)
    # Settle on the new widget counts
    await asyncio.sleep(11)
