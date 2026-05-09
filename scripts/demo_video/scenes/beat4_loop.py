"""Beat 4: loop closing. 45s, 9 phrases. At the "click approve" phrase the
scene calls openApproveModal + confirmPromote on the live dashboard.
SIDE EFFECT: actually promotes RULE_ID_FOR_PROMOTE on the live store.
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL, RULE_ID_FOR_PROMOTE
from ..phrases import phrases_for
from ._helpers import highlight, unhighlight


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/site/dashboard.html?cb=demo-beat4")
    await page.wait_for_load_state("networkidle")
    await page.wait_for_function(
        "() => document.querySelectorAll('[id^=\"rule-card-\"]').length > 0"
    )
    # Scroll past hero into the drafted-rules section so the widgets are in
    # view for the first phrases.
    await page.evaluate(
        """() => {
            const target = document.getElementById('section-rules');
            if (target) target.scrollIntoView({behavior: 'instant', block: 'start'});
        }"""
    )
    await asyncio.sleep(0.4)

    for phrase in phrases_for("beat4_loop"):
        text = phrase["text"]

        # When the narrator says "I read one, decide it is safe, click approve"
        # actually scroll to the rule card. When the narrator says "The rule is
        # now in the live agent's rule store", actually open + confirm the modal.
        if text.startswith("I read one"):
            await page.evaluate(
                f"document.getElementById('rule-card-{RULE_ID_FOR_PROMOTE}')"
                f"?.scrollIntoView({{behavior: 'smooth', block: 'center'}})"
            )
            await asyncio.sleep(0.5)
        elif text.startswith("The rule is now"):
            await page.evaluate(f"openApproveModal('{RULE_ID_FOR_PROMOTE}', CURRENT_DATE)")
            await asyncio.sleep(0.6)
            await page.evaluate(f"confirmPromote('{RULE_ID_FOR_PROMOTE}', CURRENT_DATE)")
            await asyncio.sleep(0.4)

        if phrase["selector"]:
            await highlight(page, phrase["selector"])
        await asyncio.sleep(phrase["duration_s"])
        if phrase["selector"]:
            await unhighlight(page, phrase["selector"])
