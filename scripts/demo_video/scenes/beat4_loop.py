"""Beat 4: loop closing. 45s, 9 phrases. At the "click approve" phrase the
scene calls openApproveModal + confirmPromote on the live dashboard.
SIDE EFFECT: actually promotes RULE_ID_FOR_PROMOTE on the live store.
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL, RULE_ID_FOR_PROMOTE
from ..phrases import phrases_for
from ._helpers import highlight, unhighlight, reset_phrase_clock, sleep_until_phrase_end


async def record(page: Page, on_setup_done=None) -> None:
    await page.goto(f"{SITE_URL}/site/dashboard.html?cb=demo-beat4")
    await page.wait_for_load_state("domcontentloaded")
    await page.wait_for_function(
        "() => document.querySelectorAll('[id^=\"rule-card-\"]').length > 0",
        timeout=10000,
    )
    # Pick the FIRST currently-queued rule at runtime so we never go stale.
    # (Every recording promotes the picked rule, removing it from the queue.)
    rule_id_full = await page.evaluate(
        "() => document.querySelector('[id^=\"rule-card-\"]')?.id"
    )
    rule_id = rule_id_full.replace("rule-card-", "") if rule_id_full else None
    if not rule_id:
        raise RuntimeError("no queued rule cards found on dashboard")

    # Scroll past hero into the drafted-rules section so the widgets are in
    # view for the first phrases.
    await page.evaluate(
        """() => {
            const target = document.getElementById('section-rules');
            if (target) target.scrollIntoView({behavior: 'instant', block: 'start'});
        }"""
    )
    await asyncio.sleep(0.4)
    if on_setup_done is not None:
        await on_setup_done()
    reset_phrase_clock()
    cumulative = 0.0

    for phrase in phrases_for("beat4_loop"):
        text = phrase["text"]

        # When the narrator says "I read one, decide it is safe, click approve"
        # actually scroll to the rule card. When the narrator says "The rule is
        # now in the live agent's rule store", actually open + confirm the modal.
        if text.startswith("I read one"):
            await page.evaluate(
                f"document.getElementById('rule-card-{rule_id}')"
                f"?.scrollIntoView({{behavior: 'smooth', block: 'center'}})"
            )
        elif text.startswith("The rule is now"):
            await page.evaluate(f"openApproveModal('{rule_id}', CURRENT_DATE)")
            await page.evaluate(f"confirmPromote('{rule_id}', CURRENT_DATE)")

        if phrase["selector"]:
            await highlight(page, phrase["selector"])
        cumulative += phrase["duration_s"]
        await sleep_until_phrase_end(cumulative)
        if phrase["selector"]:
            await unhighlight(page, phrase["selector"])
