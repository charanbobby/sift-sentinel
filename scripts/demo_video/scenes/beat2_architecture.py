"""Beat 2: architecture page. 60s, 12 phrases walking the Full deployment
topology panel on /site/architecture.html.

The topology section's collapsible cards are expanded so highlights can
land on the agent box, mcp box, attack-surface row, capability-token row,
and the "how the two are connected" rows below. Font sizes inside the
topology section are bumped via CSS injection (real DOM-level rule, not
zoom) so the small native fonts read on video.
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL
from ..phrases import phrases_for
from ._helpers import highlight, unhighlight, highlight_many, unhighlight_many


async def record(page: Page, on_setup_done=None) -> None:
    await page.goto(f"{SITE_URL}/site/architecture.html")
    await page.wait_for_load_state("domcontentloaded")
    # Expand every collapsed topology section so the inner rows are
    # in the DOM and visible for highlight().
    await page.evaluate(
        """() => {
            const heads = document.querySelectorAll('.topology-section.collapsible.collapsed .rsec-head');
            heads.forEach(h => h.click());
        }"""
    )
    await asyncio.sleep(0.5)
    # Bump the topology section's font sizes so the rows are readable on
    # video. Real CSS rule (not zoom): subpixel hinting is preserved.
    await page.add_style_tag(content="""
        .topology-section .pb-body { font-size: 18px !important; line-height: 1.55 !important; }
        .topology-section .pb-label { font-size: 14px !important; line-height: 1.45 !important; letter-spacing: 0.04em !important; }
        .topology-section .process-title { font-size: 24px !important; }
        .topology-section .mono-inline,
        .topology-section .chip,
        .topology-section code { font-size: 16px !important; }
        .topology-section .pb-status-off { font-size: 18px !important; padding: 4px 12px !important; }
        .shared-label { font-size: 16px !important; letter-spacing: 0.04em !important; }
        .shared-row, .shared-row * { font-size: 17px !important; line-height: 1.55 !important; }
        .shared-row .detail { font-size: 15px !important; }
        .subtitle { font-size: 18px !important; }
        h2 { font-size: 32px !important; }
    """)
    await asyncio.sleep(0.3)
    # Land on the topology header to set the visual context.
    await page.evaluate(
        """() => {
            const h2 = Array.from(document.querySelectorAll('h2'))
                .find(h => h.textContent.includes('Full deployment topology'));
            if (h2) h2.scrollIntoView({behavior: 'instant', block: 'start'});
        }"""
    )
    await asyncio.sleep(0.4)
    if on_setup_done is not None:
        await on_setup_done()
    for phrase in phrases_for("beat2_architecture"):
        # Mid-beat scroll: when transitioning to "how the two are connected"
        # subsection, scroll down so the rows below are visible.
        if phrase["text"].startswith("Below the topology"):
            await page.evaluate(
                """() => {
                    const lab = Array.from(document.querySelectorAll('.shared-label'))
                        .find(s => s.textContent.includes('how the two are connected'));
                    if (lab) lab.scrollIntoView({behavior: 'smooth', block: 'center'});
                }"""
            )
            await asyncio.sleep(0.3)
        # Pipeline section: scroll up to "The pipeline" h2 when this subbeat starts.
        if phrase["text"].startswith("Now, how the agent actually runs"):
            await page.evaluate(
                """() => {
                    const h2 = Array.from(document.querySelectorAll('h2'))
                        .find(h => h.textContent.includes('The pipeline'));
                    if (h2) h2.scrollIntoView({behavior: 'smooth', block: 'start'});
                }"""
            )
            await asyncio.sleep(0.4)
        sel = phrase["selector"]
        if sel:
            if isinstance(sel, list):
                await highlight_many(page, sel)
            else:
                await highlight(page, sel)
        await asyncio.sleep(phrase["duration_s"])
        if sel:
            if isinstance(sel, list):
                await unhighlight_many(page, sel)
            else:
                await unhighlight(page, sel)
