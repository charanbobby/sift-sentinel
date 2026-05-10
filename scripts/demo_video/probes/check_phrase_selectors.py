"""Pre-flight check that every PHRASES selector resolves to a real DOM
element on the target page. Run before recording so misses do not waste
recording time.

Each beat is checked against the page that beat will record. SPA pages
(viewer, dashboard) are loaded fresh for each beat.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from playwright.async_api import async_playwright

from demo_video.config import (
    SITE_URL, CASE_ID, RUN_ID, SECOND_CASE_ID, SECOND_RUN_ID,
    RULE_ID_FOR_PROMOTE,
)
from demo_video.phrases import PHRASES, phrases_for


_FIND_EL_JS = """
(s) => {
    const m = s.match(/^(.*?):has-text\\('(.+?)'\\)(.*)$/);
    if (!m) return !!document.querySelector(s);
    const [_, base, text, after] = m;
    const candidates = base ? document.querySelectorAll(base) : document.querySelectorAll('*');
    for (const el of candidates) {
        if ((el.textContent || '').includes(text)) {
            if (after) {
                if (el.querySelector(after.replace(/^\\s+/, ''))) return true;
            } else {
                return true;
            }
        }
    }
    return false;
}
"""


async def _setup_for_beat(page, beat: str) -> None:
    if beat == "beat1_open":
        await page.goto(f"{SITE_URL}/site/dashboard.html")
        await page.wait_for_load_state("networkidle")
    elif beat == "beat2_architecture":
        await page.goto(f"{SITE_URL}/site/architecture.html")
        await page.wait_for_load_state("domcontentloaded")
        # Expand all collapsed topology sections so inner rows are queryable.
        await page.evaluate(
            "() => document.querySelectorAll('.topology-section.collapsible.collapsed .rsec-head').forEach(h => h.click())"
        )
        await asyncio.sleep(0.4)
    elif beat == "beat3_case":
        await page.goto(f"{SITE_URL}/viewer/")
        await page.wait_for_load_state("domcontentloaded")
        await page.wait_for_function("() => typeof toggleCase === 'function'")
        # Wait for the case catalogue to populate so toggleCase can find the row.
        await page.wait_for_function(
            f"() => document.querySelector('.case-header') && Array.from(document.querySelectorAll('.case-header')).some(h => h.textContent.includes('{CASE_ID}'))",
            timeout=15000,
        )
        await page.evaluate(f"toggleCase('{CASE_ID}')")
        await asyncio.sleep(0.5)
        await page.evaluate(f"loadRun('{CASE_ID}', '{RUN_ID}')")
        await asyncio.sleep(1.5)
        # also pre-toggle the second case so file-server selectors resolve
        await page.evaluate(f"toggleCase('{SECOND_CASE_ID}')")
        await asyncio.sleep(0.5)
    elif beat == "beat4_loop":
        await page.goto(f"{SITE_URL}/site/dashboard.html")
        await page.wait_for_load_state("networkidle")
        await page.wait_for_function(
            "() => document.querySelectorAll('[id^=\"rule-card-\"]').length > 0"
        )
    elif beat == "beat5_outro":
        # End card is local file; selectors against generic .name + .row.
        from pathlib import Path as _P
        card = _P(__file__).resolve().parents[1] / "scenes" / "end_card.html"
        await page.goto(f"file:///{card.as_posix()}")
        await page.wait_for_load_state("networkidle")


async def main() -> int:
    misses_by_beat: dict[str, list[str]] = {}
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        for beat in ["beat1_open", "beat2_architecture", "beat3_case", "beat4_loop", "beat5_outro"]:
            page = await (await browser.new_context()).new_page()
            await _setup_for_beat(page, beat)
            for phrase in phrases_for(beat):
                sel = phrase["selector"]
                if not sel:
                    continue
                # Selector may be a string OR a list (multi-element). Normalize.
                sel_list = sel if isinstance(sel, list) else [sel]
                first_sel = sel_list[0]
                # For beat3, switch tabs as needed before checking the selector.
                if beat == "beat3_case":
                    if first_sel.startswith("[data-tab='evidence']") or first_sel.startswith(".ev-record"):
                        await page.evaluate('document.querySelector(\'[data-tab="evidence"]\')?.click()')
                        await asyncio.sleep(0.3)
                    elif first_sel.startswith("[data-tab='pipeline']") or first_sel.startswith(".phase-"):
                        await page.evaluate('document.querySelector(\'[data-tab="pipeline"]\')?.click()')
                        await asyncio.sleep(0.3)
                    elif "srl-2018-base-file" in first_sel:
                        # Switch back to findings + load second run for these selectors
                        await page.evaluate('document.querySelector(\'[data-tab="findings"]\')?.click()')
                        await asyncio.sleep(0.2)
                        await page.evaluate(f"loadRun('{SECOND_CASE_ID}', '{SECOND_RUN_ID}')")
                        await asyncio.sleep(1.0)
                for one in sel_list:
                    found = await page.evaluate(_FIND_EL_JS, one)
                    if not found:
                        misses_by_beat.setdefault(beat, []).append(one + "   (phrase: " + phrase["text"][:60] + ")")
            await page.close()
        await browser.close()

    if misses_by_beat:
        print("FAIL: some selectors did not resolve:")
        for beat, misses in misses_by_beat.items():
            print(f"  {beat}:")
            for m in misses:
                print(f"    - {m}")
        return 1
    print("ALL PHRASE SELECTORS RESOLVE.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
