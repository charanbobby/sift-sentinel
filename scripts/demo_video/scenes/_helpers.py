"""Shared helpers for per-phrase Playwright scenes.

highlight() draws an outlined box around the first element matching `selector`.
unhighlight() removes the box. Both are no-ops if the selector does not match.
"""
from __future__ import annotations

from playwright.async_api import Page


HIGHLIGHT_COLOR = "#60a5fa"  # blue, matches dashboard accent
HIGHLIGHT_WIDTH_PX = 3
HIGHLIGHT_OUTLINE_OFFSET_PX = 4


_FIND_EL_JS = """
const findEl = (s) => {
    const m = s.match(/^(.*?):has-text\\('(.+?)'\\)(.*)$/);
    if (!m) return document.querySelector(s);
    const [_, base, text, after] = m;
    const candidates = base ? document.querySelectorAll(base) : document.querySelectorAll('*');
    for (const el of candidates) {
        if ((el.textContent || '').includes(text)) {
            if (after) {
                const child = el.querySelector(after.replace(/^\\s+/, ''));
                if (child) return child;
            } else {
                return el;
            }
        }
    }
    return null;
};
const findAll = (s) => {
    const m = s.match(/^(.*?):has-text\\('(.+?)'\\)(.*)$/);
    if (!m) return Array.from(document.querySelectorAll(s));
    const [_, base, text, after] = m;
    const candidates = base ? document.querySelectorAll(base) : document.querySelectorAll('*');
    const out = [];
    for (const el of candidates) {
        if ((el.textContent || '').includes(text)) {
            if (after) {
                const child = el.querySelector(after.replace(/^\\s+/, ''));
                if (child) out.push(child);
            } else {
                out.push(el);
            }
        }
    }
    return out;
};
"""


async def highlight(page: Page, selector: str) -> bool:
    """Draw an outlined box around the first element matching `selector`.
    Returns True if found and styled, False otherwise. Does not raise.
    """
    return await page.evaluate(
        _FIND_EL_JS + """({sel, color, width, offset}) => {
            const el = findEl(sel);
            if (!el) return false;
            el.scrollIntoView({behavior: 'smooth', block: 'center'});
            el.dataset._origCss = el.style.cssText;
            el.style.outline = width + 'px solid ' + color;
            el.style.outlineOffset = offset + 'px';
            el.style.borderRadius = '4px';
            el.style.transition = 'outline 0.2s ease-in';
            return true;
        }""",
        {"sel": selector, "color": HIGHLIGHT_COLOR, "width": HIGHLIGHT_WIDTH_PX, "offset": HIGHLIGHT_OUTLINE_OFFSET_PX},
    )


async def unhighlight(page: Page, selector: str) -> None:
    """Remove the outline from a previously highlighted element. Safe to
    call even if the highlight did not land (no-op).
    """
    await page.evaluate(
        _FIND_EL_JS + """(sel) => {
            const el = findEl(sel);
            if (!el) return;
            const orig = el.dataset._origCss;
            if (orig !== undefined) {
                el.style.cssText = orig;
                delete el.dataset._origCss;
            } else {
                el.style.outline = '';
                el.style.outlineOffset = '';
            }
        }""",
        selector,
    )


async def highlight_many(page: Page, selectors: list[str]) -> int:
    """Highlight ALL elements matching ANY of the given selectors.
    Each element gets the outline; the first matched element is scrolled
    into view. Returns count of elements highlighted. Used for phrases
    that name multiple things at once (e.g. both msadvapi findings, or
    critic + interpret rows together).
    """
    return await page.evaluate(
        _FIND_EL_JS + """({sels, color, width, offset}) => {
            let count = 0;
            let firstEl = null;
            for (const s of sels) {
                for (const el of findAll(s)) {
                    if (!firstEl) firstEl = el;
                    el.dataset._origCss = el.style.cssText;
                    el.style.outline = width + 'px solid ' + color;
                    el.style.outlineOffset = offset + 'px';
                    el.style.borderRadius = '4px';
                    el.style.transition = 'outline 0.2s ease-in';
                    count++;
                }
            }
            if (firstEl) firstEl.scrollIntoView({behavior: 'smooth', block: 'center'});
            return count;
        }""",
        {"sels": selectors, "color": HIGHLIGHT_COLOR, "width": HIGHLIGHT_WIDTH_PX, "offset": HIGHLIGHT_OUTLINE_OFFSET_PX},
    )


async def unhighlight_many(page: Page, selectors: list[str]) -> None:
    """Remove outlines from elements highlighted by highlight_many."""
    await page.evaluate(
        _FIND_EL_JS + """(sels) => {
            for (const s of sels) {
                for (const el of findAll(s)) {
                    const orig = el.dataset._origCss;
                    if (orig !== undefined) {
                        el.style.cssText = orig;
                        delete el.dataset._origCss;
                    } else {
                        el.style.outline = '';
                        el.style.outlineOffset = '';
                    }
                }
            }
        }""",
        selectors,
    )
