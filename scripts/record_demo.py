#!/usr/bin/env python3
"""
Playwright demo recorder for the Sift Sentinel Run Viewer.

Navigates through the viewer UI, clicks on the target case and its latest run,
and steps through all five pipeline tabs (Overview, Plan, Evidence, Findings, Critic)
while recording a video.

Setup (one-time, on host):
    pip install playwright
    playwright install chromium

Run:
    python scripts/record_demo.py

Output:
    videos/sift_sentinel_demo_<YYYYMMDD_HHMMSS>.webm
    (the tmp playwright filename is renamed to a timestamped one on completion)

Requirements:
    - sift-sentinel container running with port 8080 published to host
      (docker compose -f docker/docker-compose.yaml up -d)
    - At least one completed run in out/runs/
"""

from __future__ import annotations

import sys
import time
from datetime import datetime
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright, Page
except ImportError:
    print("Playwright not installed. Run: pip install playwright && playwright install chromium")
    sys.exit(1)

BASE_URL = "http://localhost:8080"
VIDEO_DIR = Path(__file__).parent.parent / "videos"

# Case to feature in the demo. Change to any case_id that exists in out/runs/.
DEMO_CASE = "srl-2018-wkstn-05"


def pause(page: Page, ms: int) -> None:
    page.wait_for_timeout(ms)


def scroll_content(page: Page, by_px: int) -> None:
    page.locator("#content").evaluate(f"el => el.scrollTop += {by_px}")


def demo(page: Page) -> None:
    # -- landing -----------------------------------------------------------
    page.goto(BASE_URL, wait_until="networkidle")
    page.wait_for_selector(".case-header", timeout=12_000)
    pause(page, 1800)

    # -- expand case -------------------------------------------------------
    page.locator(".case-header", has_text=DEMO_CASE).click()
    page.wait_for_selector(".run-item", timeout=6_000)
    pause(page, 1200)

    # -- click latest run (API returns newest first) -----------------------
    page.locator(".run-item").first.click()
    page.wait_for_selector("#panel-overview.active", timeout=12_000)
    pause(page, 2200)

    # -- Overview: scroll stats grid down a bit ----------------------------
    scroll_content(page, 200)
    pause(page, 1800)
    scroll_content(page, -200)
    pause(page, 1000)

    # -- Plan tab ----------------------------------------------------------
    page.locator(".tab[data-tab='plan']").click()
    page.wait_for_selector("#panel-plan.active")
    pause(page, 2200)
    scroll_content(page, 300)
    pause(page, 1500)
    scroll_content(page, -300)
    pause(page, 800)

    # -- Evidence tab ------------------------------------------------------
    page.locator(".tab[data-tab='evidence']").click()
    page.wait_for_selector("#panel-evidence.active")
    pause(page, 2200)
    scroll_content(page, 400)
    pause(page, 1800)
    scroll_content(page, -400)
    pause(page, 800)

    # -- Findings tab (the money shot) ------------------------------------
    page.locator(".tab[data-tab='findings']").click()
    page.wait_for_selector("#panel-findings.active")
    pause(page, 2500)
    # Slowly scroll through findings so each card is readable
    scroll_content(page, 300)
    pause(page, 1800)
    scroll_content(page, 300)
    pause(page, 1800)
    scroll_content(page, 300)
    pause(page, 1500)
    scroll_content(page, -900)
    pause(page, 800)

    # -- Critic tab --------------------------------------------------------
    page.locator(".tab[data-tab='critic']").click()
    page.wait_for_selector("#panel-critic.active")
    pause(page, 2200)
    scroll_content(page, 300)
    pause(page, 1800)
    scroll_content(page, -300)
    pause(page, 800)

    # -- Return to Overview for closing shot -------------------------------
    page.locator(".tab[data-tab='overview']").click()
    page.wait_for_selector("#panel-overview.active")
    pause(page, 2500)


def main() -> None:
    VIDEO_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Recording demo of {DEMO_CASE} at {BASE_URL}")
    print(f"Output directory: {VIDEO_DIR}")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=False,
            args=["--window-size=1280,800", "--window-position=0,0"],
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            record_video_dir=str(VIDEO_DIR),
            record_video_size={"width": 1280, "height": 800},
        )
        page = context.new_page()

        try:
            demo(page)
            print("Demo sequence complete.")
        except Exception as exc:
            print(f"Demo error: {exc}", file=sys.stderr)
            raise
        finally:
            # Closing context flushes the video file.
            context.close()
            browser.close()

    # Rename the auto-named webm to a timestamped filename.
    videos = sorted(VIDEO_DIR.glob("*.webm"), key=lambda f: f.stat().st_mtime, reverse=True)
    if videos:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        named = VIDEO_DIR / f"sift_sentinel_demo_{ts}.webm"
        videos[0].rename(named)
        print(f"Saved: {named}")
    else:
        print("No video file found — did Playwright record?", file=sys.stderr)


if __name__ == "__main__":
    main()
