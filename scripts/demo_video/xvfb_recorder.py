"""High-quality web video recorder using xvfb + ffmpeg x11grab.

Bypasses Playwright's lossy WebM recorder. chromium renders into a virtual
xvfb display; ffmpeg captures that display directly to H.264 at controllable
bitrate. Output sharpness is bounded only by ffmpeg settings.

Why this and not Playwright's record_video_dir:
- Playwright's WebM recorder is fixed-bitrate VP8 and softens fine detail.
- xvfb + ffmpeg x11grab captures the actual chromium render at full quality.
- Verified 2026-05-09 against architecture page: kb/s 4605 vs ~600 prior.

Usage:
    async with XvfbRecorder(out_path) as rec:
        page = await rec.new_page()
        await page.goto(...)
        await rec.start_capture(duration_s=15)
        ... drive page ...
        await rec.wait_capture()

Requires (already in demo-video:latest container): Xvfb, fluxbox, ffmpeg,
chromium (via /ms-playwright/chromium-1148/chrome-linux/chrome).
"""
from __future__ import annotations

import asyncio
import os
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path

from playwright.async_api import async_playwright


CHROME_BIN = "/ms-playwright/chromium-1148/chrome-linux/chrome"
DEFAULT_DISPLAY = ":99"


class XvfbRecorder:
    def __init__(
        self,
        out_path: Path,
        viewport: tuple[int, int] = (1920, 1080),
        display: str = DEFAULT_DISPLAY,
        crf: int = 18,
        preset: str = "medium",
        framerate: int = 30,
        zoom_filter: str | None = None,
    ):
        self.out_path = Path(out_path)
        self.viewport = viewport
        self.display = display
        self.crf = crf
        self.preset = preset
        self.framerate = framerate
        self.zoom_filter = zoom_filter
        self._xvfb_proc: subprocess.Popen | None = None
        self._fluxbox_proc: subprocess.Popen | None = None
        self._ffmpeg_proc: subprocess.Popen | None = None
        self._pw = None
        self._browser = None
        self._context = None
        self._userdata: str | None = None

    async def __aenter__(self) -> "XvfbRecorder":
        w, h = self.viewport
        self._xvfb_proc = subprocess.Popen(
            ["Xvfb", self.display, "-screen", "0", f"{w}x{h}x24", "-ac"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        await asyncio.sleep(1.0)
        env_disp = {"DISPLAY": self.display, **os.environ}
        self._fluxbox_proc = subprocess.Popen(
            ["fluxbox"], env=env_disp,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        await asyncio.sleep(1.0)
        self._userdata = tempfile.mkdtemp(prefix="xvfb_chrome_")
        self._pw = await async_playwright().start()
        # launch + new_context + new_page (NOT launch_persistent_context).
        # persistent_context kept opening a default about:blank tab that
        # ended up being the visible chromium window while the scene
        # navigated a different page. With launch + new_page we get a
        # single page that IS the visible window.
        self._browser = await self._pw.chromium.launch(
            executable_path=CHROME_BIN,
            headless=False,
            ignore_default_args=["--enable-automation"],
            args=[
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--no-first-run",
                "--no-default-browser-check",
                "--test-type",
                "--disable-infobars",
                "--disable-blink-features=AutomationControlled",
                f"--window-size={w},{h}",
                "--window-position=0,0",
                "--start-maximized",
                "--hide-scrollbars",
            ],
            env=env_disp,
        )
        self._context = await self._browser.new_context(
            viewport={"width": w, "height": h},
        )
        return self

    async def new_page(self):
        page = await self._context.new_page()
        await page.bring_to_front()
        return page

    async def start_capture(self, duration_s: float) -> None:
        """Start ffmpeg x11grab as an asyncio subprocess. Returns
        immediately so the caller can drive the page while ffmpeg
        captures. Call wait_capture() to await completion. Critical:
        uses asyncio subprocess so it does NOT block the event loop;
        scene tasks can run concurrently with capture."""
        w, h = self.viewport
        out = self.out_path
        out.parent.mkdir(parents=True, exist_ok=True)
        vf = self.zoom_filter or f"scale={w}:{h}"
        self._ffmpeg_proc = await asyncio.create_subprocess_exec(
            "ffmpeg", "-y",
            "-f", "x11grab", "-framerate", str(self.framerate),
            "-video_size", f"{w}x{h}", "-i", self.display,
            "-t", f"{duration_s:.3f}",
            "-vf", vf,
            "-c:v", "libx264", "-preset", self.preset, "-crf", str(self.crf),
            "-pix_fmt", "yuv420p",
            "-color_range", "tv", "-colorspace", "bt709",
            "-color_trc", "bt709", "-color_primaries", "bt709",
            str(out),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

    async def wait_capture(self) -> int:
        if not self._ffmpeg_proc:
            return 0
        rc = await self._ffmpeg_proc.wait()
        self._ffmpeg_proc = None
        return rc

    async def __aexit__(self, exc_type, exc, tb):
        if self._ffmpeg_proc:
            try:
                self._ffmpeg_proc.send_signal(signal.SIGINT)
                await asyncio.wait_for(self._ffmpeg_proc.wait(), timeout=5)
            except Exception:
                try:
                    self._ffmpeg_proc.kill()
                except Exception:
                    pass
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.stop()
        for proc in (self._fluxbox_proc, self._xvfb_proc):
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
        if self._userdata and Path(self._userdata).exists():
            shutil.rmtree(self._userdata, ignore_errors=True)
