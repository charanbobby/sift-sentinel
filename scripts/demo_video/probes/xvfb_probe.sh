#!/bin/bash
# Fast-fail probe: bypass Playwright's WebM recorder. Run chromium on
# xvfb virtual display, ffmpeg x11grab captures the display directly to
# H.264. Output: out/demo_video/probe_xvfb.mp4 (5-second sample).
set -e

CHROME=/ms-playwright/chromium-1148/chrome-linux/chrome
URL="${URL:-https://sentinel.sshub.dev/site/architecture.html}"
OUT=/work/out/demo_video/probe_xvfb.mp4

# Start Xvfb display :99 at 1920x1080x24bpp.
Xvfb :99 -screen 0 1920x1080x24 -ac &
XVFB_PID=$!
sleep 1
export DISPLAY=:99

# Launch chromium pointed at the architecture page on display :99.
# Avoid --kiosk and --start-fullscreen because they require a window
# manager. Use explicit window-size + position-zero instead, with
# software rendering since xvfb has no GPU.
USERDATA=$(mktemp -d)
"$CHROME" \
  --no-sandbox \
  --disable-gpu \
  --disable-dev-shm-usage \
  --no-first-run \
  --no-default-browser-check \
  --disable-extensions \
  --disable-popup-blocking \
  --user-data-dir="$USERDATA" \
  --window-size=1920,1080 \
  --window-position=0,0 \
  --hide-scrollbars \
  --use-gl=swiftshader \
  "$URL" \
  > /tmp/chrome.log 2>&1 &
CHROME_PID=$!

# Wait for page to render.
sleep 8

# Quick sanity: was chromium still alive?
if ! kill -0 "$CHROME_PID" 2>/dev/null; then
  echo "CHROMIUM DIED. Last log:"; tail -40 /tmp/chrome.log; exit 1
fi
echo "Chromium PID $CHROME_PID alive. Window list:"
DISPLAY=:99 xdpyinfo 2>&1 | head -5 || true

# Capture the X11 display directly to H.264 for 5 seconds.
# CRF 18, medium preset = high quality bound only by ffmpeg, no WebM
# intermediate.
ffmpeg -y \
  -f x11grab -framerate 30 -video_size 1920x1080 -i :99 \
  -t 5 \
  -c:v libx264 -preset medium -crf 18 -pix_fmt yuv420p \
  "$OUT"

# Cleanup.
kill "$CHROME_PID" 2>/dev/null || true
kill "$XVFB_PID" 2>/dev/null || true
echo "wrote $OUT"
