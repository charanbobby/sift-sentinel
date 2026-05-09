# Demo video production image. Ephemeral; built once, re-used for recordings.
#
# Base: official Playwright Python image (chromium + python 3 + playwright
# pre-installed and tested to work headless). We add ffmpeg + IBM Plex fonts
# + uv on top.
#
# Build:
#   cd scripts/demo_video
#   docker build -t demo-video:latest .
#
# Run a recording (mounts the repo and uses host network so https calls to
# sentinel.sshub.dev work, runs as the host user so out/ files are not root-owned):
#   docker run --rm \
#     --network host \
#     -v "$(pwd)/../..:/work" \
#     -w /work \
#     demo-video:latest \
#     python -m scripts.demo_video.record_beat beat1_open
FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

# ffmpeg + libass for caption burning, IBM Plex fonts for the end-card and
# burned captions. fc-cache refreshes the font index so libass sees them.
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
        ffmpeg \
        fonts-ibm-plex \
 && fc-cache -f \
 && rm -rf /var/lib/apt/lists/*

# uv + playwright. The Microsoft base image ships chromium for Playwright
# 1.49.0 specifically, so pin the python module to the matching version
# (otherwise BrowserType.launch fails with a version-mismatch error).
RUN pip install --no-cache-dir --quiet uv \
 && uv pip install --system --no-cache --quiet "playwright==1.49.0"

# Sanity probe at build time so a broken image is caught early.
RUN ffmpeg -version | head -1 \
 && python -c "import playwright; print('playwright import ok')" \
 && python -c "from playwright.async_api import async_playwright; print('playwright async API ok')" \
 && uv --version \
 && echo "fonts installed:" && fc-list | wc -l

WORKDIR /work
