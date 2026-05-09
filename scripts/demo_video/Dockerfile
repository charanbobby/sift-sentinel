# Demo video production image. Ephemeral; built once, re-used for recordings.
#
# Base: official Playwright Python image (chromium + python 3 pre-installed).
# Add: ffmpeg for video assembly, IBM Plex fonts for the end-card and burned
# captions, uv for any extra Python deps (per project rule: always uv, never pip).
#
# Build:
#   cd scripts/demo_video
#   docker build -t demo-video:latest .
#
# Run a recording (mounts the repo and runs as the host user so out/demo_video/
# files are owned correctly):
#   docker run --rm \
#     -v "$(pwd)/../..:/work" \
#     -w /work \
#     --add-host sentinel.sshub.dev:host-gateway \
#     demo-video:latest \
#     python -m scripts.demo_video.record_beat beat1_open
FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

# ffmpeg + libass for caption burning, plus IBM Plex fonts for the end-card.
# fonts-ibm-plex pulls in the full IBM Plex family from Debian/Ubuntu repos.
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
        ffmpeg \
        fonts-ibm-plex \
 && rm -rf /var/lib/apt/lists/*

# uv installed via the official standalone installer (per project rule).
RUN pip install --no-cache-dir --quiet uv

# Sanity probe at build time so a broken image is caught early.
RUN ffmpeg -version | head -1 \
 && python -c "import playwright; print('playwright', playwright.__version__)" \
 && python -c "from playwright.async_api import async_playwright; print('playwright async API ok')" \
 && uv --version

WORKDIR /work
