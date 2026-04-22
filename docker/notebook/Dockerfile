# Bookworm pin is retained for reproducibility. Historical note: pre-Slice-5
# we needed it because trixie's `docker.io` package no longer ships the `docker`
# client binary we used for the `docker exec -i sift ...` stdio MCP bridge.
# Post-Slice-5 (Step 0.5), `sift-sentinel` no longer talks to the Docker daemon
# at all — MCP rides streamable-HTTP over an internal bridge to `sift-mcp`. The
# `docker.io` apt package has been dropped below; the pin stays simply so a
# future image rebuild doesn't silently bump the Python ABI.
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && ln -s /root/.local/bin/uv /usr/local/bin/uv

WORKDIR /workspace
