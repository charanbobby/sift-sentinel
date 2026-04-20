# Pinned to bookworm: trixie's `docker.io` package no longer ships the `docker`
# client binary (daemon/proxy/init only). Bookworm's `docker.io` still bundles
# the CLI we need for the `docker exec -i sift ...` MCP stdio bridge.
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      docker.io curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && ln -s /root/.local/bin/uv /usr/local/bin/uv

WORKDIR /workspace
