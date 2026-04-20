FROM digitalsleuth/sift-docker:jammy

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh \
    && uv --version

RUN uv pip install --system --no-cache \
      mcp \
      pydantic

# Fix shipped RegRipper: line 75 of /usr/local/bin/rip.pl is the ":" branch of a ternary
# whose "?" branch is commented out (see comment block above it). Perl sees an orphan
# ":" and refuses to compile, so `rip.pl` errors out with "syntax error near ':'" on
# ANY invocation. We comment the orphan line so the (already-set) plugindir default
# on line 73 wins. Upstream bug in digitalsleuth/sift-docker:jammy as of 2026-04-19.
RUN sed -i '75s|^                   : |#                   : |' /usr/local/bin/rip.pl \
    && rip.pl -h >/dev/null 2>&1 || (echo "rip.pl patch failed" && exit 1)

# Keep base image's USER/CMD/ENTRYPOINT — sift's startup (sshd host key gen, etc.) runs as root.
# We still spawn MCP server via `docker exec --user sansforensics sift ...` from the notebook.
