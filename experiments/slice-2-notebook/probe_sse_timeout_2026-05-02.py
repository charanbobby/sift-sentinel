"""Probe: does sse_read_timeout=3600 prevent the dual-mode hang?

The hypothesis from the 2026-05-02 sweep is that the default sse_read_timeout
(300s) breaks the SSE stream when a Volatility plugin runs longer than 5 min,
and the NEXT MCP call hangs forever on the wedged connection. The fix at
pipeline/nodes.py:1259 lifts the timeout to 3600s.

This probe simulates the long-idle scenario without paying for a real
Volatility run. It opens a streamable-HTTP MCP session, calls list_tools
(succeeds), sleeps 310s (longer than the 300s default), then calls list_tools
again. With timeout=300 the second call should hang or fail. With
timeout=3600 both calls should succeed and the wall time differs only by the
sleep.

Run inside sift-sentinel (where MCP_URL resolves and the bearer token is set):

    docker exec sift-sentinel /workspace/.venv/bin/python \\
        /workspace/probe_sse_timeout_2026-05-02.py 300
    docker exec sift-sentinel /workspace/.venv/bin/python \\
        /workspace/probe_sse_timeout_2026-05-02.py 3600

Exit codes:
    0 = both calls succeeded (timeout big enough)
    1 = second call hung or errored (timeout too small) -- this is the BUG
    2 = setup error (env var missing, connection refused, etc)
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

MCP_URL = os.environ.get("MCP_URL", "http://sift-mcp:8000/mcp")
BEARER = os.environ.get("MCP_TRANSPORT_TOKEN", "")
SLEEP_SECONDS = 310  # > default 300


async def probe(timeout: int) -> int:
    if not BEARER:
        print("FAIL: MCP_TRANSPORT_TOKEN not set in this container", file=sys.stderr)
        return 2

    headers = {"Authorization": f"Bearer {BEARER}"}
    print(f"[probe] timeout={timeout}s, mcp_url={MCP_URL}")
    print(f"[probe] sleep_window={SLEEP_SECONDS}s (default sse_read_timeout is 300s)")

    t0 = time.monotonic()
    try:
        async with streamablehttp_client(MCP_URL, headers=headers, sse_read_timeout=timeout) as (read, write, _sid):
            async with ClientSession(read, write) as session:
                await session.initialize()
                t_init = time.monotonic()
                print(f"[probe] initialize OK at +{t_init - t0:.1f}s")

                tools_a = await session.list_tools()
                t_a = time.monotonic()
                print(f"[probe] list_tools #1 OK at +{t_a - t0:.1f}s, n_tools={len(tools_a.tools)}")

                print(f"[probe] sleeping {SLEEP_SECONDS}s to provoke SSE idle ...")
                await asyncio.sleep(SLEEP_SECONDS)

                t_wake = time.monotonic()
                print(f"[probe] woke at +{t_wake - t0:.1f}s, calling list_tools #2 (with 60s wall guard)")
                try:
                    tools_b = await asyncio.wait_for(session.list_tools(), timeout=60)
                    t_b = time.monotonic()
                    print(f"[probe] list_tools #2 OK at +{t_b - t0:.1f}s, n_tools={len(tools_b.tools)}")
                    print("PASS: SSE survived the idle window")
                    return 0
                except asyncio.TimeoutError:
                    print("FAIL: list_tools #2 hung past 60s wall guard (SSE wedged)")
                    return 1
                except Exception as e:
                    print(f"FAIL: list_tools #2 raised {type(e).__name__}: {e}")
                    return 1
    except Exception as e:
        print(f"FAIL: connection error {type(e).__name__}: {e}", file=sys.stderr)
        return 2


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <sse_read_timeout_seconds>", file=sys.stderr)
        return 2
    try:
        timeout = int(argv[1])
    except ValueError:
        print(f"timeout must be int, got {argv[1]!r}", file=sys.stderr)
        return 2
    return asyncio.run(probe(timeout))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
