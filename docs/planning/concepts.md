# Concepts — What Are We Actually Working With?

> A plain-English primer on the moving parts. Re-read any time the vocabulary blurs.

---

## The three "things" (only one is a physical machine)

The word **"workstation"** appears in three places in this project and is the single biggest source of confusion. Here's what each one actually is:

### 1. Your Windows PC — the host

- The physical machine you're typing on.
- Where `D:\Python Applications\Find Evil - Hackathon\` lives.
- Where VS Code, Docker Desktop, and the browser run. (Jupyter + the MCP client *used* to run here in Slice 2; post-Slice-5-Step-0.5 both moved into the `sift-sentinel` container, and you reach Jupyter by pointing the host browser at http://localhost:8888.)
- **C: drive is off-limits for heavy data.** Evidence and containers live on D:.

### 2. The two containers — the agent's home and the tool server

Two Docker containers on the agent's data path:

- **`sift-sentinel` — the agent's home.** Python 3.12 + Jupyter + LangGraph + MCP client. **No forensic tools installed, no Docker socket mounted, no Docker CLI, no evidence mount.** Its only outward capability is signed streamable-HTTP calls to `sift-mcp`. Image: `docker-sift-sentinel` (built from `docker/notebook/Dockerfile`).
- **`sift-mcp` — the tool server the agent calls.** Extends `digitalsleuth/sift-docker:jammy` — same SANS toolset (Sleuth Kit, Volatility, Plaso, RegRipper, EZ Tools, YARA, KAPE, ~200 forensic tools). Runs a long-lived FastMCP server on `0.0.0.0:8000/mcp` as user `sansforensics`. *Not* privileged, no FUSE, no host port published. When the agent calls `fsstat`, the server forks a subprocess to the tool *inside this container* — nothing is proxied elsewhere. Image: `find-evil/sift:slice5` (built from `docker/sift/Dockerfile`).

Both containers share the `sift-home` Docker volume at `/home/sansforensics` — rw on `sift-mcp`, ro on `sift-sentinel` — so case artifacts the server writes (`tool_calls.jsonl`, extracted hives, etc.) can be read back by the agent without the agent needing its own evidence mount. `sift-mcp` separately bind-mounts the Windows-host evidence directories at `/mnt/hackathon:ro` and `/mnt/derived:rw`.

Networks: `sift-sentinel` ↔ `sift-mcp` talk over a Compose network marked `internal: true` (no host port, not externally reachable). `sift-sentinel` separately reaches the open internet over the default bridge (OpenRouter, Langfuse). The two networks don't meet.

Analogy: **two rooms in the same building.** The agent's desk (`sift-sentinel`) and the tool server the agent calls (`sift-mcp`). They share one filing cabinet (`sift-home`) and a single phone line (`findevil-internal`).

> **Why a container and not a VM?** On Windows 11 with WSL2 + Docker Desktop active, Hyper-V owns the virtualization extensions. VirtualBox falls back to software emulation and runs 10–50× slower. Docker uses Hyper-V natively → full speed. Full rationale in [PLAN.md](PLAN.md) Key Decisions.

> **Why two containers and not one?** The agent (LangGraph, MCP client) and the tool server (FastMCP, forensic binaries) have different attack-surface needs. Keeping them in separate containers means a hijacked agent can't directly invoke tools, touch evidence, or reach the host — its only capability is a bearer-authenticated HTTP call to the tool server, which is itself non-privileged and has only its own tool binaries to run. See [architecture.html](architecture.html) deployment topology + PLAN.md Carried Item 16.

> **What about manual DFIR work (`ewfmount`, `volatility`, Claude Code CLI)?** For ad-hoc commands that need FUSE + privileged (or just a shell with the full SIFT toolchain), spin up a one-off container:
> ```bash
> docker run --rm -it --privileged \
>   -v "D:/Python Applications/Find Evil - Hackathon/HACKATHON-2026:/mnt/hackathon:ro" \
>   -v "D:/Python Applications/Find Evil - Hackathon/HACKATHON-2026/derived:/mnt/derived:rw" \
>   --device /dev/fuse \
>   find-evil/sift:slice5 bash
> ```
> That's a developer tool, not part of the agent pipeline, and doesn't need to be a long-running compose service. *(Before 2026-04-22 there was a persistent `sift` workbench service in `docker-compose.yaml` serving this role; we removed it as vestigial once Step 0.5 had the MCP server in its own container.)*

### 3. `base-wkstn-05` — the victim (just a file)

- A file named `base-wkstn-05-cdrive.E01`, ~14 GB, plus a ~3 GB memory image.
- Contents: a **byte-for-byte snapshot of the hard drive** of a Windows workstation at "SRL" (a fictional SANS-contrived company) that got hacked in 2018.
- **It is not a machine.** It's inanimate. We never boot it, never log in, never install anything on it. We **read** it with tools like `fsstat` and `fls` the same way you'd read a zip file — a blob of bytes structured like a disk.
- It's big because a real Windows install is big: OS, Program Files, user profiles, event logs, registry hives, browser history. That's the point — we need the full disk to find the initial access vector and persistence mechanisms.
- Analogy: **the body at the crime scene.** The SIFT container is the morgue where the autopsy happens.

---

## How they fit together

```
┌─────────────────────────────────────────────────────────────────────┐
│  Your Windows PC (host)                                             │
│  ├─ VS Code + Portfolio                                             │
│  ├─ Browser → http://localhost:8888  (Jupyter, served from          │
│  │                                    inside sift-sentinel)         │
│  ├─ D:\Python Applications\Find Evil - Hackathon\                   │
│  │   └─ HACKATHON-2026\                                             │
│  │       ├─ base-wkstn-05-cdrive.E01       ◄── evidence (14 GB)     │
│  │       ├─ base-wkstn-05-memory\...img    ◄── evidence (3 GB, raw) │
│  │       └─ derived\...                    ◄── writable derived     │
│  └─ Docker Desktop (WSL2)                                           │
│                                                                     │
│     ┌──────────────────────────────────────────────────────────┐   │
│     │  sift-sentinel  —  THE AGENT'S HOME                      │   │
│     │  image: docker-sift-sentinel                             │   │
│     │  Python 3.12 + Jupyter + LangGraph + MCP client          │   │
│     │  no forensic tools · no Docker socket · no Docker CLI    │   │
│     │  /home/sansforensics  (ro, sift-home volume)             │   │
│     └───────┬──────────────────────────────────────────────────┘   │
│             │                                                       │
│             │  findevil-internal  (internal: true — no host port)   │
│             │  streamable-HTTP + bearer-token auth · port 8000      │
│             │                                                       │
│     ┌───────┴──────────────────────────────────────────────────┐   │
│     │  sift-mcp  —  THE TOOL SERVER THE AGENT CALLS            │   │
│     │  image: find-evil/sift:slice5                            │   │
│     │  FastMCP server · user: sansforensics · NOT privileged   │   │
│     │  runs fsstat · fls · icat · regripper · scheduled-tasks  │   │
│     │  /home/sansforensics  (rw, sift-home volume)             │   │
│     │  /mnt/hackathon       (ro, bind → HACKATHON-2026 on host)│   │
│     │  /mnt/derived         (rw, bind → derived\ on host)      │   │
│     └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

Evidence bytes stay on D: — `sift-mcp` reads them through a read-only bind mount. The `sift-home` Docker volume is what makes case artifacts written by the tool server visible inside `sift-sentinel` (read-only, so the notebook can open files the server wrote).

**Slice 5 flow:** Jupyter (inside `sift-sentinel`) drives a LangGraph pipeline → the agent emits MCP tool calls over streamable-HTTP to `sift-mcp` on the internal bridge (bearer-token-authenticated) → the tool server runs the tool as a subprocess locally and writes raw output + audit entries to the shared `sift-home` volume → returns a structured `ToolResult` to the agent. No `docker exec` on the agent's side; no Docker socket mounted anywhere on `sift-sentinel`. See [slice-5-runbook.md](../runbooks/slice-5-runbook.md) and the architecture doc's deployment topology.

**Slice 1 flow (historical, for reference):** Claude Code CLI inside a Protocol-SIFT container reasoned about the case, picked forensic tools, and ran them directly. That workflow is preserved for ad-hoc manual walkthroughs — spin up a one-off container with `docker run --rm -it --privileged -v <evidence>:/mnt/hackathon:ro --device /dev/fuse find-evil/sift:slice5 bash` when you need the full SIFT toolchain by hand. Not part of the agent pipeline.

---

## Key file formats you'll see

| Format | What it is | Read with |
|--------|-----------|-----------|
| `.E01` | EnCase Expert Witness disk image — forensic standard, compressed + hash-verified | `fsstat`, `fls`, `ewfmount`, `ewfinfo` |
| `.raw` / `.dd` / `.img` | Uncompressed byte-for-byte disk or memory dump | Same as above, plus `dd`, `xxd` |
| `.mem` / `.vmem` | Memory dump (RAM capture at a point in time) | Volatility 3 |
| `.7z` | Compressed archive SANS uses to ship large dumps | `7z x file.7z` |
| `.evtx` | Windows event log | `EvtxECmd`, `evtxdump` |
| `.pf` | Windows Prefetch — proof a program ran | `PECmd` |
| `$MFT` | NTFS Master File Table — every file's metadata | `MFTECmd` |

---

## The MCP piece (where AI enters)

**Model Context Protocol (MCP)** = Anthropic's standard for letting an LLM call tools.

- **Before MCP:** you'd copy-paste `fsstat` output into Claude's chat and ask "what do you see?"
- **With MCP:** Claude itself runs `fsstat`, reads the output, decides it also needs `fls`, runs that, and produces a structured finding — autonomously.

**Protocol SIFT** wires SIFT tools up as MCP tools so Claude Code can call them — that's the Slice 1 setup. From Slice 2 onward we run **our own** MCP server with typed contracts, path allowlists, and per-call audit logging; see [what-we-are-building.md](what-we-are-building.md) for why those are the portfolio-relevant pieces.

---

## Your mental model for the hackathon

1. **Spin up** the stack → the tool server (`sift-mcp`) and the agent home (`sift-sentinel`) via `docker compose up -d --build` from `docker/`.
2. **Mount** the evidence read-only → `/mnt/hackathon/` bind-mounted on `sift-mcp` only (not on `sift-sentinel` — the agent doesn't need direct disk access).
3. **Ask** the AI a forensic question (via Jupyter at http://localhost:8888, served from inside `sift-sentinel`).
4. **The AI** (inside `sift-sentinel`) reasons → emits MCP tool calls to `sift-mcp` over the internal bridge → the tool server runs the tool locally and writes raw output to the shared `sift-home` volume → returns a structured result → AI interprets → repeat.
5. **You** critique the findings (or build self-critique into the loop — that's Slice 3).

The hackathon submission is the whole loop wrapped in a repeatable case workflow, with evals and observability on top.

---

## Re-read trigger

If you catch yourself asking "wait, which machine?" or "why is the file so big?" — come back here.
