# Concepts — What Are We Actually Working With?

> A plain-English primer on the moving parts. Re-read any time the vocabulary blurs.

---

## The three "things" (only two are real machines)

The word **"workstation"** appears in three places in this project and is the single biggest source of confusion. Here's what each one actually is:

### 1. Your Windows PC — the host

- The physical machine you're typing on.
- Where `D:\Python Applications\Find Evil - Hackathon\` lives.
- Where VS Code, Docker Desktop, Jupyter (Slice 2+), and the MCP client run.
- **C: drive is off-limits for heavy data.** Evidence and containers live on D:.

### 2. SIFT container — the analyst's lab

- A Docker container from `digitalsleuth/sift-docker:jammy` (Ubuntu 22.04) running on Docker Desktop (WSL2 backend).
- SANS's SIFT Workstation is an Ubuntu image with ~200 pre-installed forensic tools: Sleuth Kit, Volatility, Plaso, RegRipper, EZ Tools, YARA, KAPE, etc. The Docker flavour gives us the same toolset without VirtualBox.
- **This is our lab.** Protocol SIFT is installed inside it. Claude Code (CLI) runs here for Slice 1. Case folders under `~/cases/` persist across restarts via the `sift-home` named volume.
- Analogy: **the detective's forensic lab.**

> **Why a container and not a VM?** On Windows 11 with WSL2 + Docker Desktop active, Hyper-V owns the virtualization extensions. VirtualBox falls back to software emulation and runs 10–50× slower. Docker uses Hyper-V natively → full speed. Full rationale in [PLAN.md](PLAN.md) Key Decisions.

### 3. `base-wkstn-05` — the victim (just a file)

- A file named `base-wkstn-05-cdrive.E01`, ~14 GB, plus a ~3 GB memory image.
- Contents: a **byte-for-byte snapshot of the hard drive** of a Windows workstation at "SRL" (a fictional SANS-contrived company) that got hacked in 2018.
- **It is not a machine.** It's inanimate. We never boot it, never log in, never install anything on it. We **read** it with tools like `fsstat` and `fls` the same way you'd read a zip file — a blob of bytes structured like a disk.
- It's big because a real Windows install is big: OS, Program Files, user profiles, event logs, registry hives, browser history. That's the point — we need the full disk to find the initial access vector and persistence mechanisms.
- Analogy: **the body at the crime scene.** The SIFT container is the morgue where the autopsy happens.

---

## How they fit together

```
┌─────────────────────────────────────────────────────┐
│  Your Windows PC (host)                             │
│  ├─ VS Code, Jupyter, Portfolio                     │
│  ├─ D:\Python Applications\Find Evil - Hackathon\   │
│  │   └─ HACKATHON-2026\                             │
│  │       ├─ base-wkstn-05-cdrive.E01       ◄── evidence (14 GB)
│  │       └─ base-wkstn-05-memory\...img    ◄── evidence (3 GB, raw)
│  └─ Docker Desktop (WSL2)                           │
│     └─ ┌──────────────────────────────────────┐    │
│       │  SIFT container (Ubuntu 22.04)         │    │
│       │  ├─ Protocol SIFT (~/.claude/)         │    │
│       │  ├─ Claude Code CLI                    │    │
│       │  ├─ Sleuth Kit, Plaso, RegRipper, 7z   │    │
│       │  ├─ /mnt/hackathon/  (read-only bind   │    │
│       │  │   mount to HACKATHON-2026 on host)  │    │
│       │  └─ ~/cases/srl-2018-wkstn-05/         │    │
│       │     └─ evidence/  (symlinks → /mnt/…)  │    │
│       └──────────────────────────────────────┘     │
└─────────────────────────────────────────────────────┘
```

The evidence bytes stay on D: — the container reads them through a read-only bind mount. Symlinks inside the case folder give canonical paths to the tools.

**Slice 1 flow:** Claude Code (in the container) reasons about the case → picks a forensic tool (in the container) → tool reads the E01 via `/mnt/hackathon/` → returns results → Claude interprets → repeat.

**Slice 2+ flow:** Jupyter (on the host) drives an Anthropic SDK client → calls our own MCP server → MCP server `docker exec`s into the container to run individual tools → writes structured findings JSON back to the host. See [slice-2-runbook.md](../runbooks/slice-2-runbook.md).

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

1. **Spin up** the analyst's lab → SIFT container via `docker compose up -d`.
2. **Install** the AI brain into that lab → Claude Code + Protocol SIFT (one-time, persists on the `sift-home` volume).
3. **Mount** the evidence read-only → `/mnt/hackathon/` inside the container.
4. **Ask** the AI a forensic question.
5. **The AI** reasons → calls SIFT tools via MCP → reads output → reasons again → writes findings.
6. **You** critique the findings (or build self-critique into the loop — that's Slice 3).

The hackathon submission is the whole loop wrapped in a repeatable case workflow, with evals and observability on top.

---

## Re-read trigger

If you catch yourself asking "wait, which machine?" or "why is the file so big?" — come back here.
