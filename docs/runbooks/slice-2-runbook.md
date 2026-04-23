# Slice 2 Runbook — Notebook Prototype (SKILL.md-aligned)

**Goal:** A notebook container on D: drives a **decomposed AI pipeline** (Extract → Plan → Human checkpoint → Execute → Interpret) that calls **our own MCP server** inside the SIFT container, answers one forensic question, and emits a validated `findings.json` with Langfuse traces for every LLM call.

**Why this design (vs. Slice 1):** Slice 1 was Claude Code + Protocol SIFT's native MCP — someone else's plumbing. Slice 2 is the first slice where *we* engineer the architecture: decomposed pipeline with a human approval gate, per-step model routing via OpenRouter, our own MCP server, a typed findings schema, and observability from day one. This is the SKILL.md playbook applied to forensics.

**Scope discipline:** Slice 2 answers **one** question — *"Given a Windows disk image suspected of compromise, what persistence mechanisms did the attacker install?"* The framing matters: the agent is a **specialist** for one artifact class (Run keys, services, scheduled tasks, IFEO debuggers, AppInit DLLs, logon scripts), not a generalist IR tool. A real analyst's first question — *"what happened on this host?"* — fans out into this plus execution history, network artifacts, event-log timeline, user activity, etc., each of which would be its own specialist agent in later slices. Slice 2 proves the EXTRACT → PLAN → HUMAN → EXECUTE → INTERPRET skeleton on one narrow, high-yield question before we broaden.

**Canonical record:** tick boxes as you go. Update [PLAN.md](../planning/PLAN.md) slice 2 status on completion.

---

## Architecture (Slice 2)

```
┌─── notebook container (Docker, D:) ───────┐       ┌── sift container ──┐
│ Jupyter + uv + anthropic-via-OpenRouter + │       │ forensic tools     │
│ mcp-client + langfuse                     │       │ (read-only evidence│
│                                           │       │  on /mnt/hackathon)│
│                                           │       │                    │
│ Cell 1  EXTRACT    (gemini-3.1-flash-lite)           │       │ mcp_server.py lives│
│         → out/candidates.json             │       │ here; exposes 4    │
│                                           │       │ tools over stdio:  │
│ Cell 2  PLAN       (claude-sonnet)        │       │                    │
│         → out/tool_plan.json              │       │  • fsstat_e01      │
│              ▲                            │       │  • fls_list        │
│              │  (HUMAN APPROVAL)          │       │  • icat_extract    │
│              ▼                            │       │  • regripper_run   │
│ Cell 3  EXECUTE    (gemini-3.1-flash-lite + MCP)     │       │                    │
│         MCP stdio: docker exec -i sift …──┼──────▶│                    │
│         → out/raw_results.jsonl           │◀──────│                    │
│                                           │       │                    │
│ Cell 4  INTERPRET  (claude-sonnet)        │       │                    │
│         → out/findings.json               │       │                    │
│                                           │       │                    │
│ every LLM call → Langfuse (session=case)  │       │                    │
└───────────────────────────────────────────┘       └────────────────────┘
```

**Key architectural choices (and which SKILL.md preference each satisfies):**

| Choice | SKILL.md source | Why |
|---|---|---|
| Notebook runs in its own Docker container on D: | Environment constraint: *"Never pip install on host; always Docker on D:"* | Keeps host C: drive clean, deps reproducible |
| Pipeline decomposed into 4 phases with a human checkpoint | Phase 5a | Each step produces a reviewable artifact. The plan is the verification gate, not the final output |
| OpenRouter as LLM gateway | Phase 6a default | Per-step model routing, prompt caching, cost tracking via one API |
| Per-step model selection (nano / sonnet / nano / sonnet) | Phase 5c | Cheap models for mechanical steps, expensive models for reasoning gates |
| MCP server lives *inside* SIFT container | This runbook | Direct file access to `/mnt/hackathon`; no docker.sock mounted into notebook container; no HTTP transport; stdio bridge via `docker exec -i` |
| Langfuse traces from cell 1 | Phase 3 step 5 | *"Add observability/tracing from day one — not after scaling"* |
| Pydantic schemas for every artifact | Phase 5a | `candidates.json`, `tool_plan.json`, `findings.json` all round-trip through validated models |
| Prompt hardening baked into every LLM step | Phase 4 | `NOT FOUND` for absence, over-extraction guards, calibration instructions, 3-level confidence enums |

---

## Prereqs

- [x] Slice 1 complete — sift container healthy, case folder `~/cases/srl-2018-wkstn-05/` exists
- [ ] OpenRouter API key (`OPENROUTER_API_KEY`) — free to sign up, pay-as-you-go
- [ ] Langfuse account — use free cloud tier at https://cloud.langfuse.com, or self-host later. Need `LANGFUSE_PUBLIC_KEY` + `LANGFUSE_SECRET_KEY` + `LANGFUSE_HOST`
- [ ] Both keys added to a new `.env` file at `docker/.env` (gitignored)
- [ ] `docker compose ps` shows `sift` Up

---

## Step 1 — Notebook container

Add a second service to the compose file. Both containers run side-by-side; the notebook container has `docker` CLI installed and mounts `/var/run/docker.sock` so it can `docker exec -i sift ...` for the MCP stdio bridge.

**File:** `docker/docker-compose.yaml` — add below the existing `sift` service:

```yaml
  notebook:
    build: ./notebook               # new Dockerfile, see below
    container_name: find-evil-notebook
    depends_on: [sift]
    environment:
      - OPENROUTER_API_KEY=${OPENROUTER_API_KEY}
      - LANGFUSE_PUBLIC_KEY=${LANGFUSE_PUBLIC_KEY}
      - LANGFUSE_SECRET_KEY=${LANGFUSE_SECRET_KEY}
      - LANGFUSE_HOST=${LANGFUSE_HOST:-https://cloud.langfuse.com}
    volumes:
      - "D:/Python Applications/Find Evil - Hackathon/experiments/slice-2-notebook:/workspace"
      - /var/run/docker.sock:/var/run/docker.sock   # so MCP client can `docker exec -i sift ...`
    working_dir: /workspace
    ports:
      - "8888:8888"
    command: >
      bash -c "uv sync && uv run jupyter lab
        --ip=0.0.0.0 --port=8888 --no-browser
        --ServerApp.token='' --ServerApp.password=''
        --ServerApp.allow_origin='*'"
    restart: unless-stopped
```

**File:** `docker/notebook/Dockerfile`

```dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      docker.io curl git \
    && rm -rf /var/lib/apt/lists/*
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && ln -s /root/.local/bin/uv /usr/local/bin/uv
WORKDIR /workspace
```

- [x] `docker/.env` created with all four keys (template at `docker/.env.example`)
- [x] `docker/notebook/Dockerfile` written — **pinned to `python:3.12-slim-bookworm`**; trixie's `docker.io` package no longer ships the `docker` client binary we need for the MCP bridge
- [x] `docker-compose.yaml` updated with `notebook` service
- [x] `docker compose up -d --build` brings both containers up
- [x] Jupyter Lab reachable at `http://localhost:8888` (wait ~60s for first-time `uv sync`)
- [x] From inside notebook container: `docker exec --user sansforensics sift fsstat -V` prints Sleuth Kit 4.11.1 via the bridge

---

## Step 2 — Project skeleton

```
experiments/slice-2-notebook/
├── pyproject.toml
├── mcp_server/
│   └── server.py              # lives on D:, bind-mounted into sift at runtime (see Step 3)
├── pipeline/
│   ├── __init__.py            # ← only file on disk today
│   ├── schemas.py             # (planned) Pydantic: Candidates, ToolPlan, RawResult, Findings — currently inline in slice2.ipynb C2
│   ├── llm.py                 # (planned) OpenRouter client + Langfuse wrapper — currently inline in slice2.ipynb C5
│   ├── prompts.py             # (planned) system prompts for each of the 4 phases — currently inline in slice2.ipynb C5+
│   └── mcp_client.py          # (planned) spawns `docker exec -i sift python /opt/mcp/server.py` — currently inline in slice2.ipynb C3
├── slice2.ipynb
└── out/
    ├── candidates.json        # ✅ written by C5 EXTRACT
    ├── tool_plan.json         # (next — C6 PLAN)
    ├── tool_plan.APPROVED     # (next — empty marker file, written by human)
    ├── raw_results.jsonl      # (later — C8 EXECUTE)
    └── findings.json          # (later — C9 INTERPRET)
```

**`pyproject.toml` deps (uv manages):**
- `jupyterlab`
- `openai` (used against OpenRouter's OpenAI-compatible endpoint)
- `mcp` (official Model Context Protocol SDK)
- `pydantic`
- `langfuse`
- `langgraph` — added 2026-04-17 when LangGraph was adopted in Slice 2 (see PLAN.md Key Decisions)
- `python-dotenv`

> **Notebook-first reality (2026-04-18):** `pipeline/` currently holds only `__init__.py`. The `schemas.py` / `llm.py` / `prompts.py` / `mcp_client.py` files in the tree above are the *eventual extraction targets* — they get created only after the equivalent inline notebook cell is proven. C2 holds the schemas inline, C5 holds the EXTRACT logic inline, and so on.

- [x] Skeleton created (`pipeline/__init__.py`, `mcp_server/`, `out/`)
- [x] `uv sync` inside notebook container succeeds (first-boot via compose command)
- [x] `uv run python -c "import mcp, openai, langfuse, langgraph, pydantic"` succeeds — versions: openai 2.32.0, langfuse 4.3.1, langgraph ≥0.3, pydantic 2.13.2

> **Version note:** `langfuse 4.x` is a major rewrite from v2 — it's OTel-based now and the init API changed (`from langfuse import observe, get_client`). Keep in mind when writing `pipeline/llm.py` (Step 5). `openai 2.x` is also new; chat completions API surface is stable, but minor helper imports moved around.

---

## Step 3 — MCP server (lives in SIFT container)

> **Build-small history:**
> - **2026-04-17** — first pass shipped **`fsstat_e01` + `fls_list`** only. `icat_extract` + `regripper_run` deferred.
> - **2026-04-19** — un-deferred. Reviewing the first PLAN output made it clear a 2-tool plan can at best reach file-on-disk persistence (scheduled tasks, startup folder) but literally cannot open the Registry, where most persistence lives. Rather than ship an end-to-end demo whose honest answer is "I couldn't look in the right place," we added the two tools. Fail-fast-verified `icat` + `rip.pl` against the real E01 before coding the MCP wrappers; `rip.pl` required a one-line Perl fix (commented-out `?` branch of a ternary but live `:` branch — now patched in [../../docker/sift/Dockerfile](../../docker/sift/Dockerfile)).

The server is a single Python file. We bind-mount it into the sift container at runtime — no rebuild of the sift image required.

**Bind mount:** add to the `sift` service volumes:
```yaml
  - "D:/Python Applications/Find Evil - Hackathon/experiments/slice-2-notebook/mcp_server:/opt/mcp:ro"
```

**Four tools** (one more than last draft — `icat` added so we can extract hive bytes from the E01, per [forensic-tools.md](../../training/blue-cape-dfir-foundations/forensic-tools.md)):

| Tool | Wraps | Purpose |
|---|---|---|
| `fsstat_e01(e01_path)` | `fsstat <e01>` | Filesystem metadata — confirm NTFS, get MFT offset |
| `fls_list(e01_path, parent_inode=None, recurse=False)` | `fls -m / -r <e01> [inode]` | Directory listing (includes deleted entries) |
| `icat_extract(e01_path, inode, dest_path)` | `icat <e01> <inode> > <dest>` | Extract file bytes by inode into writable case dir |
| `regripper_run(hive_path, plugin)` | `rip.pl -r <hive> -p <plugin>` | Parse registry hive with named plugin |

### Engineering discipline (these are the slice's portfolio-relevant bits)

1. **argv arrays, never shell strings.** `subprocess.run(["fsstat", path])` — no `shell=True`, no string interpolation.
2. **Typed inputs.** Pydantic models on every tool arg → MCP surfaces as JSON Schema → agent gets typed tool calls, wrong types fail before reaching the filesystem.
3. **Path allowlist.** Reads permitted only from `/mnt/hackathon/**` (read-only mount). Writes permitted only to `/home/sansforensics/cases/<case_id>/analysis/**`. Every other path is rejected.
4. **Plugin allowlist for regripper.** Only the persistence plugins that actually ship in `/usr/share/regripper/plugins/` on SIFT jammy (verified 2026-04-19): `run`, `runonceex`, `services`, `schedagent`, `appinitdlls`, `imagefile`, `winlogon_tln`. Any other plugin name → `ValueError`. The server also pins every regripper hive to `<case>/analysis/extracted/` — a directory only ever written by `icat_extract` — so the icat-before-regripper ordering is enforced at the MCP layer, not just by PLAN prompt.
5. **Output truncation.** Cap each tool's stdout at 64 KB before returning. Raw output additionally persisted to disk and referenced by `raw_output_path`.
6. **Every call appended to `/home/sansforensics/cases/<case_id>/analysis/tool_calls.jsonl`** with: uuid, tool name, args, exit code, duration, stdout hash, stdout path. Audit-trail seed.
7. **No logs on stdout.** MCP uses stdio for protocol framing — use `stderr` for diagnostics.

- [x] `mcp_server/server.py` implements all 4 tools (`fsstat_e01`, `fls_list`, `icat_extract`, `regripper_run`) with all 7 disciplines
- [x] Bind-mount added in `docker-compose.yaml` → `/opt/mcp:ro`
- [x] **Extended sift image** — `docker/sift/Dockerfile` bakes `uv` + `mcp` + `pydantic` into the image (no runtime pip bootstrap) **and patches `/usr/local/bin/rip.pl` line 75** to fix an upstream Perl syntax error in digitalsleuth/sift-docker:jammy (see the Dockerfile comment for details). Compose switched from `image:` to `build: ./sift`. **Rebuild required after the 2026-04-19 change** — `docker compose -f docker/docker-compose.yaml build sift && docker compose -f docker/docker-compose.yaml up -d sift`
- [x] `docker compose up -d sift` re-applied so the new bind mount is live
- [x] Notebook cell C3 runs end-to-end (verified 2026-04-19 against live E01): 4 tools listed, `fsstat_e01` / `fls_list` / `icat_extract` / `regripper_run` all return `exit_code: 0`, SOFTWARE hive (~80 MB) written under `analysis/extracted/`, `rip.pl -p run` returns real `Microsoft\Windows\CurrentVersion\Run` entries
- [ ] Path allowlist rejection: calling `fsstat_e01("/etc/passwd")` fails fast with a ValueError (verified when we add a dedicated cell)
- [x] `icat_extract` + `regripper_run` added (2026-04-19)

---

## Step 4 — Schemas (contracts before code)

**File:** `pipeline/schemas.py` — the contracts that every phase reads/writes against.

```python
from pydantic import BaseModel, Field
from typing import Literal
from datetime import datetime

Confidence = Literal["low", "medium", "high"]
PersistenceCategory = Literal[
    "registry_run_key", "service", "scheduled_task",
    "ifeo_debugger", "appinit_dll", "logon_script",
    "NOT_FOUND",   # explicit absence — see prompt hardening
]

# ---- Phase 1 output ----
class ArtifactCandidate(BaseModel):
    artifact_type: Literal["registry_hive", "scheduled_task_xml", "service_config"]
    path_hint: str         # e.g. "/Windows/System32/config/SOFTWARE"
    reason: str            # why this artifact is relevant to persistence
    priority: Literal[1, 2, 3]   # 1 = must check, 3 = optional

class Candidates(BaseModel):
    question: str
    candidates: list[ArtifactCandidate]

# ---- Phase 2 output ----
class PlannedStep(BaseModel):
    step_id: int
    tool: Literal["fsstat_e01", "fls_list", "icat_extract", "regripper_run"]
    args: dict
    purpose: str           # one sentence — why this step
    depends_on: list[int]  # step_ids whose output this step needs
    confidence: Confidence # calibrated — see prompt hardening

class ToolPlan(BaseModel):
    question: str
    steps: list[PlannedStep]
    expected_findings_range: tuple[int, int]  # e.g. (1, 5) — over-extraction guard

# ---- Phase 3 output (JSONL — one line per step) ----
class RawResult(BaseModel):
    step_id: int
    tool_call_id: str      # FK into tool_calls.jsonl
    tool: str
    args: dict
    exit_code: int
    stdout_excerpt: str    # truncated
    stdout_path: str       # full output on disk
    duration_ms: int

# ---- Phase 4 output ----
class Evidence(BaseModel):
    tool_call_id: str
    output_excerpt: str

class Finding(BaseModel):
    category: PersistenceCategory   # can be NOT_FOUND
    mechanism: str                  # e.g. "HKCU\\...\\Run\\updater.exe", or "none found"
    value: str
    confidence: Confidence
    evidence: list[Evidence]
    notes: str = ""

class Findings(BaseModel):
    case_id: str
    question: str
    findings: list[Finding]
    plan_digest: str        # sha256 of the approved tool_plan.json
    started_at: datetime
    finished_at: datetime
```

- [x] Schemas written **inline in `slice2.ipynb` C2** (not yet promoted to `pipeline/schemas.py` — that happens after the EXTRACT/PLAN/EXECUTE/INTERPRET cells all prove out)
- [x] All 4 schemas round-trip: `Model.model_validate_json(Model(**sample).model_dump_json())` — confirmed in C2

**Why these fields:**
- `PlannedStep.confidence` + `expected_findings_range` — calibration + over-extraction guard (Phase 4 prompt hardening)
- `PersistenceCategory` includes `NOT_FOUND` — absence-handling (SKILL.md: *"LLMs fill blanks — they don't flag them"*)
- `plan_digest` — links final findings to the exact approved plan. Tamper-evident audit chain
- `tool_call_id` — every piece of evidence FKs back to a line in `tool_calls.jsonl`

### Argument binding DSL (added 2026-04-19)

`PlannedStep.args` values are either literals (`int`, `str`, `bool`, `null`) OR a **placeholder string** that EXECUTE resolves against upstream step output before the MCP call:

```
{step:N.EXTRACTOR(PARAM)}
```

The schema stays permissive (`args: dict`) — the contract is enforced by the PLAN prompt and the structural-invariants check at the bottom of C6. Rules:

| Rule | Enforced where |
|---|---|
| Referenced `step_id` MUST be in the same step's `depends_on` | C6 validator |
| `EXTRACTOR` MUST be in `KNOWN_EXTRACTORS` | C6 validator |
| `icat_extract.inode` MUST be a placeholder (no literal `0` sentinel allowed) | C6 validator |
| Malformed placeholder (missing braces / colon / parens) fails fast | C6 validator |

**Extractors live today:**

| Extractor | Signature | Source | Resolves to |
|---|---|---|---|
| `inode_by_name` | `inode_by_name(FILENAME)` | upstream `fls_list` step's `stdout_excerpt` | the inode of the named entry (basename, case-insensitive) |

**EXECUTE (C8) resolver contract — what it needs to do before each MCP call:**

1. For every arg value that's a string matching `PLACEHOLDER_RE`:
   a. Read the upstream step's `RawResult.stdout_path` (full file, not truncated excerpt)
   b. Apply the extractor (for `inode_by_name`: parse `fls -m` bodyfile output, match basename case-insensitively, return the inode field)
   c. Substitute the resolved value into the args dict
2. Call the MCP tool with the resolved args
3. If any extractor fails (no matching entry, ambiguous match, malformed source), log a structured error and stop the run — C8 does NOT guess, C7's human review plus Slice 3's Critic decide how to recover.

**When to add a new extractor:** EXECUTE's resolver needs it AND the prompt can document it unambiguously. Don't add one just because the model might want it — every extractor is attack surface for the Critic (Slice 3) to second-guess.

**Why the notebook container needs a read-only mount of `sift-home`:** the MCP server writes raw tool output (e.g. `fls -m` bodyfile) to `/home/sansforensics/cases/<case>/analysis/raw/<uuid>/stdout.txt` inside the sift container. The path in `RawResult.stdout_path` is that *sift-internal* path. The resolver does a plain `open(stdout_path)` from the notebook kernel, so `sift-home` must be visible at the same path in the notebook container. Compose mounts it read-only (`- sift-home:/home/sansforensics:ro`) — forensic integrity is preserved because the notebook can't modify artifacts. Without this mount, C8's resolver hits `FileNotFoundError` on the first step with a placeholder. (Discovered 2026-04-19 the hard way; runbook step now includes the mount.)

**Compose step after any volumes/ change:**

```bash
# in the repo root
docker compose -f docker/docker-compose.yaml up -d --force-recreate notebook
# kernel state (pipeline_state) is lost on recreate — re-run C1 through C8
```

---

## Step 5 — OpenRouter + Langfuse wiring

**File:** currently inline in `slice2.ipynb` C5 / C6 (will promote to `pipeline/llm.py` once EXECUTE + INTERPRET exist and we can extract a common shape).

**OpenRouter:**
- OpenAI-compatible base URL: `https://openrouter.ai/api/v1`
- Model IDs (per SKILL.md Phase 5c per-step routing):
  - `google/gemini-3.1-flash-lite-preview` — EXTRACT, EXECUTE (cheap)
  - `anthropic/claude-sonnet-4.6` — PLAN, INTERPRET (quality)

**Langfuse — the observability contract (lands 2026-04-19, all five gaps in the critique from that day are closed):**

| Dimension | Goes into | Why |
|---|---|---|
| `user_id = CASE_ID` | every `propagate_attributes(...)` call | Filter Langfuse by investigation |
| `session_id = run_id` (`srl-…-<hex>` or `smoke-<hex>`) | every phase in one pipeline run | **One session = one investigation run**, so EXTRACT + PLAN + (eventually EXECUTE + INTERPRET) land in the same tree. C5 / C6 reuse `pipeline_state.run_id` if it exists, mint a new one if not — `del pipeline_state` resets. |
| `tags=["phase:<name>"]` + `metadata={"phase": "<name>"}` | every phase + the C3 smoke test (`phase:smoke`) | Per-phase cost / latency rollups without manual regex on session IDs |
| `@observe("extract")` + `langfuse.update_current_span(output=pydantic.model_dump(), metadata={...})` | every phase node in the LangGraph pipeline | Structured Pydantic output rendered as first-class JSON on the parent span (not buried in LLM message strings). Counts like `n_candidates`, `n_icat_extract`, `n_regripper_run` land as metadata for UI filtering |
| `langfuse.start_as_current_observation(as_type="tool", name=<tool>, input=args)` + `span.update(output={exit_code, stdout_hash, stdout_path, duration_ms, truncated}, metadata={tool_call_id})` | every MCP `session.call_tool(...)` in C3 now, C8 later | Each MCP call appears as a child "tool" span under the parent. Non-zero exit → `span.update(level="ERROR")` so broken runs are grep-able in the session list |

- [x] C5 + C6 use the `propagate_attributes` shape above (phase tags + metadata + structured output) — verified 2026-04-19
- [x] C3 wraps every MCP call with a Langfuse `tool` span under an `mcp_smoke_test` parent — verified 2026-04-19
- [x] Traces render first-class Candidates / ToolPlan JSON on the parent span (not just inside LLM messages) — verified 2026-04-19
- [ ] Prompt caching verified on repeat runs (system prompts + tool schemas send cache hints; second run should report cache hit in Langfuse generation details)
- [ ] Per-phase cost breakdown visible in Langfuse UI by filtering `tags:phase:plan` etc.
- [ ] Once C8 + C9 land, one full invocation of `graph.invoke()` produces **one session with 4 parent spans** (extract / plan / execute / interpret) — EXECUTE has per-tool child spans

---

## Step 6 — Prompts (prompt hardening applied)

**File:** `pipeline/prompts.py`

Each phase has a system prompt. Apply SKILL.md Phase 4 "Prompt Hardening" rules — excerpted here per phase:

### EXTRACT (gemini-3.1-flash-lite)
```
You are listing the candidate artifact locations that could contain persistence
evidence on a Windows host. You are NOT analyzing evidence yet — just enumerating
where to look.

Return a single JSON object matching exactly this schema (no prose, no markdown fences):

{Candidates JSON Schema — inlined at build time via Candidates.model_json_schema()}

Rules:
- Windows typically has 8-15 persistence-relevant artifact locations worth checking.
  Do not exceed 15. If you are tempted to list more, prioritize.
- Do not invent paths. Use canonical Windows paths only.
- Each candidate MUST have a non-empty `reason`.
```

**Implementation note:** the schema is embedded in the prompt at f-string build time. We call `.chat.completions.create(response_format={"type": "json_object"})` — not OpenAI's `.beta.parse(response_format=<PydanticModel>)` — because `.parse()` emits Pydantic-generated schemas with `$defs`/`$ref` that Google's JSON Schema validator can't resolve (resulted in a 400 on 2026-04-18: *"schema at properties.candidates.items requires unspecified property 'artifact_type'"*). Pydantic still guards the contract on receive via `Candidates.model_validate_json(raw)`.

**Design note (acknowledging a real trade-off):** for the current Slice 2 scope (persistence-on-Windows) this phase is effectively a canonical lookup — the output barely varies between runs. We keep it as an LLM step for (1) *question agnosticism* (future cases will ask about credential theft / exfiltration / lateral movement, each of which maps to a different artifact list), (2) *OS agnosticism* (Linux → systemd units, crontabs, shell rc files; macOS → LaunchAgents / LaunchDaemons), and (3) *architectural symmetry* with PLAN / EXECUTE / INTERPRET. A deterministic YAML-fixture fallback for common `(question, os)` pairs is a documented later optimization, not a Slice 2 deliverable.

### PLAN (claude-sonnet)
```
You design a tool-call plan to answer the forensic question, using only the 4 tools
whose schemas are below.

Rules:
- Score confidence for each step INDEPENDENTLY. Do not default to "high".
- Set `expected_findings_range` based on prior knowledge of typical compromised hosts
  (usually 1-5 persistence mechanisms). If you expect more, justify in purpose text.
- Every `regripper_run` must be preceded by an `icat_extract` that produces the hive.
  Dependencies must be declared in `depends_on`.
- Do NOT execute anything. Output only the plan object.
```

### EXECUTE (gemini-3.1-flash-lite + MCP tools)
```
You are a tool runner. Execute the steps in the approved plan in dependency order.
Resolve dependencies by reading the output of prior steps (inode numbers, paths) and
passing them as args to later steps. Do not improvise — only call the tools in the
plan, with the args in the plan, enriched by resolved dependencies.

If a step fails (non-zero exit code), record it and STOP. Do not invent retries.
(Retries belong to Slice 3's self-correction loop, not this one.)
```

### INTERPRET (claude-sonnet)
```
You convert raw tool output into structured findings.

Rules:
- If NO persistence evidence is found, return exactly ONE Finding with
  `category: NOT_FOUND`, `confidence: high`, `mechanism: "none found"`.
  Do NOT invent findings to fill the list.
- Every Finding.evidence[] entry MUST reference a real tool_call_id from raw_results.
- Confidence levels:
  - "high"   = tool output directly shows the persistence mechanism
  - "medium" = indirect evidence (e.g. suspicious path but no registry value)
  - "low"    = inferred from context
  Rate INDEPENDENTLY. Do not default to any level.
- Expected range of findings (from plan): {expected_findings_range}. If your findings
  count falls outside this range, add a sentence to notes explaining why.
```

- [ ] All 4 system prompts written with hardening rules visible
- [ ] Each prompt ≤ 40 lines; no padding

---

## Step 7 — Notebook

**File:** `slice2.ipynb`

Each phase gets its own markdown header + code cell pair (so the notebook reads as a runbook itself). Live cell layout (12 cells total: a top-level intro + 5 phase pairs + one trailing scratch cell):

| Cell tag | Cell type | What it does |
|---|---|---|
| **C0** | markdown | Top-of-notebook intro — question, cell index, how to re-run |
| **C1** | Setup | Load `.env`, build OpenRouter client, init Langfuse, pin `CASE_ID` / `E01_PATH` / `MODELS` |
| **C2** | Schemas | Define `Candidates`, `ToolPlan`, `RawResult`, `Findings` Pydantic models inline |
| **C3** | MCP smoke test | Spawn MCP server (`docker exec -i sift python3 /opt/mcp/server.py`), list tools, call `fsstat_e01` against the real E01 |
| **C4** | LangGraph | Define `PipelineState` + the 4-node `StateGraph` (extract → plan → execute → interpret) with stub nodes; render Mermaid + PNG |
| **C5** | EXTRACT (real) | Call `gemini-3.1-flash-lite-preview` via `langfuse.openai.OpenAI`; `response_format={"type":"json_object"}` + inline schema; validate with `Candidates.model_validate_json(...)`; write `out/candidates.json` |
| **C6** | PLAN (next) | Call `claude-sonnet-4.6`; produce `ToolPlan`; write `out/tool_plan.json`; print plan table |
| **C7** | HUMAN CHECKPOINT (next) | `assert Path("out/tool_plan.APPROVED").exists()` halts the kernel until the human creates the marker file |
| **C8** | EXECUTE (next) | Spawn MCP client; run planned steps in dependency order; append each to `out/raw_results.jsonl` |
| **C9** | INTERPRET (next) | Call `claude-sonnet-4.6`; produce `Findings`; compute `plan_digest`; write `out/findings.json` |

- [x] C1 Setup — Langfuse session visible in UI (confirmed 2026-04-18)
- [x] C2 Schemas — round-trip OK, all 4 models validate sample dicts
- [x] C3 MCP smoke — 4 tools listed, end-to-end `fsstat → fls → icat(SOFTWARE) → rip.pl(run)` all return `exit_code: 0` (re-verified 2026-04-19 after un-deferring icat + regripper)
- [x] C4 LangGraph — Mermaid + PNG render inline; stub nodes print labels in dependency order
- [x] C5 EXTRACT — `candidates.json` validates against `Candidates`, ≥5 candidates (confirmed 2026-04-18 — gemini-3.1-flash-lite-preview via json_object + Pydantic validation)
- [x] C6 PLAN — `tool_plan.json` validates against `ToolPlan` (confirmed 2026-04-18 against 2-tool scope; prompt + tools expanded 2026-04-19 — re-run required after sift rebuild to regenerate a 4-tool plan)
- [ ] C6 PLAN re-verified on the 4-tool prompt: plan contains at least one `icat_extract → regripper_run` chain, structural-invariants check in the cell prints `OK`
- [ ] C7 Human checkpoint — first run halts with a clear message; second run (after creating marker) proceeds
- [ ] C8 EXECUTE — `raw_results.jsonl` has one line per planned step, no `exit_code != 0`
- [ ] C9 INTERPRET — `findings.json` validates; every `evidence[].tool_call_id` resolves to a real line in sift's `tool_calls.jsonl`
- [ ] Langfuse shows one trace with 4 named spans (extract / plan / execute / interpret) under session `srl-2018-wkstn-05`

---

## Step 8 — Smoke test: real persistence finding

The target image is known-evil. Any of the following in `findings.json` counts as Slice 2 success:

- Any Run / RunOnce key in NTUSER.DAT with a non-standard value
- A service with a suspicious ImagePath
- A scheduled task pointing to a user-writable directory

**What Slice 2 success looks like:**
- [ ] ≥1 Finding with `category != NOT_FOUND` and non-empty evidence, OR explicit `NOT_FOUND` with high confidence (both valid — we're testing the pipeline, not guessing the answer)
- [ ] `plan_digest` in `findings.json` matches `sha256(tool_plan.json)` at the moment of approval
- [ ] `tool_calls.jsonl` line count matches `raw_results.jsonl` line count
- [ ] Langfuse shows total cost of one run (dollars + tokens + per-step breakdown)

**What Slice 2 is NOT responsible for:**
- Being right. Ground-truth scoring is Slice 4.
- Retrying on contradictions. That's Slice 3.
- Fully typed MCP tool contracts with per-tool capability tokens. That's Slice 5.
- UI. That's Slice 7.

---

## Step 9 — Update PLAN.md

- [ ] Flip Slice 2 row to ✅ with date
- [ ] One-line reflection in Current Status
- [ ] Next Action → Slice 3 (self-correction loop plugs into `Finding.confidence` + `plan_digest`)

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `docker exec -i` from notebook container fails permission | docker.sock not mounted, or socket owned by root group notebook user isn't in | Mount `/var/run/docker.sock`; run notebook container as root (it's a dev container) |
| MCP Inspector can't see tools | Server writing logs to stdout | Route all logs to `stderr`; only MCP framing on stdout |
| Cell 3 plan missing `icat_extract` before `regripper_run` | Prompt not strict enough | Tighten PLAN prompt; add schema validator that rejects this dependency pattern |
| Cell 5 fails resolving dependencies | Executor model (gemini-3.1-flash-lite-preview) too cheap | Bump EXECUTE step to `claude-haiku-4.5` or `claude-sonnet-4.6`; dependency resolution is not pure mechanics |
| Langfuse traces missing | `LANGFUSE_HOST` env var not set or keys wrong | Check container env; hit Langfuse's healthcheck from inside notebook container |
| `regripper_run` returns no output but no error | F-Response volume quirk from Slice 1 persists; hive path inside E01 differs from host path | Use `fls` recursively to locate `SOFTWARE` / `NTUSER.DAT` by name, not by canonical path |
| Cost blows up | Plan step (Sonnet) called per cell rerun without caching | Verify OpenRouter cache headers fire on repeat runs; system prompt must be first message and unchanged |
| Findings validation fails with weird strings | Model didn't follow schema | Use `response_format={"type": "json_object"}` + embed the schema inline in the prompt + validate with `Model.model_validate_json(raw)`. Raises `pydantic.ValidationError` on mismatch. Portable across Gemini / Claude / GPT |
| OpenRouter → Gemini returns 400 *"schema at properties.X.items requires unspecified property 'Y'"* | OpenAI SDK's `.beta.parse(response_format=<PydanticModel>)` emits schemas with `$defs`/`$ref` that Google's validator can't resolve | Swap to `.chat.completions.create(response_format={"type":"json_object"})` + inline the schema into the system prompt + validate with Pydantic on receive. See C5 EXTRACT implementation |
| `regripper_run` raises `syntax error at /usr/local/bin/rip.pl line 75, near ":"` | Upstream bug in digitalsleuth/sift-docker:jammy: line 75 is the `:` branch of a ternary whose `?` branch is commented out. Perl refuses to compile on any invocation | Rebuild the sift image — `docker/sift/Dockerfile` includes a `sed` patch that comments the orphan line. Run `docker compose -f docker/docker-compose.yaml build sift && docker compose -f docker/docker-compose.yaml up -d sift` |
| `regripper_run` returns `ValueError: hive path <x> must be under /home/sansforensics/cases/<case>/analysis/extracted/` | Model tried to run rip.pl on a path that wasn't extracted via `icat_extract` first | This is the server enforcing icat-before-regripper ordering. Fix the PLAN: add an `icat_extract` step upstream and point `hive_path` at its `dest_path` |
| PLAN returns `regripper_run` with a plugin not in the allowlist (e.g. `user_run`, `appinit`) | Names in earlier drafts of this runbook didn't match the actual filenames in `/usr/share/regripper/plugins` on SIFT jammy | Use the allowlisted names: `run`, `runonceex`, `services`, `schedagent`, `appinitdlls`, `imagefile`, `winlogon_tln` |

---

## Portfolio piece progress after Slice 2

| Portfolio piece | After Slice 2 | Gap remaining |
|---|---|---|
| Decomposed pipeline with human checkpoint | ✅ 4 phases, approval gate, artifacts per phase | — |
| Our own MCP server | ✅ 4 tools, stdio, inside sift | Typed contracts per tool, capability tokens (Slice 5) |
| Per-step model routing | ✅ OpenRouter, 2 models | Cost-based auto-routing (optional) |
| Observability | ✅ Langfuse traces, session grouping, cost per call | UI surfacing of metrics (Slice 6/7) |
| Audit trail | ✅ `tool_calls.jsonl` + `plan_digest` | Rollup views, per-case metrics (Slice 6) |
| Self-correction loop | ❌ Not in scope | Whole loop: critic, contradiction check, retry policy (Slice 3) |
| Prompt hardening | ✅ Absence handling, over-extraction guard, calibration, 3-level enums | Evaluated against adversarial inputs (Slice 4) |
| Architectural sandboxing | ✅ Path allowlist, plugin allowlist, read-only mount, argv arrays | Tool-scoped capability tokens (Slice 5) |

---

## Reference — paths quick card

| Location | Where |
|---|---|
| Notebook source | `D:\Python Applications\Find Evil - Hackathon\experiments\slice-2-notebook\` (host) = `/workspace/` (notebook container) |
| MCP server source | Same host path → `/opt/mcp/` (sift container, read-only) |
| Evidence | `/mnt/hackathon/` (sift container, read-only) |
| Case working dir | `/home/sansforensics/cases/srl-2018-wkstn-05/` (sift container, writable via `sift-home` volume) |
| Extracted hives | `<case>/analysis/extracted/` — the only location `regripper_run` will accept as `hive_path`; only written by `icat_extract` |
| Raw tool stdout | `<case>/analysis/raw/<tool_call_id>.stdout` (text tools); binary tools write directly to `extracted/` |
| Jupyter | http://localhost:8888 (no token, dev-only) |
| Langfuse | https://cloud.langfuse.com, session `srl-2018-wkstn-05` |

---

## Next

Once `findings.json` round-trips and Langfuse shows one complete trace with all 4 spans, Slice 2 is done. Open `docs/runbooks/slice-3-runbook.md` for the self-correction loop (the critic step that reads `Finding.confidence` and `raw_results.jsonl` to detect contradictions, then re-plans and re-runs failing steps).
