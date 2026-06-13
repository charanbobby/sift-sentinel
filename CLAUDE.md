# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

`sift-sentinel` is a SANS "Find Evil" hackathon entry: an autonomous DFIR agent that triages Windows disk images (E01) and memory dumps to find attacker persistence, with a specialization in catching attackers who use AI tooling themselves (planted local LLM inference servers, prompt-injection payloads in registry/scheduled-task fields). The agent picks forensic tools, runs them, writes findings with cited evidence, and a deterministic rule engine double-checks every claim before a human sees it.

Read `README.md` first for the full pitch and `docs/planning/PLAN.md` (the live iteration plan) for current slice status and open questions. `SKILL.md` is the user's phase-ordered build workflow; follow its phases in order when doing greenfield work.

## The pipeline lives in one place

Despite the repo's size, the working system is the package under **`experiments/slice-2-notebook/`**. Everything else (`HACKATHON-2026/` evidence, `docs/`, `scripts/`, `out/`) supports it. Inside that directory:

- `pipeline/`: the LangGraph state machine and all its nodes. This is the core.
- `mcp_server/server.py`: the long-lived MCP forensic-tool server (runs in a separate container).
- `tests/`: pytest suite (~111 tests). Tests assume cwd `/workspace` (see `tests/conftest.py`), so they run **inside the container**, not on Windows.
- `run_case.py`: CLI entrypoint that builds the initial state and invokes the graph for one case.
- `site/`, `viewer/`, `pipeline/site.py`, `pipeline/viewer.py`: the run-viewer dashboards served on ports 8080/8081.
- `probe_*.py`, `*.ipynb`: fail-fast probes and the original prototype notebook (`slice2.ipynb`).

## Architecture: the LangGraph pipeline

One `PipelineState` (Pydantic, in `pipeline/graph.py`) flows through every node. The graph (`build_graph()` in `graph.py`, node bodies in `pipeline/nodes.py`):

```
START → extract → plan → reissue_token → execute → interpret → critic
                                                                  │
              critic_edge() routes one of four ways:             │
                commit        → END                              │
                re_interpret  → debounce_before_interpret → interpret
                re_plan       → debounce_before_plan → plan
                escalate      → human_review → END
```

Stage roles and LLM call sites:
- **EXTRACT** (Gemini 3 Flash): skims image metadata, picks candidate inodes.
- **PLAN** (Claude Sonnet 4.6): emits a typed `ToolPlan`; pauses for human approval, then a capability token is minted bound to the approved plan + case path scope.
- **EXECUTE**: calls the MCP server's typed tools using the capability token; server returns `EvidenceRecord`s.
- **INTERPRET** (Claude Sonnet 4.6): reads `structured_fields` only and writes `Findings` with cited evidence.
- **CRITIC** (`pipeline/critic.py`, no AI): runs ~17 deterministic rules (`R_01`..`R_13` + reserved slots) against each finding; failures retry once with a budget cap, then escalate.

`pipeline/ledger.py` hash-chains plan → tool call → finding for replay. `pipeline/schemas.py` is the single source of truth for every typed contract (`ToolPlan`, `EvidenceRecord`, `Finding`, `CapabilityToken`, etc.).

## The four trust boundaries (architectural, not prompt-based)

These are the project's headline differentiator; preserve them when editing:
1. **MCP allow-list**: the agent can only call 10 typed forensic functions (5 disk: `fsstat_e01`, `fls_list`, `icat_extract`, `regripper_run`, `scheduled_tasks_parse`; 5 memory Volatility plugins: `pslist`, `cmdline`, `netscan`, `dlllist`, `malfind`). There is no shell primitive.
2. **Capability tokens** (`pipeline/mcp/tokens.py`): every MCP call carries a per-run HMAC-signed token bound to the approved plan digest and case path scope; the server rejects out-of-scope calls before running the tool.
3. **Injection scanner** (`pipeline/mcp/injection_scanner.py`): scans every evidence record before it reaches the analysis LLM; flagged records are quarantined.
4. **Deterministic critic** (`pipeline/critic.py`): verifies every claim cites resolvable evidence.

The **dual-channel boundary** is structural: the analysis LLM (INTERPRET) and the critic only ever see server-parsed `structured_fields`, never raw tool stdout. Do not reintroduce raw-stdout reads into the interpret or critic path.

## Two-container topology

`docker/docker-compose.yaml` defines:
- **`sift-mcp`**: the forensic toolchain (Volatility, Sleuth Kit, RegRipper) exposed only as the 10 MCP tools over an `internal: true` bridge network. Non-privileged; evidence mounted read-only.
- **`sift-sentinel`**: the agent: Jupyter (8888), the run viewer (8080), and the unified site (8081). Holds the LangGraph orchestrator and MCP client.

The agent reaches the tools only over the internal bridge; the MCP port is never published to the host.

## Commands

The pipeline `.venv` is Linux-built inside the container. **Never run `uv` against it from Windows** (it corrupts the env). All Python execution happens in the container.

```bash
# Bring up the stack (from repo root)
cd docker && docker compose up -d

# Run the full test suite (inside the container; cwd is /workspace = experiments/slice-2-notebook)
docker compose exec sift-sentinel uv run pytest -q

# Run a single test file or a single test by name
docker compose exec sift-sentinel uv run pytest tests/test_critic.py -q
docker compose exec sift-sentinel uv run pytest tests/test_critic.py -k "R_05" -q

# Run one forensic case end to end (planner pauses for human plan approval)
docker compose exec sift-sentinel uv run python run_case.py \
  --case my-case \
  --e01 /mnt/hackathon/my-case/disk.E01 \
  --memory-image /mnt/hackathon/my-case/memory.raw \
  --memory-profile Win10x64_19041
# --e01 / --memory-image are individually optional (at least one required);
# --memory-image requires --memory-profile. Paths are container paths:
# HACKATHON-2026/ on the host = /mnt/hackathon/ inside.

# Build the submission PDF (Node, runs on host)
cd scripts/build-submission-pdf && npm install && npm run build
```

Per-case artifacts (plan, evidence, findings, critic-disagreement log, ledger) land under `experiments/slice-2-notebook/out/runs/<case>/<run-id>/`.

## Fail-fast gate (enforced, not optional)

`.failfast.list` enforces probe-before-edit on the runtime files it globs (`pipeline/*.py`, `pipeline/mcp/*.py`, the synthetic-workstation files). A PreToolUse hook and a git pre-commit hook both check for a recent probe marker. Before editing an enforced file, run an execution probe against the live container:

```bash
scripts/probe.sh experiments/slice-2-notebook/pipeline/nodes.py -- <probe-command that actually runs the new code>
```

`ast.parse` is not a probe. The probe must execute against the real runtime and exit 0 before you edit the target.

## Cost discipline (this project bills real money on OpenRouter calls)

Every LLM call must print a cost breakdown before and after, read from the provider usage object (`_llm_cost_pre` / `_llm_cost_post` in `pipeline/nodes.py`). Any tool output added to an LLM-facing bundle must have a worst-case size guard (tested on a domain controller, not just a workstation) and a code-enforced trim if it can exceed ~50 KB. Both rules exist because of past incidents; see the global `CLAUDE.md` for the full protocol. The `claude` CLI itself is covered by the user's Max plan (zero cost); only the OpenRouter pipeline calls are pay-per-token.

## Learning loop

`pipeline/learned_rules.jsonl` holds promoted detection rules generated by `scripts/learn_from_misses.py` (Claude Haiku reads scored misses and drafts `extract_location` / `counter_rule` entries). Promotion is human-gated through the dashboard. A daily VPS cron loop (22:30 UTC) plants synthetic AI-attacker artifacts, runs the sentinel, and scores per-artifact PASS/MISS. Run new test cases on the local Docker stack, not the VPS (the VPS is reserved for the cron loop).
