# Architecture — Find Evil Hackathon

**Last updated:** 2026-04-24
**Audience:** hackathon judges. Maintainers: see [architecture-detailed.md](architecture-detailed.md) for full schemas, data-flow walkthrough, and threat model.
**Visual:** [architecture.html](architecture.html) — styled pipeline diagram.

---

## At a glance

| | |
|---|---|
| **Pipeline** | `E01 → EXTRACT → PLAN → gates → EXECUTE(MCP) → INTERPRET → CRITIC → findings.json` |
| **Architectural pattern** | Two of the contest's four supported patterns, layered: **Custom MCP Server (#2)** (typed forensic tools, server-side path allow-listing, capability-token verification, injection scanning) plus **Multi-Agent / Workflow (#3)** (the LangGraph state machine of named stages). The LangGraph topology is the "comparable agentic architecture" the contest rules explicitly permit. |
| **What's shipped** | L2 end-to-end with 5/5 MCP tools, 11/13 active Critic rules (+ R_13 stub), LangGraph topology, Langfuse tracing, Slice 5 full stack (HTTP MCP transport, capability tokens, dual-channel handler, injection-quarantine wiring), 128-test pytest suite, **canary tripwire on the INTERPRET bundle** |
| **What's next** | Slice 6 (bounded Reference Dataset + L3 ship + Accuracy Report) · AI-adversary detection demo only if it stays evidence-anchored |
| **Headline trust claim** | *Replayable auditability for a research workflow, with explicit defender-AI integrity controls.* We defend the **agent's context** from injected evidence and **detect adversarial attempts to manipulate the defender LLM itself**; we do **not** defend the Python runtime from a hijacked agent. |
| **Out of scope** | Memory / network / evtx forensics · non-Windows filesystems · seccomp / microVM isolation · courtroom admissibility |

Status legend: ✅ shipped • 🟡 in progress • ⬜ defined, not built

---

## 1. The pipeline (one diagram)

Happy path is solid; retry is dotted; MCP is a subgraph inside EXECUTE. A more detailed four-diagram breakdown (retry, MCP zoom, cross-cutting audit) lives in [architecture-detailed.md §2](architecture-detailed.md#2-pipeline-diagrams).

```mermaid
flowchart LR
    E01[/"E01<br/>(read-only)"/]
    EXT["EXTRACT"]
    PLN["PLAN"]
    GATE{{"gates<br/>invariants + approve"}}
    subgraph EXEC["EXECUTE — MCP boundary"]
      direction TB
      TOK{"token check"}
      T["5 typed tools<br/>fsstat · fls · icat · regripper · tasks"]
      DUAL["dual-channel handler"]
      TOK --> T --> DUAL
    end
    INT["INTERPRET"]
    CRIT["CRITIC<br/>13 rules"]
    OUT[/"findings.json<br/>+ plan_digest"/]
    HUMAN[["human_review"]]

    E01 --> EXT --> PLN --> GATE --> EXEC --> INT --> CRIT --> OUT

    GATE -.->|invariant fail| PLN
    CRIT -.->|rule fail → dedup + debounce| PLN
    CRIT -.->|budget exceeded| HUMAN
    GATE -.->|reject| HUMAN
    EXEC -.->|token invalid / injection| HUMAN
    INT -.->|canary leak → run halt| HUMAN
```

**What each stage does, one line each:**

- **EXTRACT** — enumerate candidate artifact paths from the investigation question. Gemini 3.1 Flash Lite, JSON mode.
- **PLAN** — emit a typed `ToolPlan` with a `depends_on` DAG. Claude Sonnet 4.6, prompt-cached.
- **Gates** — structural invariants (e.g. every `regripper_run` must have an `icat_extract` upstream) + human approval at L1/L2, policy file at L3.
- **EXECUTE** — dispatch each tool via MCP. Capability token scoped to `(case_id, tools, paths, plan_digest, expiry)`. Dual-channel handler splits raw bytes (→ ledger), structured fields (→ agent), injection-flagged content (→ quarantine).
- **INTERPRET** — synthesize typed `Finding`s with DFIR classification. Pydantic `model_validator` auto-populates ATT&CK fields; LLM output on those fields is discarded. Per-run **canary tripwire** (`_canary` field embedded in the bundle): if the LLM response echoes the nonce, the instruction/data boundary leaked — write `CANARY_LEAK` audit entry and halt the run.
- **CRITIC** — 13 deterministic Python rules. Fail routes through **plan-hash dedup** (no sycophantic retry) then **pre_retry_debounce** (clear volatile state) back to PLAN or INTERPRET.

---

## 2. Component map

| Component | Status | Where |
|---|---|---|
| `EXTRACT` node (Gemini 3.1 Flash Lite) | ✅ | [`slice2.ipynb`](../../experiments/slice-2-notebook/slice2.ipynb) C5 |
| `PLAN` node (Claude Sonnet 4.6, cached) | ✅ | `slice2.ipynb` C6 |
| Structural invariants | ✅ | `slice2.ipynb` C6 |
| `plan_approve` gate | ✅ | LangGraph conditional edge |
| `EXECUTE` node + HTTP MCP server | ✅ | `slice2.ipynb` C8 + [`mcp_server/server.py`](../../experiments/slice-2-notebook/mcp_server/server.py) |
| 5 typed MCP tools | ✅ | `mcp_server/server.py` |
| Capability-token verification | ✅ Slice 5 | `mcp_server/server.py` + [`pipeline/mcp/tokens.py`](../../experiments/slice-2-notebook/pipeline/mcp/tokens.py) |
| Dual-channel evidence handler | ✅ Slice 5 | `mcp_server/server.py` + [`pipeline/mcp/injection_scanner.py`](../../experiments/slice-2-notebook/pipeline/mcp/injection_scanner.py) |
| `INTERPRET` node | ✅ (lifted Slice 5 Step 7) | [`pipeline/nodes.py`](../../experiments/slice-2-notebook/pipeline/nodes.py) `interpret_node` |
| Canary tripwire (defender-AI integrity) | ✅ Tier-1 (2026-04-24) | [`pipeline/nodes.py`](../../experiments/slice-2-notebook/pipeline/nodes.py) `_check_canary_leak` + [`pipeline/graph.py`](../../experiments/slice-2-notebook/pipeline/graph.py) `mint_canary` |
| `CRITIC` node | ✅ 11 active + R_13 stub (Phase C) | [`pipeline/critic.py`](../../experiments/slice-2-notebook/pipeline/critic.py) + `pipeline/nodes.py` `critic_node` |
| `human_review` escalation sink | ✅ | `pipeline/nodes.py` `human_review_node` |
| `pre_retry_debounce` + plan-hash dedup | ✅ Phase C | `pipeline/nodes.py` `debounce_before_*` + `pipeline/graph.py` `plan_hash` |
| Thread-scoped checkpointer | 🟡 Phase C | `slice2.ipynb` C4 |
| Integrity ledger (SHA-256 linear hash chain) | ⬜ Slice 6 | separate from case folder |
| `verify_chain_of_custody.py` replay tool | ⬜ Slice 6 | |
| Langfuse tracing | ✅ | throughout |
| `score.py` precision/recall/hallucination | ✅ base / 🟡 autonomy metrics | [`score.py`](../../experiments/slice-2-notebook/score.py) |

---

## 3. Trust boundaries — what we do and do not claim

**Four layers. Each catches a different failure class.**

Every boundary below is tagged **Architectural** (enforced in code or container topology, so it holds even if the LLM is fully compromised) or **Prompt-based** (an instruction the LLM is asked to follow, backstopped by an architectural control). The load-bearing boundaries are architectural by design; the prompt-based layer is an inner convenience, never the last line of defense.

| Adversary | Defense | Enforcement |
|---|---|---|
| Prompt injection embedded in E01 content (filenames, registry values, document bodies) | **Dual-channel handler:** raw bytes go to the ledger, structured fields to the agent, flagged content to quarantine. The hijack payload never reaches the LLM context. | **Architectural:** server-side code splits the channels before the LLM is invoked |
| Adversarial attempt to manipulate the defender LLM itself (boundary leak: a structured-field escape persuading the model to treat data as instructions) | **Canary tripwire:** per-run random nonce (`_canary`) embedded in the INTERPRET bundle. If the response echoes the nonce, the instruction/data boundary leaked, so the run is halted and a `CANARY_LEAK` audit entry is written. | **Architectural:** deterministic post-response check in `_check_canary_leak`, no LLM in the loop |
| LLM-internal failure (sycophancy, spec drift, silent tool-failure swallowing, hallucinated relationships) | **13-rule Critic + Hadi3 negative-case validation** | **Architectural:** deterministic Python rules; no AI in the critic loop |
| Accidental agent drift (proposes a tool or path outside scope) | **Capability tokens** at the MCP boundary (application-layer routing) | **Architectural:** HMAC verification server-side; out-of-scope calls rejected before the tool runs |
| Post-hoc tampering with recorded evidence | **SHA-256 linear hash chain:** altering entry N breaks the hash embedded in entry N+1 | **Architectural:** cryptographic chain, verifiable offline |
| Analyst-discipline lapses (failing to rule out DFIR tools / vendor products, over-confident classification, mislabeled ATT&CK fields) | **Planner / interpreter prompt discipline:** rule-out instructions, the confidence rubric, and classification guidance in the system prompts | **Prompt-based:** an instruction the LLM may ignore; every finding it produces is re-checked by the architectural Critic above, which rejects any that violate the discipline |

**Explicitly out of scope:** local root compromise · supply-chain attacks on packages / images / model providers · network-layer attackers · courtroom admissibility.

**The honest isolation caveat.** LangGraph and the MCP server now run in separate containers over internal HTTP MCP, with no Docker socket or forensic tool binaries in the agent container. Capability tokens are therefore load-bearing for MCP tool routing, but they are still **not** a cryptographic sandbox against container escape, host compromise, model-provider compromise, or a bug in the Python runtime itself. Seccomp-BPF, eBPF-LSM, or microVM wrapping would close more of that gap; documented as an extension point, not in scope for 8 weeks.

---

## 4. Autonomy climb

Components activate progressively. L4 (post-deployment Forensic Auditor) is **not** in the submission narrative.

**Scope correction:** the submission goal stops at L3. With only a handful of fully ground-truthed cases, we should not imply that the project reaches a calibrated autonomous-auditor stage. Any sampled audit across non-ground-truthed cases is supporting evidence for the Accuracy Report, not a headline goal.

| | L1 Assisted | L2 Guarded | L3 Exception-Based |
|---|---|---|---|
| `plan_approve` | human always | human always | policy file (auto unless flagged) |
| Critic retry loop | disabled (fail → human) | bounded retry | bounded + plan-hash dedup + debounce |
| Capability tokens | per-plan | per-plan | per-plan, shorter expiry |
| Dual-channel handler | active | active | active |
| Thread-scoped checkpointer | optional | recommended | required |
| Confidence rubric | advisory | advisory + escalate Low | auto-escalate Low |

**Headline: L2 shipped, L3 is the submission target.** Every slice of new autonomy is matched by a new gate.

---

## 5. Where detail lives

For anything below:

- **Data flow end-to-end (13 steps)** → [architecture-detailed.md §4](architecture-detailed.md#4-data-flow--one-case-end-to-end)
- **`PipelineState` field-level write/read discipline** → [architecture-detailed.md §5](architecture-detailed.md#5-pipelinestate-schema)
- **MCP tool schemas** → [architecture-detailed.md §6](architecture-detailed.md#6-mcp-tool-surface)
- **Critic rule catalog (R_01–R_13, what each catches, phase)** → [architecture-detailed.md §7](architecture-detailed.md#7-critic-rule-catalog-13-rules-r_01r_13)
- **What's deliberately out of scope** → [architecture-detailed.md §9](architecture-detailed.md#9-whats-deliberately-not-in-this-architecture)

When this page changes, edit `architecture-detailed.md` first — then roll the deltas up to here and to [architecture.html](architecture.html).
