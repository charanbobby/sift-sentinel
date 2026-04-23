"""LangGraph runtime — `PipelineState`, helper functions, and `build_graph()`.

Extracted from slice2.ipynb cell C4 at Slice 5 Step 7 (see docs/runbooks/slice-5-
runbook.md §Step 7b). Pure Python — no I/O, no LLM calls, no MCP. Those belong
in `pipeline/nodes.py`; this module just defines the shared state contract and
assembles the compiled graph.

Key Slice-5 shape changes vs. the Slice-3 notebook version:
  - `raw_results: list[RawResult]` replaced by `evidence: list[EvidenceRecord]`
    (server returns EvidenceRecord under the dual-channel boundary; see schemas).
  - `capability_token: CapabilityToken | None` threads the token issued after
    human plan approval through every downstream MCP call (Step 8 wires the
    issue-point; Step 7 just reserves the field so execute_node can read it).
  - `plan_digest: str | None` persisted on the state so execute_node can pass
    it to each MCP call without re-hashing the ToolPlan.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from pydantic import BaseModel

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from pipeline.schemas import (
    CapabilityToken,
    Candidates,
    EvidenceRecord,
    Findings,
    ToolPlan,
)
# `plan_hash` reuses the canonical `compute_plan_digest` so the Critic's
# failed_plan_hashes dedup, the orchestrator's plan_digest label, and the
# capability-token's plan_digest binding all live in the same hash space. One
# definition, one set of equivalence classes — a re-plan that re-emits the
# exact same plan canonically hashes identically in all three places.
from pipeline.mcp.tokens import compute_plan_digest as plan_hash


# ---- Pipeline state (one object flows through every node) ----
class PipelineState(BaseModel):
    """LangGraph `StateGraph` channel-dict. Pydantic on purpose — every node's
    input/output contract validates against this class.

    Mutable default fields (list, dict) use `default_factory` via Pydantic's
    built-in behavior for typed defaults; re-assignment through the node return-
    dict is the only legal mutation path (`graph.invoke()` merges, doesn't
    alias).
    """

    question: str

    # run_id = one full graph.invoke() call → one Langfuse session. Generated
    # fresh per invoke (the notebook mints it in C6). user_id stays CASE_ID so
    # all runs of one case can still be filtered together. Default "" lets
    # stubs + probes run without one — real phases always set it before invoke.
    run_id: str = ""

    candidates: Optional[Candidates] = None
    tool_plan: Optional[ToolPlan] = None

    # ---- Slice 5 Step 7 additions ----
    plan_digest: Optional[str] = None
    capability_token: Optional[CapabilityToken] = None
    evidence: list[EvidenceRecord] = []   # replaces raw_results
    # ---- end Slice-5 additions ----

    findings: Optional[Findings] = None

    # ---- Slice 3 Phase B state (Critic retry loop) ----
    iteration: int = 0
    attempts_per_finding: dict[int, int] = {}
    tokens_used: int = 0
    # typed loosely to avoid forward-ref issues with pipeline.schemas.CritiqueResult
    critique_results: list = []
    corrective_instruction: Optional[str] = None

    # ---- Slice 3 Phase C: plan-hash dedup (L3 primitive #1) ----
    failed_plan_hashes: list[str] = []


# ---- Helpers (moved from notebook C4) ----
# `plan_hash` is the `compute_plan_digest` import above. Accepts a `ToolPlan`;
# the re-export keeps the C4-era call-site name intact across the node-lift.


def compute_thread_id(case_id: str, run_uuid: str) -> str:
    """sha256-derived LangGraph `thread_id` bound to `(case_id, run_uuid)`.
    Forensic-integrity guard: resumed graphs can only read state that was
    checkpointed under the same thread_id, so cross-case evidence contamination
    on a multi-case pipeline is structurally impossible.
    """
    return hashlib.sha256(f"{case_id}::{run_uuid}".encode("utf-8")).hexdigest()


# ---- Graph builder ----

def build_graph(*, checkpointer=None):
    """Construct the StateGraph, wire nodes + conditional edges, compile.

    `checkpointer=None` installs a fresh `MemorySaver` — use that in the
    notebook and in probes. Slice 6 swaps in a durable backend; signature
    stays the same.

    Node implementations live in `pipeline.nodes`; imported lazily here so
    `pipeline.graph` stays importable from `pipeline.nodes` (nodes need
    `PipelineState` at module scope for type hints).
    """
    from pipeline.nodes import (
        extract_node,
        plan_node,
        execute_node,
        interpret_node,
        critic_node,
        human_review_node,
        debounce_before_plan,
        debounce_before_interpret,
    )
    from pipeline.critic import critic_edge

    builder = StateGraph(PipelineState)
    builder.add_node("extract",                    extract_node)
    builder.add_node("plan",                       plan_node)
    builder.add_node("execute",                    execute_node)
    builder.add_node("interpret",                  interpret_node)
    builder.add_node("critic",                     critic_node)
    builder.add_node("human_review",               human_review_node)
    builder.add_node("debounce_before_plan",       debounce_before_plan)
    builder.add_node("debounce_before_interpret",  debounce_before_interpret)

    builder.add_edge(START,        "extract")
    builder.add_edge("extract",    "plan")
    builder.add_edge("plan",       "execute")
    builder.add_edge("execute",    "interpret")
    builder.add_edge("interpret",  "critic")
    builder.add_conditional_edges(
        "critic",
        critic_edge,
        {
            "commit":       END,
            "re_interpret": "debounce_before_interpret",
            "re_plan":      "debounce_before_plan",
            "escalate":     "human_review",
        },
    )
    builder.add_edge("debounce_before_plan",      "plan")
    builder.add_edge("debounce_before_interpret", "interpret")
    builder.add_edge("human_review", END)

    if checkpointer is None:
        checkpointer = MemorySaver()
    return builder.compile(checkpointer=checkpointer)


__all__ = [
    "PipelineState",
    "plan_hash",
    "compute_thread_id",
    "build_graph",
]
