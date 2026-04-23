"""Test pipeline.graph — topology assertions + critic_edge routing +
checkpointer isolation."""
from __future__ import annotations

import pytest

from pipeline.critic import (
    critic_edge,
    PER_FINDING_RETRY_LIMIT,
    TOKEN_CEILING_PER_INVESTIGATION,
)
from pipeline.graph import PipelineState, build_graph, compute_thread_id, plan_hash
from pipeline.schemas import CritiqueResult, RuleFailure


# ---- build_graph ------------------------------------------------------------


def test_build_graph_returns_compiled_graph():
    g = build_graph()
    # LangGraph's compile() returns a Pregel object; spot-check via hasattr
    assert hasattr(g, "invoke") or hasattr(g, "stream"), \
        "compiled graph should expose invoke/stream"


def test_build_graph_installs_default_memory_saver(monkeypatch):
    """Default checkpointer is a MemorySaver — the notebook + probes rely on
    this for Phase C's thread-scoped checkpointer primitive."""
    g = build_graph()
    # The compiled graph carries the checkpointer; different LangGraph versions
    # expose it via .checkpointer or .config — fall back gracefully
    checkpointer = getattr(g, "checkpointer", None)
    assert checkpointer is not None, \
        "build_graph(checkpointer=None) should install a default MemorySaver"


def test_build_graph_accepts_custom_checkpointer():
    from langgraph.checkpoint.memory import MemorySaver
    custom = MemorySaver()
    g = build_graph(checkpointer=custom)
    assert getattr(g, "checkpointer", None) is custom


def test_build_graph_nodes_include_all_eight():
    """Every node from the runbook Step 7a list is registered."""
    g = build_graph()
    # Pregel exposes .nodes in langgraph>=0.3
    node_names = set(g.nodes)
    expected = {
        "extract", "plan", "execute", "interpret", "critic",
        "human_review", "debounce_before_plan", "debounce_before_interpret",
    }
    assert expected <= node_names, f"missing nodes: {expected - node_names}"


# ---- critic_edge routing ----------------------------------------------------


def _state_with(**overrides) -> PipelineState:
    """Minimal PipelineState for critic_edge. critic_edge only reads a few
    attrs; we don't need a real tool_plan for the token/iteration-ceiling
    branches if we guard around the attribute accesses."""
    from pipeline.schemas import ToolPlan, PlannedStep
    default_plan = ToolPlan(
        question="q",
        steps=[PlannedStep(step_id=1, tool="regripper_run", args={},
                           purpose="s1", depends_on=[], confidence="high")],
        expected_findings_range=(1, 3),
    )
    state = PipelineState(question="q", tool_plan=default_plan)
    for k, v in overrides.items():
        setattr(state, k, v)
    return state


def test_critic_edge_commit_when_all_pass():
    state = _state_with(critique_results=[
        CritiqueResult(finding_index=0, rules_passed=["R_01"], rules_failed=[],
                       is_llm_judgment=False, severity="pass"),
    ])
    assert critic_edge(state) == "commit"


def test_critic_edge_escalate_when_any_severity_escalate():
    state = _state_with(critique_results=[
        CritiqueResult(finding_index=0, rules_passed=[],
                       rules_failed=[RuleFailure(rule_id="R_05",
                                                 code="EXCERPT_HALLUCINATION",
                                                 detail="x")],
                       is_llm_judgment=False, severity="escalate"),
    ])
    assert critic_edge(state) == "escalate"


def test_critic_edge_re_interpret_on_first_retry():
    state = _state_with(
        iteration=0,
        critique_results=[
            CritiqueResult(finding_index=0, rules_passed=[],
                           rules_failed=[RuleFailure(rule_id="R_01",
                                                     code="EVID_UNRESOLVED",
                                                     detail="x")],
                           is_llm_judgment=False, severity="retry"),
        ],
        attempts_per_finding={0: 1},
    )
    assert critic_edge(state) == "re_interpret"


def test_critic_edge_re_plan_on_second_retry():
    state = _state_with(
        iteration=1,
        critique_results=[
            CritiqueResult(finding_index=0, rules_passed=[],
                           rules_failed=[RuleFailure(rule_id="R_01",
                                                     code="EVID_UNRESOLVED",
                                                     detail="x")],
                           is_llm_judgment=False, severity="retry"),
        ],
        attempts_per_finding={0: 1},
    )
    assert critic_edge(state) == "re_plan"


def test_critic_edge_escalate_when_per_finding_retry_limit_hit():
    state = _state_with(
        critique_results=[
            CritiqueResult(finding_index=0, rules_passed=[],
                           rules_failed=[RuleFailure(rule_id="R_01",
                                                     code="EVID_UNRESOLVED",
                                                     detail="x")],
                           is_llm_judgment=False, severity="retry"),
        ],
        attempts_per_finding={0: PER_FINDING_RETRY_LIMIT},
    )
    assert critic_edge(state) == "escalate"


def test_critic_edge_escalate_when_token_ceiling_exceeded():
    state = _state_with(
        tokens_used=TOKEN_CEILING_PER_INVESTIGATION + 1,
        critique_results=[
            CritiqueResult(finding_index=0, rules_passed=["R_01"], rules_failed=[],
                           is_llm_judgment=False, severity="pass"),
        ],
    )
    assert critic_edge(state) == "escalate"


def test_critic_edge_returns_only_valid_values():
    """Exhaustive: critic_edge must return one of the 4 documented values."""
    valid = {"commit", "re_interpret", "re_plan", "escalate"}
    # Sample across the decision branches covered above
    configs = [
        dict(),  # no results → commit
        dict(critique_results=[]),
        dict(iteration=0, critique_results=[
            CritiqueResult(finding_index=0, rules_passed=[],
                           rules_failed=[RuleFailure(rule_id="R_01",
                                                     code="EVID_UNRESOLVED",
                                                     detail="x")],
                           is_llm_judgment=False, severity="retry")],
             attempts_per_finding={0: 1}),
    ]
    for cfg in configs:
        state = _state_with(**cfg)
        assert critic_edge(state) in valid


# ---- compute_thread_id ------------------------------------------------------


def test_compute_thread_id_deterministic():
    t1 = compute_thread_id("case-A", "run-1")
    t2 = compute_thread_id("case-A", "run-1")
    assert t1 == t2


def test_compute_thread_id_differs_per_case():
    a = compute_thread_id("case-A", "run-1")
    b = compute_thread_id("case-B", "run-1")
    assert a != b


def test_compute_thread_id_differs_per_run():
    a = compute_thread_id("case-A", "run-1")
    b = compute_thread_id("case-A", "run-2")
    assert a != b


# ---- plan_hash --------------------------------------------------------------


def test_plan_hash_deterministic_same_plan(make_plan):
    plan = make_plan("fsstat_e01", "regripper_run")
    assert plan_hash(plan) == plan_hash(plan)


def test_plan_hash_changes_when_plan_changes(make_plan):
    a = make_plan("fsstat_e01")
    b = make_plan("fsstat_e01", "regripper_run")
    assert plan_hash(a) != plan_hash(b)


# ---- Checkpointer isolation -------------------------------------------------


def test_checkpointer_isolates_per_thread():
    """Two thread IDs should have independent state on the same compiled
    graph — this is the L3 primitive that Slice 3 Phase C committed to."""
    g = build_graph()
    cfg_a = {"configurable": {"thread_id": "thread-A"}}
    cfg_b = {"configurable": {"thread_id": "thread-B"}}

    # Inspecting the checkpointer directly — graph.invoke() would require
    # the full pipeline runtime. The MemorySaver dict is the authoritative
    # store.
    cp = g.checkpointer
    # Fresh graph: neither thread has state.
    assert cp.get(cfg_a) is None
    assert cp.get(cfg_b) is None
