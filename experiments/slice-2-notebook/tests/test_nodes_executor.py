"""Test pipeline.nodes executor helpers.

Covers `_is_blocked_by_upstream`: the pure decision the execute_node loop uses
to skip the transitive descendants of a step whose placeholder failed to
resolve. The integration path (the loop itself) is exercised by live runs.
"""
from __future__ import annotations

from pipeline.nodes import _is_blocked_by_upstream
from pipeline.schemas import PlannedStep


def _step(step_id: int, depends_on: list[int]) -> PlannedStep:
    return PlannedStep(
        step_id=step_id,
        tool="fls_list",
        purpose="test",
        args={},
        depends_on=depends_on,
        confidence="high",
    )


def test_no_deps_never_blocked_even_when_other_steps_blocked():
    # Memory-channel `volatility_run` steps land here: depends_on=[] should
    # always run, even when the disk subgraph has failures.
    assert _is_blocked_by_upstream(_step(20, []), {19}) is False
    assert _is_blocked_by_upstream(_step(20, []), {1, 5, 19}) is False


def test_single_dep_clean_not_blocked():
    assert _is_blocked_by_upstream(_step(2, [1]), set()) is False


def test_single_dep_in_block_set_blocks():
    assert _is_blocked_by_upstream(_step(2, [1]), {1}) is True


def test_any_dep_in_block_set_blocks():
    assert _is_blocked_by_upstream(_step(3, [1, 2]), {2}) is True


def test_multi_dep_none_in_block_set_not_blocked():
    assert _is_blocked_by_upstream(_step(3, [1, 2]), {99}) is False


def test_transitive_block_via_chain_dep():
    # If step 20 fails (added to blocked_step_ids), step 21 with
    # depends_on=[20] is blocked. This is what propagates the block in
    # topological order through the executor loop.
    assert _is_blocked_by_upstream(_step(21, [20]), {19, 20}) is True
