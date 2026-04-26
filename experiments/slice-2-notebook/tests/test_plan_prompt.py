"""Regression tests for `_plan_system_prompt` content.

The PLAN system prompt is the only point in the pipeline where we can constrain
what the planner LLM emits before we pay for an LLM call. Drift in this prompt
is invisible until a real plan misbehaves on a real case, so each line of
prompt guidance that exists because of a real failure mode gets a regression
test here.
"""
from __future__ import annotations

from pipeline.nodes import _plan_system_prompt


def test_disk_only_prompt_forbids_hardcoded_scheduled_task_names() -> None:
    """P2 follow-up (Slice 6 Step 5, 2026-04-26): planner emitted
    `inode_by_name("At1")` on srl-2018-wkstn-05 runs 003 and 005. "At1" is
    XP-era atjob residue and does not exist on Win7+ hosts; the resolver
    correctly failed and (post-P0) skipped only that step. The prompt must
    actively forbid speculative scheduled-task names before any LLM call.
    """
    prompt = _plan_system_prompt(
        case_id="srl-2018-wkstn-05",
        e01_path="/mnt/hackathon/wkstn-05.E01",
    )
    # Concrete XP-era residue names called out as forbidden examples.
    assert "At1" in prompt
    assert "At2" in prompt
    # Mechanism the rule prescribes: enumerate Tasks/ via fls_list rather than
    # speculatively parsing.
    assert "fls_list" in prompt
    assert "Tasks" in prompt
    # Directive itself: "NEVER hardcode" + scope of the prohibition.
    assert "NEVER hardcode" in prompt
    assert "scheduled_tasks_parse" in prompt
    assert "inode_by_name" in prompt


def test_dual_channel_prompt_carries_the_same_rule() -> None:
    """The hard rule must apply with or without a memory image staged. The
    memory branch appends extra rules but must not displace the disk-side
    hard rules.
    """
    prompt = _plan_system_prompt(
        case_id="srl-2018-wkstn-05",
        e01_path="/mnt/hackathon/wkstn-05.E01",
        memory_image_path="/var/lib/find-evil/memory/wkstn-05.img",
        memory_profile="Win7SP1x64",
    )
    assert "NEVER hardcode" in prompt
    assert "At1" in prompt
    assert "scheduled_tasks_parse" in prompt
    # And the memory rules still ride along after the new hard rule.
    assert "Memory-evidence rules" in prompt
    assert "pslist FIRST" in prompt or "Plan `pslist` FIRST" in prompt
