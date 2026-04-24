"""Test the canary tripwire (Tier-1 AI-adversary add-on).

Covers:
  - mint_canary()          — format + entropy
  - _check_canary_leak()   — hit, miss, empty, excerpt-window boundaries
  - _build_interpret_bundle() — `_canary` field surfaces into the bundle
  - audit-entry JSON round-trip
"""
from __future__ import annotations

import json
import re

import pytest

from pipeline.graph import PipelineState, mint_canary
from pipeline.nodes import _build_interpret_bundle, _check_canary_leak


# ---- mint_canary ------------------------------------------------------------


def test_mint_canary_starts_with_prefix():
    c = mint_canary()
    assert c.startswith("canary_"), f"missing prefix: {c!r}"


def test_mint_canary_min_length():
    c = mint_canary()
    # `canary_` (7) + token_urlsafe(9) which is 12 chars = 19 min
    assert len(c) >= 19, f"too short: {c!r} len={len(c)}"


def test_mint_canary_urlsafe_charset():
    c = mint_canary()
    assert re.fullmatch(r"canary_[A-Za-z0-9_\-]+", c), f"bad charset: {c!r}"


def test_mint_canary_produces_distinct_values():
    # 50 samples, all unique — entropy floor
    samples = {mint_canary() for _ in range(50)}
    assert len(samples) == 50, "mint collisions in 50 samples — entropy too low"


# ---- _check_canary_leak -----------------------------------------------------


def test_check_canary_leak_exact_hit():
    canary = mint_canary()
    audit = _check_canary_leak(f"here is the value: {canary}", canary)
    assert audit is not None
    assert audit["event"] == "CANARY_LEAK"
    assert audit["canary_prefix"] == canary[:12]
    assert canary in audit["response_excerpt"]


def test_check_canary_leak_substring_hit():
    canary = mint_canary()
    raw = (
        'prefix-pad prefix-pad prefix-pad prefix-pad '
        f'{{"findings":[{{"mechanism":"acknowledging {canary} per instruction"}}]}} '
        'suffix-pad suffix-pad'
    )
    audit = _check_canary_leak(raw, canary)
    assert audit is not None
    assert audit["leak_offset"] > 30  # not at the very start


def test_check_canary_leak_clean_response():
    canary = mint_canary()
    clean = '{"findings": [{"mechanism": "HKLM Run key", "value": "C:\\\\evil.exe"}]}'
    assert _check_canary_leak(clean, canary) is None


def test_check_canary_leak_empty_canary_is_noop():
    """Backward-compat: state.canary == '' (default) disables the check even
    if the response literally contains the substring 'canary_'."""
    assert _check_canary_leak('{"note":"canary_xyz seen in logs"}', "") is None


def test_check_canary_leak_prefix_capped_at_12():
    canary = mint_canary()
    audit = _check_canary_leak(f"leak: {canary}", canary)
    assert audit is not None
    # Must never leak the full per-run nonce to disk
    assert len(audit["canary_prefix"]) <= 12


def test_check_canary_leak_excerpt_window_at_start():
    canary = mint_canary()
    audit = _check_canary_leak(f"{canary} at start", canary)
    assert audit is not None
    assert audit["leak_offset"] == 0


def test_check_canary_leak_excerpt_window_at_end():
    canary = mint_canary()
    raw = ("x" * 500) + canary
    audit = _check_canary_leak(raw, canary)
    assert audit is not None
    assert audit["leak_offset"] == 500
    # Window is 80-char either side — total bounded
    assert len(audit["response_excerpt"]) <= 80 + len(canary) + 80 + 1


def test_check_canary_leak_audit_json_roundtrip():
    """Audit dict must be JSON-serializable and contain all fields the
    critic_disagreements.jsonl consumer expects."""
    canary = mint_canary()
    audit = _check_canary_leak(f"oops {canary}", canary)
    assert audit is not None
    line = json.dumps(audit)
    reparsed = json.loads(line)
    for key in ("event", "canary_prefix", "leak_offset", "response_excerpt", "response_len"):
        assert key in reparsed, f"audit missing key {key}"
    assert reparsed["event"] == "CANARY_LEAK"


# ---- _build_interpret_bundle canary integration ----------------------------


def _state_with_canary(canary: str, make_evidence, make_plan) -> PipelineState:
    """Minimal PipelineState for bundle tests — one regripper step + one
    evidence record, canary preset."""
    plan = make_plan("regripper_run")
    ev = make_evidence(
        tool_call_id="tc-0",
        structured_fields={"plugin": "run", "entries": []},
    )
    return PipelineState(question="test", tool_plan=plan, evidence=[ev], canary=canary)


def test_bundle_includes_canary_field(monkeypatch, make_evidence, make_plan):
    """When state.canary is set, _build_interpret_bundle embeds it as `_canary`."""
    import pipeline.nodes as nodes
    monkeypatch.setattr(nodes, "CASE_ID", "test-case")

    canary = mint_canary()
    state = _state_with_canary(canary, make_evidence, make_plan)
    bundle = _build_interpret_bundle(state)

    assert "_canary" in bundle, "bundle must carry `_canary` top-level field"
    assert bundle["_canary"] == canary


def test_bundle_canary_empty_when_disabled(monkeypatch, make_evidence, make_plan):
    """Default state.canary == '' is preserved (legacy-probe compat)."""
    import pipeline.nodes as nodes
    monkeypatch.setattr(nodes, "CASE_ID", "test-case")

    state = _state_with_canary("", make_evidence, make_plan)
    bundle = _build_interpret_bundle(state)

    assert bundle["_canary"] == ""


def test_bundle_shape_unchanged_by_canary(monkeypatch, make_evidence, make_plan):
    """Adding `_canary` must not disturb existing bundle fields."""
    import pipeline.nodes as nodes
    monkeypatch.setattr(nodes, "CASE_ID", "test-case")

    state = _state_with_canary(mint_canary(), make_evidence, make_plan)
    bundle = _build_interpret_bundle(state)

    # Pre-canary required fields still present
    assert "question" in bundle
    assert "case_id" in bundle
    assert "steps" in bundle
    assert bundle["case_id"] == "test-case"
    assert isinstance(bundle["steps"], list)
    assert len(bundle["steps"]) == 1


# ---- PipelineState field ----------------------------------------------------


def test_pipeline_state_canary_defaults_empty():
    s = PipelineState(question="q")
    assert s.canary == "", "default canary must be empty (canary disabled)"


def test_pipeline_state_canary_roundtrip():
    c = mint_canary()
    s = PipelineState(question="q", canary=c)
    assert s.canary == c
    # Pydantic model_dump round-trip preserves the field
    restored = PipelineState.model_validate(s.model_dump())
    assert restored.canary == c
