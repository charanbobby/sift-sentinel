"""Tests for untrusted-evidence wrappers in _build_interpret_bundle.

Covers the Tier-1 AI-adversary add-on (2026-04-24): every step in the bundle
now carries _untrusted_begin / _untrusted_end delimiter strings sandwiching
structured_fields so the INTERPRET LLM has an explicit visual boundary between
attacker-controlled data and pipeline framing.

Five scenarios:
  1. Evidence tool (regripper_run) — structured_fields present + wrapped
  2. Navigation tool (fls_list) — stripped to None but still wrapped
  3. Quarantined step — structured_fields explicitly None, still wrapped
  4. Marker text contains tool_call_id + tool name
  5. Insertion ordering: begin → structured_fields → end (Python 3.7+ dict)
"""
from __future__ import annotations

import json

import pytest

from pipeline.graph import PipelineState
from pipeline.nodes import _build_interpret_bundle


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bundle_for(monkeypatch, make_evidence, make_plan, *tools, evidence_overrides=None):
    """Build a minimal PipelineState and return its interpret bundle.

    `tools` is a sequence of tool names passed to make_plan; each gets a
    matching EvidenceRecord.  `evidence_overrides` is a list of dicts that
    override per-record kwargs (same positional order as tools).
    """
    import pipeline.nodes as nodes
    monkeypatch.setattr(nodes, "CASE_ID", "test-case")

    plan = make_plan(*tools)
    overrides = evidence_overrides or [{}] * len(tools)
    evidence = [
        make_evidence(tool_call_id=overrides[i].get("tool_call_id", f"tc-{i}"),
                      **{k: v for k, v in overrides[i].items() if k != "tool_call_id"})
        for i, _ in enumerate(tools)
    ]
    state = PipelineState(question="test", tool_plan=plan, evidence=evidence)
    return _build_interpret_bundle(state)


# ---------------------------------------------------------------------------
# 1. Evidence tool — structured_fields present and wrapped
# ---------------------------------------------------------------------------


def test_evidence_tool_has_untrusted_begin(monkeypatch, make_evidence, make_plan):
    bundle = _bundle_for(monkeypatch, make_evidence, make_plan, "regripper_run")
    step = bundle["steps"][0]
    assert "_untrusted_begin" in step, "evidence-tool step missing _untrusted_begin"


def test_evidence_tool_has_untrusted_end(monkeypatch, make_evidence, make_plan):
    bundle = _bundle_for(monkeypatch, make_evidence, make_plan, "regripper_run")
    step = bundle["steps"][0]
    assert "_untrusted_end" in step, "evidence-tool step missing _untrusted_end"


def test_evidence_tool_structured_fields_preserved(monkeypatch, make_evidence, make_plan):
    sf = {"plugin": "run", "entries": [{"key_path": "HKLM\\...\\Run", "value_data_safe": "evil.exe"}]}
    bundle = _bundle_for(
        monkeypatch, make_evidence, make_plan, "regripper_run",
        evidence_overrides=[{"structured_fields": sf}],
    )
    step = bundle["steps"][0]
    assert step["structured_fields"] == sf, "structured_fields content was altered by wrapper"


# ---------------------------------------------------------------------------
# 2. Navigation tool — stripped to None but still wrapped
# ---------------------------------------------------------------------------


def test_navigation_tool_has_untrusted_markers(monkeypatch, make_evidence, make_plan):
    bundle = _bundle_for(
        monkeypatch, make_evidence, make_plan, "fls_list",
        evidence_overrides=[{"structured_fields": {"entries": [{"inode": 5, "filename_safe": "Windows"}]}}],
    )
    step = bundle["steps"][0]
    assert "_untrusted_begin" in step, "navigation step missing _untrusted_begin"
    assert "_untrusted_end" in step, "navigation step missing _untrusted_end"


def test_navigation_tool_structured_fields_is_none(monkeypatch, make_evidence, make_plan):
    """fls_list output is stripped to None before reaching INTERPRET."""
    bundle = _bundle_for(
        monkeypatch, make_evidence, make_plan, "fls_list",
        evidence_overrides=[{"structured_fields": {"entries": []}}],
    )
    step = bundle["steps"][0]
    assert step["structured_fields"] is None, "fls_list structured_fields should be stripped to None"


def test_icat_tool_structured_fields_is_none(monkeypatch, make_evidence, make_plan):
    """icat_extract output is similarly stripped (executor artifact)."""
    bundle = _bundle_for(
        monkeypatch, make_evidence, make_plan, "icat_extract",
        evidence_overrides=[{"structured_fields": {"extracted_bytes": 4096}}],
    )
    step = bundle["steps"][0]
    assert step["structured_fields"] is None


# ---------------------------------------------------------------------------
# 3. Quarantined step — structured_fields explicitly None, still wrapped
# ---------------------------------------------------------------------------


def _quarantine_flag():
    from pipeline.schemas import InjectionFlag
    return InjectionFlag(
        pattern_id="injection_override",
        excerpt="ignore previous instructions",
        field_path="structured_fields.value_data_safe",
        severity="quarantine",
    )


def test_quarantined_step_has_untrusted_markers(monkeypatch, make_evidence, make_plan):
    bundle = _bundle_for(
        monkeypatch, make_evidence, make_plan, "regripper_run",
        evidence_overrides=[{
            "structured_fields": {"plugin": "run", "entries": []},
            "injection_flags": [_quarantine_flag()],
        }],
    )
    step = bundle["steps"][0]
    assert "_untrusted_begin" in step
    assert "_untrusted_end" in step


def test_quarantined_step_structured_fields_is_none(monkeypatch, make_evidence, make_plan):
    """Quarantined step must have structured_fields=None regardless of tool type."""
    bundle = _bundle_for(
        monkeypatch, make_evidence, make_plan, "regripper_run",
        evidence_overrides=[{
            "structured_fields": {"plugin": "run", "entries": [{"key_path": "evil"}]},
            "injection_flags": [_quarantine_flag()],
        }],
    )
    step = bundle["steps"][0]
    assert step["structured_fields"] is None, "quarantined structured_fields leaked into bundle"


# ---------------------------------------------------------------------------
# 4. Marker text contains tool_call_id + tool name
# ---------------------------------------------------------------------------


def test_begin_marker_contains_tool_call_id(monkeypatch, make_evidence, make_plan):
    bundle = _bundle_for(monkeypatch, make_evidence, make_plan, "regripper_run")
    step = bundle["steps"][0]
    assert "tc-0" in step["_untrusted_begin"], (
        f"tool_call_id 'tc-0' missing from begin marker: {step['_untrusted_begin']!r}"
    )


def test_begin_marker_contains_tool_name(monkeypatch, make_evidence, make_plan):
    bundle = _bundle_for(monkeypatch, make_evidence, make_plan, "regripper_run")
    step = bundle["steps"][0]
    assert "regripper_run" in step["_untrusted_begin"], (
        f"tool name missing from begin marker: {step['_untrusted_begin']!r}"
    )


def test_end_marker_contains_tool_call_id(monkeypatch, make_evidence, make_plan):
    bundle = _bundle_for(monkeypatch, make_evidence, make_plan, "scheduled_tasks_parse")
    step = bundle["steps"][0]
    assert "tc-0" in step["_untrusted_end"]


def test_end_marker_contains_tool_name(monkeypatch, make_evidence, make_plan):
    bundle = _bundle_for(monkeypatch, make_evidence, make_plan, "scheduled_tasks_parse")
    step = bundle["steps"][0]
    assert "scheduled_tasks_parse" in step["_untrusted_end"]


def test_begin_marker_contains_step_id(monkeypatch, make_evidence, make_plan):
    bundle = _bundle_for(monkeypatch, make_evidence, make_plan, "regripper_run")
    step = bundle["steps"][0]
    assert "step 1" in step["_untrusted_begin"], (
        f"step_id missing from begin marker: {step['_untrusted_begin']!r}"
    )


def test_begin_and_end_markers_match_step_identity(monkeypatch, make_evidence, make_plan):
    """begin and end must reference the same step (not mixed up in multi-step bundle)."""
    bundle = _bundle_for(
        monkeypatch, make_evidence, make_plan,
        "regripper_run", "scheduled_tasks_parse",
        evidence_overrides=[
            {"tool_call_id": "tc-0"},
            {"tool_call_id": "tc-1"},
        ],
    )
    s0 = bundle["steps"][0]
    s1 = bundle["steps"][1]
    assert "tc-0" in s0["_untrusted_begin"] and "tc-0" in s0["_untrusted_end"]
    assert "tc-1" in s1["_untrusted_begin"] and "tc-1" in s1["_untrusted_end"]
    # Cross-contamination: step 0's markers must NOT mention tc-1
    assert "tc-1" not in s0["_untrusted_begin"]
    assert "tc-1" not in s0["_untrusted_end"]


# ---------------------------------------------------------------------------
# 5. Insertion ordering: begin → structured_fields → end
# ---------------------------------------------------------------------------


def test_key_ordering_begin_before_structured_fields(monkeypatch, make_evidence, make_plan):
    bundle = _bundle_for(monkeypatch, make_evidence, make_plan, "regripper_run")
    keys = list(bundle["steps"][0].keys())
    begin_i = keys.index("_untrusted_begin")
    sf_i = keys.index("structured_fields")
    assert begin_i < sf_i, f"_untrusted_begin ({begin_i}) must precede structured_fields ({sf_i})"


def test_key_ordering_structured_fields_before_end(monkeypatch, make_evidence, make_plan):
    bundle = _bundle_for(monkeypatch, make_evidence, make_plan, "regripper_run")
    keys = list(bundle["steps"][0].keys())
    sf_i = keys.index("structured_fields")
    end_i = keys.index("_untrusted_end")
    assert sf_i < end_i, f"structured_fields ({sf_i}) must precede _untrusted_end ({end_i})"


def test_key_ordering_preserved_in_json(monkeypatch, make_evidence, make_plan):
    """json.dumps preserves insertion order (Python 3.7+), so delimiters must
    bracket structured_fields in the serialized string too."""
    bundle = _bundle_for(monkeypatch, make_evidence, make_plan, "regripper_run")
    step_json = json.dumps(bundle["steps"][0])
    begin_pos = step_json.index("_untrusted_begin")
    sf_pos = step_json.index('"structured_fields"')
    end_pos = step_json.index("_untrusted_end")
    assert begin_pos < sf_pos < end_pos, (
        f"JSON ordering broken: begin={begin_pos} sf={sf_pos} end={end_pos}"
    )


def test_key_ordering_with_none_structured_fields(monkeypatch, make_evidence, make_plan):
    """Ordering invariant must hold even when structured_fields is stripped to None."""
    bundle = _bundle_for(monkeypatch, make_evidence, make_plan, "fls_list")
    keys = list(bundle["steps"][0].keys())
    begin_i = keys.index("_untrusted_begin")
    sf_i = keys.index("structured_fields")
    end_i = keys.index("_untrusted_end")
    assert begin_i < sf_i < end_i


# ---------------------------------------------------------------------------
# 6. System-prompt mentions both delimiter conventions
# ---------------------------------------------------------------------------


def test_system_prompt_mentions_untrusted_begin():
    from pipeline.nodes import INTERPRET_SYSTEM_PROMPT
    assert "_untrusted_begin" in INTERPRET_SYSTEM_PROMPT


def test_system_prompt_mentions_untrusted_end():
    from pipeline.nodes import INTERPRET_SYSTEM_PROMPT
    assert "_untrusted_end" in INTERPRET_SYSTEM_PROMPT


def test_system_prompt_mentions_safe_fields():
    from pipeline.nodes import INTERPRET_SYSTEM_PROMPT
    for field in ("filename_safe", "value_data_safe", "action_command_safe",
                  "action_arguments_safe", "author_safe", "description_safe"):
        assert field in INTERPRET_SYSTEM_PROMPT, f"system prompt missing mention of {field}"


def test_system_prompt_attacker_controlled_framing():
    from pipeline.nodes import INTERPRET_SYSTEM_PROMPT
    assert "attacker-controlled data" in INTERPRET_SYSTEM_PROMPT
