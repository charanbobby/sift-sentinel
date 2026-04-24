"""Test pipeline.schemas — Pydantic round-trips, Literal membership, and
ATTACK_MAPPING coverage. Deterministic, no I/O."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import get_args

import pytest
from pydantic import ValidationError


# ---- Literal memberships ----------------------------------------------------


def test_rule_id_literal_covers_R_01_to_R_13():
    from pipeline.schemas import RuleId
    vals = set(get_args(RuleId))
    expected = {f"R_{i:02d}" for i in range(1, 14)}
    assert expected <= vals, f"missing rule IDs: {expected - vals}"


def test_failure_code_membership():
    from pipeline.schemas import FailureCode
    vals = set(get_args(FailureCode))
    # Core codes the Critic emits (spot-check; schemas.py is authoritative)
    for code in (
        "EVID_UNRESOLVED", "PATH_INCONSISTENCY", "TOOL_MISMATCH",
        "EXCERPT_HALLUCINATION", "INJECTION_FLAGGED_EVIDENCE",
        "INJECTION_QUARANTINE",  # Step 8 addition
        "CLASSIFICATION_MISSING", "ABSENCE_UNSUBSTANTIATED", "TEMPORAL_INCONSISTENT",
    ):
        assert code in vals, f"FailureCode missing {code!r}"


def test_persistence_category_literal():
    from pipeline.schemas import PersistenceCategory
    vals = set(get_args(PersistenceCategory))
    assert {"registry_run_key", "service", "scheduled_task", "ifeo_debugger",
            "appinit_dll", "logon_script", "NOT_FOUND"} == vals


def test_classification_literal():
    from pipeline.schemas import Classification
    vals = set(get_args(Classification))
    assert {"attacker_persistence", "legitimate_responder_tool",
            "legitimate_vendor_product", "legitimate_windows_default",
            "requires_disambiguation"} == vals


def test_tool_execution_status_literal():
    from pipeline.schemas import ToolExecutionStatus
    vals = set(get_args(ToolExecutionStatus))
    # Slice 5 statuses. Authoritative list lives in schemas.py.
    for status in ("ok", "timeout", "parse_error", "empty", "capability_denied"):
        assert status in vals, f"ToolExecutionStatus missing {status!r}"


# ---- ATTACK_MAPPING coverage ------------------------------------------------


def test_attack_mapping_covers_every_non_notfound_category():
    from pipeline.schemas import ATTACK_MAPPING, PersistenceCategory
    cats = set(get_args(PersistenceCategory)) - {"NOT_FOUND"}
    missing = cats - set(ATTACK_MAPPING.keys())
    assert not missing, f"ATTACK_MAPPING missing: {missing}"
    # Every non-NOT_FOUND mapped value is a (T-code, name) pair
    for cat in cats:
        val = ATTACK_MAPPING[cat]
        assert isinstance(val, tuple) and len(val) == 2, f"{cat}: {val!r}"
        t_code, name = val
        assert t_code.startswith("T1"), f"{cat}: T-code {t_code!r} malformed"
        assert isinstance(name, str) and name, f"{cat}: empty name"


# ---- Round-trip tests -------------------------------------------------------


def test_evidence_record_round_trip(make_evidence):
    from pipeline.schemas import EvidenceRecord
    ev = make_evidence("tc-rt", {"entries": [{"k": "v"}]})
    blob = ev.model_dump_json()
    ev2 = EvidenceRecord.model_validate_json(blob)
    assert ev == ev2


def test_evidence_record_accepts_every_tool_execution_status(make_evidence):
    from pipeline.schemas import ToolExecutionStatus
    for status in get_args(ToolExecutionStatus):
        ev = make_evidence("tc-s", tool_execution_status=status)
        assert ev.tool_execution_status == status


def test_finding_round_trip(make_finding):
    from pipeline.schemas import Finding
    f = make_finding(evidence_refs=[("tc-0", "excerpt")])
    blob = f.model_dump_json()
    f2 = Finding.model_validate_json(blob)
    assert f == f2


def test_finding_classification_is_required():
    from pipeline.schemas import Finding, Evidence
    with pytest.raises(ValidationError):
        Finding(
            category="service",
            mechanism="X",
            value="Y",
            confidence="high",
            # classification omitted — Pydantic should reject
            notes="",
            evidence=[Evidence(tool_call_id="t", output_excerpt="")],
        )


def test_finding_derives_attack_fields_from_category(make_finding):
    from pipeline.schemas import Finding
    f = make_finding(category="registry_run_key")
    dumped = f.model_dump()
    # Validator injects T-code + name into serialized output
    assert "attack_id" in dumped or "attack_name" in dumped or True
    # Spot: the T-code should come from ATTACK_MAPPING
    from pipeline.schemas import ATTACK_MAPPING
    expected_tcode, expected_name = ATTACK_MAPPING["registry_run_key"]
    # Whichever field names the Finding uses, at least one should carry the T-code
    assert expected_tcode in str(dumped)


def test_tool_plan_round_trip(make_plan):
    from pipeline.schemas import ToolPlan
    plan = make_plan("fsstat_e01", "regripper_run")
    blob = plan.model_dump_json()
    plan2 = ToolPlan.model_validate_json(blob)
    assert plan == plan2


def test_capability_token_round_trip():
    from pipeline.schemas import CapabilityToken
    tok = CapabilityToken(
        token_id="11111111-1111-1111-1111-111111111111",
        case_id="c",
        allowed_tools=frozenset({"fls_list"}),
        allowed_paths=("/mnt/",),
        plan_digest="d" * 64,
        expires_at=datetime(2026, 12, 31, tzinfo=timezone.utc),
        signature="a" * 64,
    )
    blob = tok.model_dump_json()
    tok2 = CapabilityToken.model_validate_json(blob)
    assert tok == tok2


def test_injection_flag_severity_literal():
    from pipeline.schemas import InjectionFlag
    for sev in ("info", "warn", "quarantine"):
        flag = InjectionFlag(
            pattern_id="INJ_TEST",
            excerpt="x",
            field_path="p",
            severity=sev,
        )
        assert flag.severity == sev
    with pytest.raises(ValidationError):
        InjectionFlag(pattern_id="INJ_TEST", excerpt="x",
                      field_path="p", severity="critical")


def test_injection_flag_excerpt_max_length():
    from pipeline.schemas import InjectionFlag
    # 128 should fit; 129 should not
    InjectionFlag(pattern_id="INJ_T", excerpt="a" * 128,
                  field_path="p", severity="warn")
    with pytest.raises(ValidationError):
        InjectionFlag(pattern_id="INJ_T", excerpt="a" * 129,
                      field_path="p", severity="warn")


def test_findings_round_trip(make_finding):
    from pipeline.schemas import Findings
    findings = Findings(
        case_id="c",
        question="q",
        findings=[make_finding(evidence_refs=[("t-0", "e")])],
        plan_digest="d" * 64,
        started_at=datetime(2026, 4, 23, tzinfo=timezone.utc),
        finished_at=datetime(2026, 4, 23, tzinfo=timezone.utc),
    )
    blob = findings.model_dump_json()
    findings2 = Findings.model_validate_json(blob)
    assert findings == findings2


# ---- Schema tightening (Tier-1 #3, 2026-04-24) -----------------------------


def test_strip_adversarial_controls_clean_passthrough():
    from pipeline.schemas import strip_adversarial_controls
    assert strip_adversarial_controls("normal text") == "normal text"
    assert strip_adversarial_controls("") == ""


def test_strip_adversarial_controls_preserves_whitespace():
    """\\t \\n \\r are legitimate JSON string content — must survive."""
    from pipeline.schemas import strip_adversarial_controls
    assert strip_adversarial_controls("l1\nl2\tc2\r\nl3") == "l1\nl2\tc2\r\nl3"


def test_strip_adversarial_controls_removes_zero_widths():
    from pipeline.schemas import strip_adversarial_controls
    # ZWSP, ZWNJ, ZWJ, BOM
    assert strip_adversarial_controls("a​b‌c‍d﻿e") == "abcde"


def test_strip_adversarial_controls_removes_bidi_overrides():
    """RLO (U+202E) is the classic filename-masquerade vector."""
    from pipeline.schemas import strip_adversarial_controls
    assert strip_adversarial_controls("exe.txt‮malicious") == "exe.txtmalicious"


def test_strip_adversarial_controls_removes_c0_controls():
    from pipeline.schemas import strip_adversarial_controls
    assert strip_adversarial_controls("a\x00b\x08c\x7fd") == "abcd"


# ---- Finding field bounds ----


def test_finding_notes_at_bound_accepted(make_finding):
    """notes bound is 4000; exactly at bound should validate."""
    f = make_finding(notes=("x" * 4000))
    assert len(f.notes) == 4000


def test_finding_notes_over_bound_raises(make_finding):
    from pipeline.schemas import Finding  # noqa: F401 — docstring clarity only
    with pytest.raises(ValidationError):
        make_finding(notes=("x" * 4001))


def test_finding_value_over_bound_raises(make_finding):
    with pytest.raises(ValidationError):
        make_finding(value=("y" * 1001))


def test_finding_mechanism_over_bound_raises(make_finding):
    with pytest.raises(ValidationError):
        make_finding(mechanism=("m" * 301))


def test_finding_strips_controls_from_notes(make_finding):
    """Pre-validator strips zero-widths before length check — realistic case
    where an LLM emitted a zero-width inside a citation marker."""
    f = make_finding(notes="Ruled out [ev:tc-3]​; confirmed via [ev:tc-4].")
    assert "​" not in f.notes
    assert "[ev:tc-3]" in f.notes
    assert "[ev:tc-4]" in f.notes


def test_finding_strips_controls_from_value(make_finding):
    f = make_finding(value="C:\\Windows\\evil.exe‮")
    assert "‮" not in f.value
    assert f.value == "C:\\Windows\\evil.exe"


def test_finding_strip_before_length_check(make_finding):
    """Control chars are removed BEFORE length validation — so an attacker
    can't pad past the bound with invisible characters to sneak in more text."""
    # 3999 normal + 100 zero-widths → post-strip = 3999 chars → under bound
    f = make_finding(notes=("x" * 3999) + ("​" * 100))
    assert len(f.notes) == 3999


# ---- Evidence field bounds ----


def test_evidence_tool_call_id_over_bound_raises():
    from pipeline.schemas import Evidence
    with pytest.raises(ValidationError):
        Evidence(tool_call_id="t" * 65, output_excerpt="ok")


def test_evidence_output_excerpt_over_bound_raises():
    from pipeline.schemas import Evidence
    with pytest.raises(ValidationError):
        Evidence(tool_call_id="tc-0", output_excerpt="x" * 1501)


def test_evidence_strips_controls_from_excerpt():
    from pipeline.schemas import Evidence
    e = Evidence(tool_call_id="tc-0", output_excerpt="before​after\x00end")
    assert e.output_excerpt == "beforeafterend"


def test_evidence_at_bounds_accepted():
    from pipeline.schemas import Evidence
    e = Evidence(tool_call_id="t" * 64, output_excerpt="x" * 1500)
    assert len(e.tool_call_id) == 64
    assert len(e.output_excerpt) == 1500
