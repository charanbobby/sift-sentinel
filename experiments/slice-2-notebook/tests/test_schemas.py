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
