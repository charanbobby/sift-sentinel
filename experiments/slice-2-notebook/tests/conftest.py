"""Shared pytest fixtures for the Slice 5 test suite.

Synthetic builders for EvidenceRecord / Finding / ToolPlan / CapabilityToken.
Ported from the reference probes in `d:/tmp/probe_step*.py` that accreted
during Slice 5. Keep these pure-construction (no MCP, no LLM, no subprocess);
any test that needs I/O should build its own tmp fixture.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

import pytest

# Ensure /workspace is on sys.path so `from pipeline.*` works when pytest is
# invoked from anywhere. In sift-sentinel the cwd is /workspace; elsewhere,
# add the project root explicitly.
if "/workspace" not in sys.path:
    sys.path.insert(0, "/workspace")

# Pin an HMAC key for token tests. Tests pin this BEFORE importing the tokens
# module (which may read at module load), so fixtures that construct tokens get
# a deterministic signature.
os.environ.setdefault("CAPABILITY_TOKEN_KEY", "pytest-hmac-key-slice5-abc123")


# ---- Evidence ---------------------------------------------------------------


@pytest.fixture
def make_evidence():
    """Factory for EvidenceRecord. Defaults produce an 'ok'-status record with
    no injection flags; override any field via kwargs."""
    from pipeline.schemas import EvidenceRecord

    def _make(
        tool_call_id: str = "tc-0",
        structured_fields: dict | None = None,
        *,
        tool_execution_status: str = "ok",
        injection_flags=None,
        expected_paths_covered=None,
        token_id: str = "tok-test",
        raw_sha256: str | None = None,
    ) -> "EvidenceRecord":
        return EvidenceRecord(
            tool_call_id=tool_call_id,
            raw_sha256=(raw_sha256 or ("0" * 64)),
            raw_path=f"/tmp/{tool_call_id}.raw",
            structured_fields=structured_fields if structured_fields is not None
                              else {"entries": []},
            injection_flags=injection_flags or [],
            expected_paths_covered=expected_paths_covered or [],
            tool_execution_status=tool_execution_status,
            issued_at=datetime(2026, 4, 23, 12, 0, tzinfo=timezone.utc),
            token_id=token_id,
        )

    return _make


# ---- Plan -------------------------------------------------------------------


@pytest.fixture
def make_plan():
    """Factory for ToolPlan. Pass tool names in order; each becomes a step."""
    from pipeline.schemas import ToolPlan, PlannedStep

    def _make(*tools: str, question: str = "test question") -> "ToolPlan":
        steps = [
            PlannedStep(
                step_id=i + 1,
                tool=tool,
                args={},
                purpose=f"step-{i+1}",
                depends_on=[],
                confidence="high",
            )
            for i, tool in enumerate(tools)
        ]
        return ToolPlan(question=question, steps=steps,
                        expected_findings_range=(0, 5))

    return _make


# ---- Finding ----------------------------------------------------------------


@pytest.fixture
def make_finding():
    """Factory for Finding. Defaults produce a high-confidence attacker_persistence
    entry with rule-out notes; override via kwargs."""
    from pipeline.schemas import Finding, Evidence

    def _make(
        *,
        category: str = "registry_run_key",
        mechanism: str = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        value: str = "C:\\malware.exe",
        confidence: str = "high",
        classification: str = "attacker_persistence",
        notes: str = "Ruled out DFIR tools + vendor products + Windows defaults.",
        evidence_refs: list[tuple[str, str]] | None = None,
    ) -> "Finding":
        return Finding(
            category=category,
            mechanism=mechanism,
            value=value,
            confidence=confidence,
            classification=classification,
            notes=notes,
            evidence=[
                Evidence(tool_call_id=tcid, output_excerpt=excerpt)
                for tcid, excerpt in (evidence_refs or [])
            ],
        )

    return _make


# ---- Capability token (pre-signed, for token tests) -------------------------


@pytest.fixture
def make_token_plan():
    """Builds a realistic 3-step plan for token tests — fsstat + fls + icat.
    Matches the shape used in probe_step3_tokens.py so port is exact."""
    from pipeline.schemas import ToolPlan, PlannedStep

    return ToolPlan(
        question="probe",
        steps=[
            PlannedStep(step_id=1, tool="fsstat_e01",
                        args={"e01_path": "/mnt/hackathon/x.E01"},
                        purpose="get fs metadata", depends_on=[], confidence="high"),
            PlannedStep(step_id=2, tool="fls_list",
                        args={"e01_path": "/mnt/hackathon/x.E01",
                              "parent_inode": None, "recurse": False},
                        purpose="root listing", depends_on=[], confidence="high"),
            PlannedStep(step_id=3, tool="icat_extract",
                        args={"e01_path": "/mnt/hackathon/x.E01",
                              "inode": 12345, "dest_filename": "SOFTWARE"},
                        purpose="extract hive", depends_on=[2], confidence="high"),
        ],
        expected_findings_range=(1, 5),
    )
