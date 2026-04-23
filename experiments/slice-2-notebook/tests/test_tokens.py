"""Test capability-token issuer + verifier.

Ports the 10 hostile cases (+ positive control) from d:/tmp/probe_step3_tokens.py
into parametrized pytest cases. CAPABILITY_TOKEN_KEY is pinned in conftest.py
so signatures are deterministic.

Runbook Step 3c:
  0. valid (positive control)
  1. tampered signature
  2. tool not in allowed_tools
  3. path outside allowed_paths
  4. expired token
  5. plan_digest mismatch (token for plan A, call claims plan B)
  6. case_id mismatch (cross-case replay)
  7. tool-order-independence (any allowed tool passes)
  8. token reused across plans (plan mutation)
  9. empty allowed_paths (every path fails)
 10. path-traversal via `..`
"""
from __future__ import annotations

import time

import pytest

from pipeline.mcp.tokens import (
    CapabilityDenied,
    compute_plan_digest,
    issue_token,
    verify_token,
)
from pipeline.schemas import PlannedStep, ToolPlan


CASE = "probe-case-001"
PATHS = (
    "/mnt/hackathon/",
    "/home/sansforensics/cases/probe-case-001/analysis/extracted/",
)


# ---- Issuance invariants ----------------------------------------------------


def test_issue_token_allowed_tools_matches_plan(make_token_plan):
    token = issue_token(make_token_plan, CASE, PATHS, ttl_seconds=60)
    assert token.allowed_tools == {"fsstat_e01", "fls_list", "icat_extract"}


def test_issue_token_plan_digest_matches_compute(make_token_plan):
    token = issue_token(make_token_plan, CASE, PATHS, ttl_seconds=60)
    assert token.plan_digest == compute_plan_digest(make_token_plan)


# ---- CASE 0 — positive control ---------------------------------------------


def test_verify_token_case0_valid_call_passes(make_token_plan):
    token = issue_token(make_token_plan, CASE, PATHS, ttl_seconds=60)
    verify_token(
        token, tool="fls_list",
        path="/mnt/hackathon/x.E01",
        case_id=CASE, plan_digest=compute_plan_digest(make_token_plan),
    )


# ---- CASE 1 — tampered signature -------------------------------------------


def test_verify_token_case1_tampered_signature_denied(make_token_plan):
    token = issue_token(make_token_plan, CASE, PATHS, ttl_seconds=60)
    tampered = token.model_copy(update={"signature": "0" * 64})
    with pytest.raises(CapabilityDenied) as exc:
        verify_token(
            tampered, tool="fls_list",
            path="/mnt/hackathon/x.E01",
            case_id=CASE, plan_digest=compute_plan_digest(make_token_plan),
        )
    assert exc.value.reason.startswith("signature_mismatch")


# ---- CASE 2 — tool not in allowed_tools ------------------------------------


def test_verify_token_case2_tool_not_in_allowed_tools_denied(make_token_plan):
    # Plan has fsstat/fls/icat — regripper_run was never planned, never allowed
    token = issue_token(make_token_plan, CASE, PATHS, ttl_seconds=60)
    with pytest.raises(CapabilityDenied) as exc:
        verify_token(
            token, tool="regripper_run",
            path="/mnt/hackathon/x.E01",
            case_id=CASE, plan_digest=compute_plan_digest(make_token_plan),
        )
    assert exc.value.reason.startswith("tool_not_allowed")


# ---- CASE 3 — path outside allowed_paths -----------------------------------


def test_verify_token_case3_path_outside_allowed_prefixes_denied(make_token_plan):
    token = issue_token(make_token_plan, CASE, PATHS, ttl_seconds=60)
    with pytest.raises(CapabilityDenied) as exc:
        verify_token(
            token, tool="fls_list",
            path="/etc/shadow",
            case_id=CASE, plan_digest=compute_plan_digest(make_token_plan),
        )
    assert exc.value.reason.startswith("path_not_allowed")


# ---- CASE 4 — expired token -------------------------------------------------


def test_verify_token_case4_expired_token_denied(make_token_plan):
    """1s TTL + sleep 2s → expired."""
    short = issue_token(make_token_plan, CASE, PATHS, ttl_seconds=1)
    time.sleep(1.5)
    with pytest.raises(CapabilityDenied) as exc:
        verify_token(
            short, tool="fls_list",
            path="/mnt/hackathon/x.E01",
            case_id=CASE, plan_digest=compute_plan_digest(make_token_plan),
        )
    assert exc.value.reason.startswith("expired")


# ---- CASE 5 — plan_digest mismatch -----------------------------------------


def test_verify_token_case5_plan_digest_mismatch_denied(make_token_plan):
    token = issue_token(make_token_plan, CASE, PATHS, ttl_seconds=60)
    with pytest.raises(CapabilityDenied) as exc:
        verify_token(
            token, tool="fls_list",
            path="/mnt/hackathon/x.E01",
            case_id=CASE, plan_digest="f" * 64,
        )
    assert exc.value.reason.startswith("plan_digest_mismatch")


# ---- CASE 6 — cross-case replay --------------------------------------------


def test_verify_token_case6_cross_case_replay_denied(make_token_plan):
    """T7 in the threat model — leaked token replayed on a different case."""
    token = issue_token(make_token_plan, CASE, PATHS, ttl_seconds=60)
    with pytest.raises(CapabilityDenied) as exc:
        verify_token(
            token, tool="fls_list",
            path="/mnt/hackathon/x.E01",
            case_id="probe-case-002",
            plan_digest=compute_plan_digest(make_token_plan),
        )
    assert exc.value.reason.startswith("case_id_mismatch")


# ---- CASE 7 — tool-order-independence --------------------------------------


def test_verify_token_case7_any_allowed_tool_passes_in_any_order(make_token_plan):
    """Token allows fsstat/fls/icat — the order they're invoked in is a plan
    concern, not a token concern."""
    token = issue_token(make_token_plan, CASE, PATHS, ttl_seconds=60)
    verify_token(
        token, tool="fsstat_e01",
        path="/mnt/hackathon/x.E01",
        case_id=CASE, plan_digest=compute_plan_digest(make_token_plan),
    )


# ---- CASE 8 — token reused across plans (plan mutation) ---------------------


def test_verify_token_case8_plan_mutation_invalidates_token(make_token_plan):
    """Plan B adds a new step → different plan_digest → original token rejected."""
    token = issue_token(make_token_plan, CASE, PATHS, ttl_seconds=60)
    plan_b = make_token_plan.model_copy(update={
        "steps": make_token_plan.steps + [PlannedStep(
            step_id=4, tool="fls_list",
            args={"e01_path": "/mnt/hackathon/x.E01",
                  "parent_inode": 100, "recurse": True},
            purpose="recurse", depends_on=[1], confidence="medium",
        )],
    })
    plan_b_digest = compute_plan_digest(plan_b)
    assert plan_b_digest != compute_plan_digest(make_token_plan)
    with pytest.raises(CapabilityDenied) as exc:
        verify_token(
            token, tool="fls_list",
            path="/mnt/hackathon/x.E01",
            case_id=CASE, plan_digest=plan_b_digest,
        )
    assert exc.value.reason.startswith("plan_digest_mismatch")


# ---- CASE 9 — empty allowed_paths -------------------------------------------


def test_verify_token_case9_empty_allowed_paths_denies_every_path(make_token_plan):
    token = issue_token(make_token_plan, CASE, allowed_paths=(), ttl_seconds=60)
    with pytest.raises(CapabilityDenied) as exc:
        verify_token(
            token, tool="fls_list",
            path="/mnt/hackathon/x.E01",
            case_id=CASE, plan_digest=compute_plan_digest(make_token_plan),
        )
    assert exc.value.reason.startswith("path_not_allowed")


# ---- CASE 10 — path-traversal via `..` --------------------------------------


def test_verify_token_case10_path_traversal_denied(make_token_plan):
    token = issue_token(make_token_plan, CASE, PATHS, ttl_seconds=60)
    with pytest.raises(CapabilityDenied) as exc:
        verify_token(
            token, tool="fls_list",
            path="/mnt/hackathon/../etc/shadow",
            case_id=CASE, plan_digest=compute_plan_digest(make_token_plan),
        )
    # Reason prefix pattern — probe uses "path_not_allowed:traversal" historically
    assert "traversal" in exc.value.reason or exc.value.reason.startswith("path_not_allowed")
