"""Capability-token issuer (orchestrator side) + verifier (MCP server side).

Tokens are HMAC-SHA256-signed scopes issued ONCE per approved plan. Every MCP
tool call carries one; verification rejects any call outside the scope declared
at issuance. The five checks in `verify_token`, in order:

  1. HMAC-SHA256 signature matches recomputed canonical serialization
  2. expires_at not elapsed
  3. case_id matches the call's case_id
  4. tool in token.allowed_tools
  5. path starts with at least one token.allowed_paths prefix (canonical form)
  6. plan_digest passed by the caller matches token.plan_digest

Deviation from the runbook's verify_token sketch (which listed five params,
not six): `case_id` is explicit. The runbook's T7 threat ("token replay on a
different case") mandates a case_id check; folding that into path_not_allowed
is fragile (a token scoped to /mnt/hackathon/ covers every case's evidence at
that prefix). Adding it as a first-class check costs one parameter.

What tokens DO NOT defend against: a hijacked agent process with direct
filesystem access in the same container. That's a system-level isolation
problem — the dual-channel handler (Slice 5 Step 5) keeps adversarial evidence
out of the LLM context in the first place; seccomp / eBPF / microVM isolation
is documented as a Slice-7+ extension point.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath

from pipeline.schemas import CapabilityToken, ToolPlan


# Shared HMAC key between issuer (orchestrator, in sift-sentinel) and verifier
# (MCP server, in sift-mcp). Pinned via docker/.env → both compose services.
_ENV_KEY = "CAPABILITY_TOKEN_KEY"


class CapabilityDenied(Exception):
    """Raised by `verify_token` on any scope violation. Carries `reason`
    (short structured string, e.g. "tool_not_allowed:icat_extract") and
    `token_id` (uuid4 from the rejected token) so the caller can log a
    structured audit entry without re-parsing the exception text.
    """

    def __init__(self, reason: str, *, token_id: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.token_id = token_id


def _require_key() -> bytes:
    """Read CAPABILITY_TOKEN_KEY at call time (not module import) so tests
    can monkey-patch it. Fails loud if unset.
    """
    val = os.environ.get(_ENV_KEY, "")
    if not val:
        raise RuntimeError(
            f"{_ENV_KEY} env var not set or empty. Pin it in docker/.env + "
            f"pass through to sift-sentinel (issuer) AND sift-mcp (verifier) "
            f"in docker-compose.yaml."
        )
    return val.encode("utf-8")


def _canonical_payload(
    *,
    token_id: str,
    case_id: str,
    allowed_tools: frozenset[str],
    allowed_paths: tuple[str, ...],
    plan_digest: str,
    expires_at: datetime,
) -> bytes:
    """Canonical JSON of the token's unsigned fields. `sort_keys=True` +
    tight separators + explicit ISO-format datetime + sorted tool set so two
    tokens with identical scopes serialize to identical bytes regardless of
    Python dict ordering or set iteration order.
    """
    payload = {
        "token_id": token_id,
        "case_id": case_id,
        "allowed_tools": sorted(allowed_tools),
        "allowed_paths": list(allowed_paths),
        "plan_digest": plan_digest,
        "expires_at": expires_at.astimezone(timezone.utc).isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_plan_digest(plan: ToolPlan) -> str:
    """sha256 hex of the plan's canonical JSON. Stable across Python runs;
    changes iff any field of any step changes. This is the binding between
    the token and the human-approved plan.
    """
    canonical = json.dumps(
        plan.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def issue_token(
    plan: ToolPlan,
    case_id: str,
    allowed_paths: tuple[str, ...],
    ttl_seconds: int = 1800,
) -> CapabilityToken:
    """Create a signed `CapabilityToken` for the approved plan.

    `allowed_tools` is derived from the distinct tools appearing in
    `plan.steps`; the orchestrator does not pick this manually. `allowed_paths`
    is orchestrator-supplied because the *human* approves "this plan may read
    from these prefixes." `expires_at` = now + ttl_seconds, UTC.
    """
    key = _require_key()
    allowed_tools = frozenset(step.tool for step in plan.steps)
    plan_digest = compute_plan_digest(plan)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    token_id = str(uuid.uuid4())

    payload = _canonical_payload(
        token_id=token_id,
        case_id=case_id,
        allowed_tools=allowed_tools,
        allowed_paths=allowed_paths,
        plan_digest=plan_digest,
        expires_at=expires_at,
    )
    signature = hmac.new(key, payload, hashlib.sha256).hexdigest()

    return CapabilityToken(
        token_id=token_id,
        case_id=case_id,
        allowed_tools=allowed_tools,
        allowed_paths=allowed_paths,
        plan_digest=plan_digest,
        expires_at=expires_at,
        signature=signature,
    )


def verify_token(
    token: CapabilityToken,
    *,
    tool: str,
    path: str,
    case_id: str,
    plan_digest: str,
) -> None:
    """Raise `CapabilityDenied` if the tool call is outside the token's scope.
    Returns None on success. Checks run in a fixed order; the first failure
    raises, so callers get one deterministic reason per denial.
    """
    key = _require_key()

    # 1. Signature check — first gate, rejects any field tampering.
    expected_payload = _canonical_payload(
        token_id=token.token_id,
        case_id=token.case_id,
        allowed_tools=token.allowed_tools,
        allowed_paths=token.allowed_paths,
        plan_digest=token.plan_digest,
        expires_at=token.expires_at,
    )
    expected_sig = hmac.new(key, expected_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, token.signature):
        raise CapabilityDenied("signature_mismatch", token_id=token.token_id)

    # 2. Expiry.
    if datetime.now(timezone.utc) > token.expires_at:
        raise CapabilityDenied("expired", token_id=token.token_id)

    # 3. Case scope — blocks cross-case replay (T7 threat).
    if case_id != token.case_id:
        raise CapabilityDenied(
            f"case_id_mismatch:token={token.case_id}:call={case_id}",
            token_id=token.token_id,
        )

    # 4. Tool scope.
    if tool not in token.allowed_tools:
        raise CapabilityDenied(f"tool_not_allowed:{tool}", token_id=token.token_id)

    # 5. Path scope — canonical POSIX form blocks `..` traversal.
    canonical_path = PurePosixPath(path)
    if ".." in canonical_path.parts:
        raise CapabilityDenied(f"path_not_allowed:traversal:{path}", token_id=token.token_id)
    canonical_str = str(canonical_path)
    if not any(canonical_str.startswith(prefix) for prefix in token.allowed_paths):
        raise CapabilityDenied(f"path_not_allowed:{canonical_str}", token_id=token.token_id)

    # 6. Plan-digest binding — rejects token reuse across re-plans.
    if plan_digest != token.plan_digest:
        raise CapabilityDenied("plan_digest_mismatch", token_id=token.token_id)


__all__ = [
    "CapabilityDenied",
    "compute_plan_digest",
    "issue_token",
    "verify_token",
]
