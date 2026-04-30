"""
Find Evil — Slice 2 MCP Server (long-lived service on the `sift-mcp` container).

Transport: MCP streamable-HTTP over an internal Docker bridge network. Bound to
`0.0.0.0:8000/mcp` inside `sift-mcp`; unreachable from the host (the
`findevil-internal` Compose network is declared `internal: true`). The
`sift-sentinel` container connects with a bearer token in the `Authorization`
header; unauthorized connections are rejected at the Starlette middleware layer
before any MCP frame is processed.

Pre-Slice-5 Step 0.5, this server ran stdio over `docker exec` — the notebook
container had `/var/run/docker.sock` mounted (root-on-host equivalent), which
let a hijacked agent bypass every per-call check. Slice 5 Step 0.5 removed that
socket and made the MCP server the agent's only capability.

Case scoping:
    `case_id` is passed on every tool call. The server is not pinned to a
    single case at startup — it serves many. Slice 5 Step 4 wired in capability
    tokens: every call also carries `capability_token` (JSON-serialized
    `CapabilityToken`) + `plan_digest` (sha256 of the approved ToolPlan). The
    server parses the token, calls `verify_token()`, and on any denial returns
    a `ToolResult` with `exit_code=-1` and `stdout_excerpt="capability_denied:
    <reason>"` instead of raising — the agent is expected to learn and re-plan.

Seven disciplines enforced (see slice-2-runbook.md Step 3):

    1. argv arrays only — never shell=True or string interpolation
    2. Typed tool inputs via Pydantic → MCP JSON Schema
    3. Path allowlist: reads from /mnt/hackathon/** and /mnt/derived/**;
       writes under <case>/analysis/**
    4. Plugin allowlist for regripper
    5. stdout truncation: 64 KB cap returned to client; full output persisted
    6. Every call appended to <case>/analysis/tool_calls.jsonl (audit trail)
    7. All diagnostics go to stderr — stdout is reserved for protocol framing
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple, Optional

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, Field, ValidationError
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import uvicorn

# `/opt/pipeline` is a read-only bind-mount of experiments/slice-2-notebook/pipeline
# (see docker-compose.yaml). Adding `/opt` to sys.path lets this server import the
# same schema + token logic the orchestrator (sift-sentinel) uses — one definition
# of the wire contract, no duplication.
sys.path.insert(0, "/opt")

from pipeline.schemas import CapabilityToken, EvidenceRecord  # noqa: E402
from pipeline.mcp.tokens import CapabilityDenied, verify_token  # noqa: E402
from pipeline.mcp.injection_scanner import scan_evidence  # noqa: E402
from pipeline.mcp import parsers as P  # noqa: E402


# Read-path allowlist. `/mnt/hackathon` is :ro raw evidence (E01s, memory dumps).
# `/mnt/derived` is :rw preprocessed artifacts (raw .dd partitions extracted from
# multi-segment E01s via ewfmount+dd). `/mnt/working` is :ro synthetic-workstation
# daily-loop images written by build.py (added 2026-04-29 so Phase E's run_case.py
# call against /mnt/working/<synthetic>.raw clears the read-path gate). All three
# are legitimate read sources for fsstat/fls/icat; only /mnt/hackathon is
# forensic-integrity-protected at the mount layer.
EVIDENCE_ROOTS = tuple(p.resolve() for p in (Path("/mnt/hackathon"), Path("/mnt/derived"), Path("/mnt/working")))
EVIDENCE_ROOT = EVIDENCE_ROOTS[0]  # retained for backwards-compat where code/errors name the primary root
# Memory-image read-path allowlist (Slice 6 Step 3b.6). Production target is the
# named Docker volume `/var/lib/find-evil/memory`; `/tmp` is the dev path during
# initial Vol2 probing while the volume is being provisioned. Vol2 needs fast
# container-local reads; bind-mounted memory dumps from `/mnt/hackathon` were
# measured at ~1.5 MB/s on Windows Docker Desktop, making per-plugin runs unusably
# slow. Each dump is staged once into MEMORY_EVIDENCE_ROOTS before the pipeline runs.
MEMORY_EVIDENCE_ROOTS = tuple(
    p.resolve() for p in (
        Path("/var/lib/find-evil/memory"),
        Path("/home/sansforensics"),
        Path("/tmp"),
    )
    if p.exists()
)
CASES_ROOT = Path("/home/sansforensics/cases")
STDOUT_CAP_BYTES = 64 * 1024

# Case-id format: letters, digits, dash, underscore, dot; 1..64 chars.
# Blocks path-traversal (`..`, `/`) and shell-special characters.
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# Transport-layer bearer token. Shared secret between sift-mcp and sift-sentinel,
# pinned in `.env` and passed in via docker-compose. Distinct from Slice-5
# capability tokens — this is the WiFi-password layer; capability tokens are
# per-call scope. Empty / unset here is fatal at server start.
MCP_TRANSPORT_TOKEN = os.environ.get("MCP_TRANSPORT_TOKEN", "")

# Regripper plugin allowlist — verified against /usr/share/regripper/plugins on
# digitalsleuth/sift-docker:jammy 2026-04-19. Only persistence-relevant plugins.
# Each entry maps plugin name → hive it expects (for PLAN-time validation).
REGRIPPER_PLUGIN_ALLOWLIST: dict[str, str] = {
    "run":           "Software or NTUSER.DAT",  # Run / RunOnce keys
    "runonceex":     "Software",                # RunOnceEx
    "services":      "System",                  # Services \ CurrentControlSet
    "schedagent":    "Software",                # Scheduled Tasks registry tracking
    "appinitdlls":   "Software",                # AppInit_DLLs
    "imagefile":     "Software",                # Image File Execution Options (IFEO debuggers)
    "winlogon_tln":  "Software",                # Winlogon Userinit / Shell / Notify
    "securityproviders": "System",              # SecurityProviders (WDigest UseLogonCredential = Mimikatz prep)
}


class CasePaths(NamedTuple):
    case_root: Path
    analysis: Path
    raw_out: Path
    extracted: Path
    tool_calls_log: Path
    integrity_stub: Path  # Slice 5 Step 6b — stub for Slice 6 hash-chain ledger


def _log(msg: str) -> None:
    print(f"[mcp-server] {msg}", file=sys.stderr, flush=True)


def _validate_case_id(case_id: str) -> str:
    """Reject any case_id that could escape the case directory or smuggle shell metachars."""
    if not isinstance(case_id, str) or not _CASE_ID_RE.match(case_id):
        raise ValueError(
            f"case_id {case_id!r} invalid; must match {_CASE_ID_RE.pattern}"
        )
    return case_id


def _case_paths(case_id: str) -> CasePaths:
    """Compute + create the per-case directory layout on demand.

    Replaces Slice-2's module-scope constants that required a single
    FIND_EVIL_CASE_ID env var pinning the process to one case. Long-lived
    server must serve many cases, so paths are computed per call.
    """
    _validate_case_id(case_id)
    case_root = CASES_ROOT / case_id
    analysis = (case_root / "analysis").resolve()
    paths = CasePaths(
        case_root=case_root,
        analysis=analysis,
        raw_out=analysis / "raw",
        extracted=analysis / "extracted",
        tool_calls_log=analysis / "tool_calls.jsonl",
        integrity_stub=analysis / "integrity_stub.jsonl",
    )
    paths.analysis.mkdir(parents=True, exist_ok=True)
    paths.raw_out.mkdir(parents=True, exist_ok=True)
    paths.extracted.mkdir(parents=True, exist_ok=True)
    return paths


def _check_read_path(path_str: str) -> Path:
    p = Path(path_str).resolve()
    if not any(p == root or str(p).startswith(str(root) + os.sep) for root in EVIDENCE_ROOTS):
        allowed = ", ".join(str(r) for r in EVIDENCE_ROOTS)
        raise ValueError(f"read path {p} outside allowlist ({allowed})")
    if not p.exists():
        raise ValueError(f"read path {p} does not exist")
    return p


def _check_memory_image_path(path_str: str) -> Path:
    """Volatility 2 memory-dump path validator (Slice 6 Step 3b.6). Distinct
    from `_check_read_path` because memory dumps live in container-fast staging
    storage, not bind-mounted evidence roots."""
    p = Path(path_str).resolve()
    if not MEMORY_EVIDENCE_ROOTS:
        raise ValueError(
            "no memory-evidence root mounted; create /var/lib/find-evil/memory "
            "named volume or stage to /tmp"
        )
    if not any(
        p == root or str(p).startswith(str(root) + os.sep)
        for root in MEMORY_EVIDENCE_ROOTS
    ):
        allowed = ", ".join(str(r) for r in MEMORY_EVIDENCE_ROOTS)
        raise ValueError(f"memory-image path {p} outside allowlist ({allowed})")
    if not p.exists():
        raise ValueError(f"memory-image path {p} does not exist")
    return p


# Volatility 2 profile name validator. Profile flows directly into vol.py argv as
# `--profile=<X>`; a permissive value would let an attacker-controlled plan smuggle
# extra flags. Letters / digits / underscore only, length-bounded.
_VOLATILITY_PROFILE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,63}$")


def _check_volatility_profile(profile: str) -> str:
    if not isinstance(profile, str) or not _VOLATILITY_PROFILE_RE.match(profile):
        raise ValueError(
            f"profile {profile!r} invalid; must match {_VOLATILITY_PROFILE_RE.pattern}"
        )
    return profile


def _check_extracted_path(case_id: str, path_str: str) -> Path:
    """Hives passed to regripper MUST live under <case>/analysis/extracted/ — that
    directory is only ever written by icat_extract, so this check is what forces the
    icat-before-regripper dependency at the MCP layer (belt to the PLAN prompt's braces).
    """
    extracted_dir = _case_paths(case_id).extracted
    p = Path(path_str).resolve()
    if not str(p).startswith(str(extracted_dir) + os.sep):
        raise ValueError(f"hive path {p} must be under {extracted_dir}")
    if not p.exists():
        raise ValueError(f"hive path {p} does not exist (run icat_extract first)")
    return p


def _check_dest_filename(case_id: str, name: str) -> Path:
    """icat_extract takes a FILENAME (not a path) — prevents traversal via '..' or '/'."""
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        raise ValueError(f"dest_filename must be a plain filename, got {name!r}")
    return (_case_paths(case_id).extracted / name).resolve()


class _SubprocessOutput(NamedTuple):
    tool_call_id: str
    returncode: int
    raw_bytes: bytes                 # always populated — for binary tools we read back from disk
    raw_path: Path
    duration_ms: int
    raw_stderr: bytes


def _run_subprocess(
    case_id: str,
    tool: str,
    argv: list[str],
    call_args: dict,
    *,
    stdout_target: Optional[Path] = None,
) -> _SubprocessOutput:
    """Execute `argv`, persist raw stdout to disk, append a tool_calls.jsonl
    audit entry, return the bytes + subprocess metadata. No parsing, no scanning,
    no EvidenceRecord construction — those live in `_emit_evidence` so this is
    the single subprocess-boundary we can reason about.

    stdout_target=None (default): capture stdout in memory, persist to
        <raw>/<tool_call_id>.raw, return the bytes.
    stdout_target=<Path>: stream straight to that file (icat_extract binary path).
        We then read the bytes back from disk so the channel-A hash computation
        and injection-scan have the same input either way.
    """
    paths = _case_paths(case_id)
    tool_call_id = str(uuid.uuid4())
    t0 = time.monotonic()

    if stdout_target is not None:
        stdout_target.parent.mkdir(parents=True, exist_ok=True)
        with stdout_target.open("wb") as sink:
            completed = subprocess.run(argv, stdout=sink, stderr=subprocess.PIPE, check=False)
        raw_path = stdout_target
        raw_bytes = stdout_target.read_bytes()
    else:
        completed = subprocess.run(argv, capture_output=True, check=False)
        raw_bytes = completed.stdout or b""
        raw_path = paths.raw_out / f"{tool_call_id}.raw"
        raw_path.write_bytes(raw_bytes)

    duration_ms = int((time.monotonic() - t0) * 1000)
    raw_stderr = completed.stderr or b""

    if raw_stderr:
        (paths.raw_out / f"{tool_call_id}.stderr").write_bytes(raw_stderr)

    entry = {
        "tool_call_id": tool_call_id,
        "case_id": case_id,
        "tool": tool,
        "args": call_args,
        "argv": argv,
        "exit_code": completed.returncode,
        "duration_ms": duration_ms,
        "raw_path": str(raw_path),
        "raw_bytes_len": len(raw_bytes),
        "stderr_bytes": len(raw_stderr),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    with paths.tool_calls_log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    _log(
        f"{tool} case={case_id} exit={completed.returncode} dur={duration_ms}ms "
        f"out={len(raw_bytes)}B id={tool_call_id}"
    )
    return _SubprocessOutput(
        tool_call_id=tool_call_id,
        returncode=completed.returncode,
        raw_bytes=raw_bytes,
        raw_path=raw_path,
        duration_ms=duration_ms,
        raw_stderr=raw_stderr,
    )


def _derive_status(returncode: int, raw_stderr: bytes, parser_status: str) -> str:
    """Map subprocess exit + parser status to a single ToolExecutionStatus.
    Parser's status wins on 0-exit; non-zero exit maps to timeout/
    permission_denied/parse_error based on the signal or stderr shape.
    """
    if returncode < 0:
        # Killed by signal (SIGKILL / SIGTERM etc.) — most common cause in our
        # docker setup is an OOM kill or a subprocess-timeout sentinel we don't
        # currently implement. Treat as timeout until we have a real timer.
        return "timeout"
    if returncode != 0:
        low = raw_stderr.lower()
        if b"permission denied" in low or b"eacces" in low:
            return "permission_denied"
        # Non-zero exit with non-permission stderr: let the parser's view win
        # when it has one, else fall back to parse_error.
        return parser_status if parser_status in {"ok", "empty"} else "parse_error"
    return parser_status


def _append_integrity_entry(
    case_id: str,
    tool_call_id: str,
    raw_sha256: str,
    token_id: str,
    plan_digest: str,
) -> str:
    """Slice 5 Step 6b — stub-writer for the Slice 6 hash-chain integrity
    ledger. Shape is final; the writer gets replaced in Slice 6 with the
    tamper-evident implementation. `critic_decision` is `"pending"` at
    write time and gets backfilled at finding-commit time.

    Entry hash: sha256(plan_digest || raw_sha256 || critic_decision || prev_entry_hash).
    prev_entry_hash is read from the last line of the case's integrity_stub.jsonl,
    or "" on first entry.

    Returns the newly-computed entry_hash so callers can put it on the
    EvidenceRecord for end-to-end tracing if they want.
    """
    paths = _case_paths(case_id)
    prev_entry_hash = ""
    if paths.integrity_stub.exists():
        try:
            with paths.integrity_stub.open("rb") as f:
                # Cheap tail-read: for Slice 5 the file is small enough that
                # reading the whole thing is fine; Slice 6's real implementation
                # will maintain an in-memory cursor.
                lines = f.read().decode("utf-8", errors="replace").splitlines()
                if lines:
                    prev_entry_hash = json.loads(lines[-1]).get("entry_hash", "")
        except Exception as e:  # noqa: BLE001 — never fail the tool call on ledger error
            _log(f"integrity-stub-read-error case={case_id}: {e}")

    critic_decision = "pending"
    hash_input = f"{plan_digest}|{raw_sha256}|{critic_decision}|{prev_entry_hash}".encode("utf-8")
    entry_hash = hashlib.sha256(hash_input).hexdigest()

    entry = {
        "tool_call_id": tool_call_id,
        "raw_sha256": raw_sha256,
        "token_id": token_id,
        "plan_digest": plan_digest,
        "critic_decision": critic_decision,
        "prev_entry_hash": prev_entry_hash,
        "entry_hash": entry_hash,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with paths.integrity_stub.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:  # noqa: BLE001
        _log(f"integrity-stub-write-error case={case_id}: {e}")
    return entry_hash


def _emit_evidence(
    *,
    tool: str,
    sub: _SubprocessOutput,
    structured_model: BaseModel,
    parser_status: str,
    free_text_fields: list[tuple[str, str]],
    expected_paths: list[str],
    token_id: str,
    plan_digest: str,
    case_id: str,
) -> EvidenceRecord:
    """Turn a parsed subprocess result into an EvidenceRecord — runs the
    injection scanner on raw+channel-B, derives the final status, writes the
    integrity-stub entry, and returns the record. Called by every tool function."""
    raw_sha256 = hashlib.sha256(sub.raw_bytes).hexdigest()
    status = _derive_status(sub.returncode, sub.raw_stderr, parser_status)
    flags = scan_evidence(raw_bytes=sub.raw_bytes, text_fields=free_text_fields)
    _append_integrity_entry(case_id, sub.tool_call_id, raw_sha256, token_id, plan_digest)
    return EvidenceRecord(
        tool_call_id=sub.tool_call_id,
        raw_sha256=raw_sha256,
        raw_path=str(sub.raw_path),
        structured_fields=structured_model.model_dump(mode="json"),
        injection_flags=flags,
        expected_paths_covered=expected_paths,
        tool_execution_status=status,
        issued_at=datetime.now(timezone.utc),
        token_id=token_id,
    )


# --- Slice 5 Step 4: capability-token enforcement ----------------------------
# Every tool call carries a JSON-serialized `CapabilityToken` plus a `plan_digest`.
# `_enforce_capability` parses + verifies the token and returns None when the
# call is in-scope, or a synthetic denial `ToolResult` (exit_code=-1, reason in
# `stdout_excerpt`) when it isn't. Tool functions call it first thing and early-
# return the denial — no subprocess runs, no audit entry logs the tool as having
# executed. Denials go to stderr AND to the case audit log when the case_id is
# valid (malformed case_id → stderr-only; nowhere safe to write).


def _record_denial(
    tool: str, case_id: str, reason: str, path: str, token_id: str | None,
) -> None:
    _log(f"DENIED {tool} case={case_id} reason={reason} path={path} token_id={token_id}")
    try:
        _validate_case_id(case_id)
    except ValueError:
        return
    try:
        paths = _case_paths(case_id)
        entry = {
            "denial": True,
            "tool": tool,
            "case_id": case_id,
            "reason": reason,
            "path": path,
            "token_id": token_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        with paths.tool_calls_log.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:  # noqa: BLE001 — audit-log write failure must not mask the denial
        _log(f"denial-log-error tool={tool} case={case_id}: {e}")


_EMPTY_BYTES_SHA256 = hashlib.sha256(b"").hexdigest()


def _denial_record(
    tool: str, reason: str, case_id: str, path: str, token_id: str | None = None,
) -> EvidenceRecord:
    """EvidenceRecord sentinel for a denied call. No subprocess ran, so
    raw_sha256 is sha256(b"") and raw_path is empty. tool_execution_status =
    'capability_denied'; structured_fields carries the structured reason so
    Critic can distinguish denial types without parsing free text."""
    return EvidenceRecord(
        tool_call_id=str(uuid.uuid4()),
        raw_sha256=_EMPTY_BYTES_SHA256,
        raw_path="",
        structured_fields={
            "denial": True,
            "tool": tool,
            "reason": reason,
            "case_id": case_id,
            "path": path,
            "token_id": token_id,
        },
        injection_flags=[],
        expected_paths_covered=[],
        tool_execution_status="capability_denied",
        issued_at=datetime.now(timezone.utc),
        token_id=token_id or "",
    )


def _enforce_capability(
    capability_token: str,
    plan_digest: str,
    tool: str,
    *,
    case_id: str,
    path: str,
) -> tuple[CapabilityToken | None, EvidenceRecord | None]:
    """Return (token, None) on success, (None, denial_record) on any denial.
    Tool functions use the parsed token for token_id / downstream bookkeeping
    so we don't re-parse.

    Order of checks — each short-circuits so callers get one deterministic reason:
      1. case_id validation (stops malformed case_ids reaching _case_paths)
      2. token JSON parse
      3. verify_token (signature, expiry, case match, tool match, path match, plan_digest match)
    """
    try:
        _validate_case_id(case_id)
    except ValueError as e:
        _record_denial(tool, case_id, f"case_id_invalid:{e}", path, None)
        return None, _denial_record(tool, "case_id_invalid", case_id, path)

    try:
        token = CapabilityToken.model_validate_json(capability_token)
    except ValidationError as e:
        etype = e.errors()[0]["type"] if e.errors() else "unknown"
        _record_denial(tool, case_id, f"token_parse_error:{etype}", path, None)
        return None, _denial_record(tool, f"token_parse_error:{etype}", case_id, path)
    except Exception as e:  # noqa: BLE001 — JSON decode / unexpected pre-validation failure
        _record_denial(tool, case_id, f"token_parse_error:{type(e).__name__}", path, None)
        return None, _denial_record(tool, f"token_parse_error:{type(e).__name__}", case_id, path)

    try:
        verify_token(token, tool=tool, path=path, case_id=case_id, plan_digest=plan_digest)
    except CapabilityDenied as e:
        _record_denial(tool, case_id, e.reason, path, token.token_id)
        return None, _denial_record(tool, e.reason, case_id, path, token_id=token.token_id)

    return token, None


mcp = FastMCP(
    "find-evil-slice2",
    host="0.0.0.0",
    port=8000,
    streamable_http_path="/mcp",
    # DNS-rebinding protection off: we're on an internal-only Compose bridge,
    # bearer auth gates connection, and the default allowlist ([127.0.0.1:*,
    # localhost:*, [::1]:*]) would reject `Host: sift-mcp:8000` from sift-sentinel.
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)


@mcp.tool()
def fsstat_e01(
    capability_token: str,
    plan_digest: str,
    case_id: str,
    e01_path: str,
) -> EvidenceRecord:
    """Run `fsstat` on an E01 image. Returns filesystem metadata (type, block size, MFT offset for NTFS).

    Args:
        capability_token: JSON-serialized CapabilityToken issued by the orchestrator after human plan approval; scopes this call to (tool, path-prefix, plan).
        plan_digest: sha256 of the approved ToolPlan; must equal token.plan_digest or the call is denied.
        case_id: the case this call belongs to; audit trail + extracted hives scope to <case>/analysis/
        e01_path: absolute path to the E01 under /mnt/hackathon/
    """
    token, denial = _enforce_capability(
        capability_token, plan_digest, "fsstat_e01",
        case_id=case_id, path=e01_path,
    )
    if denial is not None:
        return denial
    evidence = _check_read_path(e01_path)
    sub = _run_subprocess(
        case_id=case_id, tool="fsstat_e01",
        argv=["fsstat", str(evidence)],
        call_args={"e01_path": str(evidence)},
    )
    result, parser_status = P.parse_fsstat(sub.raw_bytes)
    return _emit_evidence(
        tool="fsstat_e01", sub=sub,
        structured_model=result, parser_status=parser_status,
        free_text_fields=P.fsstat_free_text_fields(result),
        expected_paths=[str(evidence)],
        token_id=token.token_id, plan_digest=plan_digest, case_id=case_id,
    )


@mcp.tool()
def fls_list(
    capability_token: str,
    plan_digest: str,
    case_id: str,
    e01_path: str,
    parent_inode: Optional[int] = None,
    recurse: bool = False,
) -> EvidenceRecord:
    """Run `fls` on an E01 image — list directory entries including deleted ones.

    Args:
        capability_token: JSON-serialized CapabilityToken; scopes this call.
        plan_digest: sha256 of the approved ToolPlan; must equal token.plan_digest.
        case_id: the case this call belongs to
        e01_path: absolute path to the E01 under /mnt/hackathon/
        parent_inode: list children of this inode; None lists the root
        recurse: if True, recurse into subdirectories
    """
    token, denial = _enforce_capability(
        capability_token, plan_digest, "fls_list",
        case_id=case_id, path=e01_path,
    )
    if denial is not None:
        return denial
    evidence = _check_read_path(e01_path)
    argv = ["fls", "-m", "/"]
    if recurse:
        argv.append("-r")
    argv.append(str(evidence))
    if parent_inode is not None:
        argv.append(str(parent_inode))
    sub = _run_subprocess(
        case_id=case_id, tool="fls_list", argv=argv,
        call_args={
            "e01_path": str(evidence),
            "parent_inode": parent_inode,
            "recurse": recurse,
        },
    )
    result, parser_status = P.parse_fls(sub.raw_bytes)
    # expected_paths_covered records the directory enumeration surface: the
    # E01 root if parent_inode is None, else the specific inode. R_06 reads
    # this to verify a "nothing here" finding actually looked somewhere.
    covered = [str(evidence)]
    if parent_inode is not None:
        covered.append(f"inode_{parent_inode}")
    return _emit_evidence(
        tool="fls_list", sub=sub,
        structured_model=result, parser_status=parser_status,
        free_text_fields=P.fls_free_text_fields(result),
        expected_paths=covered,
        token_id=token.token_id, plan_digest=plan_digest, case_id=case_id,
    )


@mcp.tool()
def icat_extract(
    capability_token: str,
    plan_digest: str,
    case_id: str,
    e01_path: str,
    inode: int,
    dest_filename: str,
) -> EvidenceRecord:
    """Run `icat` to extract a file's bytes by inode out of an E01 image into
    the case's extracted/ directory. Use this to pull registry hive files
    (SOFTWARE, SYSTEM, NTUSER.DAT) off the disk before calling `regripper_run`.

    Args:
        capability_token: JSON-serialized CapabilityToken; scopes this call.
        plan_digest: sha256 of the approved ToolPlan; must equal token.plan_digest.
        case_id: the case this call belongs to
        e01_path: absolute path to the E01 under /mnt/hackathon/
        inode: inode number from a prior `fls_list` call
        dest_filename: a plain filename (no path separators), e.g. "SOFTWARE".
            The file lands at <case>/analysis/extracted/<dest_filename>, which
            is the only location `regripper_run` will accept as a hive path.
    """
    token, denial = _enforce_capability(
        capability_token, plan_digest, "icat_extract",
        case_id=case_id, path=e01_path,
    )
    if denial is not None:
        return denial
    evidence = _check_read_path(e01_path)
    dest_path = _check_dest_filename(case_id, dest_filename)
    sub = _run_subprocess(
        case_id=case_id, tool="icat_extract",
        argv=["icat", str(evidence), str(inode)],
        call_args={
            "e01_path": str(evidence),
            "inode": inode,
            "dest_filename": dest_filename,
            "dest_path": str(dest_path),
        },
        stdout_target=dest_path,
    )
    # icat's parser takes metadata, not stdout bytes — extracted file lives
    # at dest_path, bytes are also in sub.raw_bytes for hash + scan.
    extracted_sha256 = hashlib.sha256(sub.raw_bytes).hexdigest()
    result, parser_status = P.parse_icat(
        bytes_written=len(sub.raw_bytes),
        sha256=extracted_sha256,
        dest_path=str(dest_path),
        magic_peek=sub.raw_bytes[:16],
    )
    return _emit_evidence(
        tool="icat_extract", sub=sub,
        structured_model=result, parser_status=parser_status,
        free_text_fields=P.icat_free_text_fields(result),
        expected_paths=[str(dest_path)],
        token_id=token.token_id, plan_digest=plan_digest, case_id=case_id,
    )


@mcp.tool()
def regripper_run(
    capability_token: str,
    plan_digest: str,
    case_id: str,
    hive_path: str,
    plugin: str,
) -> EvidenceRecord:
    """Run a named RegRipper plugin against a Windows Registry hive to extract
    persistence-relevant keys (Run, Services, IFEO, etc.). The hive MUST have
    been produced by a prior `icat_extract` call — only files under the case's
    extracted/ directory are accepted.

    Args:
        capability_token: JSON-serialized CapabilityToken; scopes this call.
        plan_digest: sha256 of the approved ToolPlan; must equal token.plan_digest.
        case_id: the case this call belongs to
        hive_path: absolute path to a hive already under <case>/analysis/extracted/
        plugin: plugin name (without .pl suffix); must be in the allowlist.
            Allowed plugins and their expected hives:
              - run           (Software or NTUSER.DAT) Run / RunOnce keys
              - runonceex     (Software) RunOnceEx
              - services      (System) CurrentControlSet\\Services
              - schedagent    (Software) scheduled task tracking
              - appinitdlls   (Software) AppInit_DLLs injection
              - imagefile     (Software) Image File Execution Options / debuggers
              - winlogon_tln  (Software) Winlogon Userinit / Shell / Notify
    """
    token, denial = _enforce_capability(
        capability_token, plan_digest, "regripper_run",
        case_id=case_id, path=hive_path,
    )
    if denial is not None:
        return denial
    hive = _check_extracted_path(case_id, hive_path)
    if plugin not in REGRIPPER_PLUGIN_ALLOWLIST:
        raise ValueError(
            f"plugin {plugin!r} not in allowlist; "
            f"allowed: {sorted(REGRIPPER_PLUGIN_ALLOWLIST)}"
        )
    sub = _run_subprocess(
        case_id=case_id, tool="regripper_run",
        argv=["rip.pl", "-r", str(hive), "-p", plugin],
        call_args={"hive_path": str(hive), "plugin": plugin},
    )
    result, parser_status = P.parse_regripper(sub.raw_bytes, plugin=plugin)
    return _emit_evidence(
        tool="regripper_run", sub=sub,
        structured_model=result, parser_status=parser_status,
        free_text_fields=P.regripper_free_text_fields(result),
        expected_paths=P.regripper_expected_paths(plugin),
        token_id=token.token_id, plan_digest=plan_digest, case_id=case_id,
    )


@mcp.tool()
def scheduled_tasks_parse(
    capability_token: str,
    plan_digest: str,
    case_id: str,
    e01_path: str,
    task_xml_inode: int,
    dest_filename: str,
) -> EvidenceRecord:
    """Extract a Windows Task XML file by inode and parse it server-side.

    Chains `icat` (extract XML bytes) + `xml.etree.ElementTree` (parse) in one
    MCP call so the PLAN prompt can advertise T1053.005 (Scheduled Task)
    coverage without the orchestrator having to chain two calls. The extracted
    file lands at <case>/analysis/extracted/<dest_filename> and is available
    for later re-inspection; the structured result carries one
    ScheduledTaskEntry per <Task> element found.

    Args:
        capability_token: JSON-serialized CapabilityToken; scopes this call.
        plan_digest: sha256 of the approved ToolPlan.
        case_id: the case this call belongs to
        e01_path: absolute path to the E01 under /mnt/hackathon/
        task_xml_inode: inode number from a prior `fls_list` call that
            enumerated C:\\Windows\\System32\\Tasks\\
        dest_filename: a plain filename (no path separators); the extracted
            XML lands at <case>/analysis/extracted/<dest_filename>
    """
    token, denial = _enforce_capability(
        capability_token, plan_digest, "scheduled_tasks_parse",
        case_id=case_id, path=e01_path,
    )
    if denial is not None:
        return denial
    evidence = _check_read_path(e01_path)
    dest_path = _check_dest_filename(case_id, dest_filename)
    sub = _run_subprocess(
        case_id=case_id, tool="scheduled_tasks_parse",
        argv=["icat", str(evidence), str(task_xml_inode)],
        call_args={
            "e01_path": str(evidence),
            "task_xml_inode": task_xml_inode,
            "dest_filename": dest_filename,
            "dest_path": str(dest_path),
        },
        stdout_target=dest_path,
    )
    result, parser_status = P.parse_scheduled_tasks(sub.raw_bytes)
    return _emit_evidence(
        tool="scheduled_tasks_parse", sub=sub,
        structured_model=result, parser_status=parser_status,
        free_text_fields=P.scheduled_tasks_free_text_fields(result),
        expected_paths=[str(dest_path), f"inode_{task_xml_inode}"],
        token_id=token.token_id, plan_digest=plan_digest, case_id=case_id,
    )


@mcp.tool()
def volatility_run(
    capability_token: str,
    plan_digest: str,
    case_id: str,
    image_path: str,
    profile: str,
    plugin: str,
) -> EvidenceRecord:
    """Run a Volatility 2 plugin against a staged memory dump.

    Slice 6 Step 3b.6 — memory-evidence triage tool. Wraps `vol.py -f <image>
    --profile=<profile> <plugin>` for a 5-plugin allowlist. Image MUST be staged
    under /var/lib/find-evil/memory or /tmp (container-fast storage); bind-mounted
    dumps from /mnt/hackathon are too slow on Windows Docker Desktop and are
    rejected by the path validator.

    Args:
        capability_token: JSON-serialized CapabilityToken; scopes this call.
        plan_digest: sha256 of the approved ToolPlan; must equal token.plan_digest.
        case_id: the case this call belongs to.
        image_path: absolute path to a staged memory dump (.img / .raw).
        profile: Volatility 2 profile (e.g. Win7SP1x64, Win10x64_17134,
            Win2008R2SP1x64). Profile is per-host; the case manifest pins it.
        plugin: one of {pslist, cmdline, netscan, dlllist, malfind}.
            - pslist:  process tree (PID, PPID, threads, start time)
            - cmdline: full command-line per process
            - netscan: TCP/UDP connections (proto, local, foreign, state, owner)
            - dlllist: loaded modules per process (high volume; trim before LLM)
            - malfind: memory regions with anomalous protection (PAGE_EXECUTE_
              READWRITE etc.) — process-injection / unpacker signature
    """
    token, denial = _enforce_capability(
        capability_token, plan_digest, "volatility_run",
        case_id=case_id, path=image_path,
    )
    if denial is not None:
        return denial
    image = _check_memory_image_path(image_path)
    profile_safe = _check_volatility_profile(profile)
    if plugin not in P.VOLATILITY_PLUGIN_ALLOWLIST:
        raise ValueError(
            f"plugin {plugin!r} not in allowlist; "
            f"allowed: {sorted(P.VOLATILITY_PLUGIN_ALLOWLIST)}"
        )
    sub = _run_subprocess(
        case_id=case_id, tool="volatility_run",
        argv=["vol.py", "-f", str(image), f"--profile={profile_safe}", plugin],
        call_args={
            "image_path": str(image),
            "profile": profile_safe,
            "plugin": plugin,
        },
    )
    result, parser_status = P.parse_volatility(sub.raw_bytes, plugin, profile_safe)
    return _emit_evidence(
        tool="volatility_run", sub=sub,
        structured_model=result, parser_status=parser_status,
        free_text_fields=P.volatility_free_text_fields(result),
        expected_paths=[str(image), f"profile:{profile_safe}", f"plugin:{plugin}"],
        token_id=token.token_id, plan_digest=plan_digest, case_id=case_id,
    )


class BearerAuth(BaseHTTPMiddleware):
    """Transport-layer auth: every SSE handshake must carry
    `Authorization: Bearer <MCP_TRANSPORT_TOKEN>` or the connection is rejected
    with 401 before any MCP frame is processed. Distinct from Slice-5
    capability tokens — this gates *whether a client may connect at all*.
    """

    async def dispatch(self, request, call_next):
        header = request.headers.get("authorization", "")
        expected = f"Bearer {MCP_TRANSPORT_TOKEN}"
        if header != expected:
            return JSONResponse(
                {"error": "unauthorized", "reason": "missing_or_wrong_bearer"},
                status_code=401,
            )
        return await call_next(request)


def _build_app() -> Starlette:
    base = mcp.streamable_http_app()
    return Starlette(
        routes=base.routes,
        middleware=[Middleware(BearerAuth)],
        lifespan=base.router.lifespan_context,
    )


if __name__ == "__main__":
    if not MCP_TRANSPORT_TOKEN:
        print(
            "[mcp-server] FATAL: MCP_TRANSPORT_TOKEN env var not set or empty. "
            "Set it in .env / docker-compose.yaml before starting.",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(2)
    if not os.environ.get("CAPABILITY_TOKEN_KEY"):
        print(
            "[mcp-server] FATAL: CAPABILITY_TOKEN_KEY env var not set or empty. "
            "Slice 5 Step 4 capability-token verifier requires this key. "
            "Generate with: python -c 'import secrets; print(secrets.token_urlsafe(32))' "
            "and pin it in .env / docker-compose.yaml on both sift-mcp and sift-sentinel.",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(2)
    _log(
        f"starting streamable-HTTP on 0.0.0.0:8000/mcp; "
        f"evidence_roots={[str(r) for r in EVIDENCE_ROOTS]}; "
        f"cases_root={CASES_ROOT}; bearer_len={len(MCP_TRANSPORT_TOKEN)}; "
        f"cap_key_len={len(os.environ.get('CAPABILITY_TOKEN_KEY', ''))}"
    )
    uvicorn.run(_build_app(), host="0.0.0.0", port=8000, log_level="info")
