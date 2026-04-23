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

from pipeline.schemas import CapabilityToken  # noqa: E402
from pipeline.mcp.tokens import CapabilityDenied, verify_token  # noqa: E402


# Read-path allowlist. `/mnt/hackathon` is :ro raw evidence (E01s, memory dumps).
# `/mnt/derived` is :rw preprocessed artifacts (raw .dd partitions extracted from
# multi-segment E01s via ewfmount+dd). Both are legitimate read sources for fsstat
# /fls/icat; only /mnt/hackathon is forensic-integrity-protected at the mount layer.
EVIDENCE_ROOTS = tuple(p.resolve() for p in (Path("/mnt/hackathon"), Path("/mnt/derived")))
EVIDENCE_ROOT = EVIDENCE_ROOTS[0]  # retained for backwards-compat where code/errors name the primary root
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
}


class CasePaths(NamedTuple):
    case_root: Path
    analysis: Path
    raw_out: Path
    extracted: Path
    tool_calls_log: Path


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


class ToolResult(BaseModel):
    tool_call_id: str
    tool: str
    args: dict
    exit_code: int
    duration_ms: int
    stdout_excerpt: str = Field(
        description=f"stdout truncated to {STDOUT_CAP_BYTES} bytes"
    )
    stdout_hash: str
    stdout_path: str
    truncated: bool


def _run_and_record(
    case_id: str,
    tool: str,
    argv: list[str],
    call_args: dict,
    *,
    stdout_target: Optional[Path] = None,
) -> ToolResult:
    """Run `argv`, record the call in the per-case audit trail, return a ToolResult.

    Default (stdout_target=None): capture stdout into memory, write to
    <raw>/<tool_call_id>.stdout, return a UTF-8 excerpt. Right for text tools like
    fsstat / fls / rip.pl.

    With stdout_target: stream stdout straight to that file (used by icat_extract
    for binary hive bytes that would be multi-MB and meaningless as a text excerpt).
    The excerpt is synthesized from size + sha256 so the LLM still sees a short,
    informative summary.
    """
    paths = _case_paths(case_id)
    tool_call_id = str(uuid.uuid4())
    t0 = time.monotonic()
    if stdout_target is not None:
        stdout_target.parent.mkdir(parents=True, exist_ok=True)
        with stdout_target.open("wb") as sink:
            completed = subprocess.run(
                argv, stdout=sink, stderr=subprocess.PIPE, check=False,
            )
    else:
        completed = subprocess.run(argv, capture_output=True, check=False)
    duration_ms = int((time.monotonic() - t0) * 1000)

    raw_stderr = completed.stderr or b""

    if stdout_target is not None:
        stdout_size = stdout_target.stat().st_size
        h = hashlib.sha256()
        with stdout_target.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        stdout_hash = h.hexdigest()
        stdout_path = stdout_target
        excerpt = (
            f"<binary: {stdout_size} bytes written to {stdout_target} "
            f"sha256={stdout_hash}>"
        )
        truncated = True  # we never return the full bytes in the excerpt
    else:
        raw_stdout = completed.stdout or b""
        stdout_size = len(raw_stdout)
        stdout_hash = hashlib.sha256(raw_stdout).hexdigest()
        stdout_path = paths.raw_out / f"{tool_call_id}.stdout"
        stdout_path.write_bytes(raw_stdout)
        truncated = stdout_size > STDOUT_CAP_BYTES
        excerpt = raw_stdout[:STDOUT_CAP_BYTES].decode("utf-8", errors="replace")

    if raw_stderr:
        (paths.raw_out / f"{tool_call_id}.stderr").write_bytes(raw_stderr)

    result = ToolResult(
        tool_call_id=tool_call_id,
        tool=tool,
        args=call_args,
        exit_code=completed.returncode,
        duration_ms=duration_ms,
        stdout_excerpt=excerpt,
        stdout_hash=stdout_hash,
        stdout_path=str(stdout_path),
        truncated=truncated,
    )

    entry = {
        "tool_call_id": tool_call_id,
        "case_id": case_id,
        "tool": tool,
        "args": call_args,
        "argv": argv,
        "exit_code": completed.returncode,
        "duration_ms": duration_ms,
        "stdout_hash": stdout_hash,
        "stdout_path": str(stdout_path),
        "stderr_bytes": len(raw_stderr),
        "truncated": truncated,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    with paths.tool_calls_log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    _log(
        f"{tool} case={case_id} exit={completed.returncode} dur={duration_ms}ms "
        f"out={stdout_size}B id={tool_call_id}"
    )
    return result


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


def _denial_result(
    tool: str, reason: str, case_id: str, path: str, token_id: str | None = None,
) -> ToolResult:
    return ToolResult(
        tool_call_id=str(uuid.uuid4()),
        tool=tool,
        args={"case_id": case_id, "path": path, "token_id": token_id},
        exit_code=-1,
        duration_ms=0,
        stdout_excerpt=f"capability_denied:{reason}",
        stdout_hash="",
        stdout_path="",
        truncated=False,
    )


def _enforce_capability(
    capability_token: str,
    plan_digest: str,
    tool: str,
    *,
    case_id: str,
    path: str,
) -> ToolResult | None:
    """Return None when the call is in the token's scope, else a denial ToolResult.

    Order of checks — each short-circuits so callers get one deterministic reason:
      1. case_id validation (stops malformed case_ids reaching _case_paths)
      2. token JSON parse
      3. verify_token (signature, expiry, case match, tool match, path match, plan_digest match)
    """
    try:
        _validate_case_id(case_id)
    except ValueError as e:
        _record_denial(tool, case_id, f"case_id_invalid:{e}", path, None)
        return _denial_result(tool, "case_id_invalid", case_id, path)

    try:
        token = CapabilityToken.model_validate_json(capability_token)
    except ValidationError as e:
        etype = e.errors()[0]["type"] if e.errors() else "unknown"
        _record_denial(tool, case_id, f"token_parse_error:{etype}", path, None)
        return _denial_result(tool, f"token_parse_error:{etype}", case_id, path)
    except Exception as e:  # noqa: BLE001 — JSON decode / unexpected pre-validation failure
        _record_denial(tool, case_id, f"token_parse_error:{type(e).__name__}", path, None)
        return _denial_result(tool, f"token_parse_error:{type(e).__name__}", case_id, path)

    try:
        verify_token(token, tool=tool, path=path, case_id=case_id, plan_digest=plan_digest)
    except CapabilityDenied as e:
        _record_denial(tool, case_id, e.reason, path, token.token_id)
        return _denial_result(tool, e.reason, case_id, path, token_id=token.token_id)

    return None


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
) -> ToolResult:
    """Run `fsstat` on an E01 image. Returns filesystem metadata (type, block size, MFT offset for NTFS).

    Args:
        capability_token: JSON-serialized CapabilityToken issued by the orchestrator after human plan approval; scopes this call to (tool, path-prefix, plan).
        plan_digest: sha256 of the approved ToolPlan; must equal token.plan_digest or the call is denied.
        case_id: the case this call belongs to; audit trail + extracted hives scope to <case>/analysis/
        e01_path: absolute path to the E01 under /mnt/hackathon/
    """
    denial = _enforce_capability(
        capability_token, plan_digest, "fsstat_e01",
        case_id=case_id, path=e01_path,
    )
    if denial is not None:
        return denial
    evidence = _check_read_path(e01_path)
    return _run_and_record(
        case_id=case_id,
        tool="fsstat_e01",
        argv=["fsstat", str(evidence)],
        call_args={"e01_path": str(evidence)},
    )


@mcp.tool()
def fls_list(
    capability_token: str,
    plan_digest: str,
    case_id: str,
    e01_path: str,
    parent_inode: Optional[int] = None,
    recurse: bool = False,
) -> ToolResult:
    """Run `fls` on an E01 image — list directory entries including deleted ones.

    Args:
        capability_token: JSON-serialized CapabilityToken; scopes this call.
        plan_digest: sha256 of the approved ToolPlan; must equal token.plan_digest.
        case_id: the case this call belongs to
        e01_path: absolute path to the E01 under /mnt/hackathon/
        parent_inode: list children of this inode; None lists the root
        recurse: if True, recurse into subdirectories
    """
    denial = _enforce_capability(
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
    return _run_and_record(
        case_id=case_id,
        tool="fls_list",
        argv=argv,
        call_args={
            "e01_path": str(evidence),
            "parent_inode": parent_inode,
            "recurse": recurse,
        },
    )


@mcp.tool()
def icat_extract(
    capability_token: str,
    plan_digest: str,
    case_id: str,
    e01_path: str,
    inode: int,
    dest_filename: str,
) -> ToolResult:
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
    denial = _enforce_capability(
        capability_token, plan_digest, "icat_extract",
        case_id=case_id, path=e01_path,
    )
    if denial is not None:
        return denial
    evidence = _check_read_path(e01_path)
    dest_path = _check_dest_filename(case_id, dest_filename)
    return _run_and_record(
        case_id=case_id,
        tool="icat_extract",
        argv=["icat", str(evidence), str(inode)],
        call_args={
            "e01_path": str(evidence),
            "inode": inode,
            "dest_filename": dest_filename,
            "dest_path": str(dest_path),
        },
        stdout_target=dest_path,
    )


@mcp.tool()
def regripper_run(
    capability_token: str,
    plan_digest: str,
    case_id: str,
    hive_path: str,
    plugin: str,
) -> ToolResult:
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
    denial = _enforce_capability(
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
    return _run_and_record(
        case_id=case_id,
        tool="regripper_run",
        argv=["rip.pl", "-r", str(hive), "-p", plugin],
        call_args={"hive_path": str(hive), "plugin": plugin},
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
