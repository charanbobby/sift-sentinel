"""
Find Evil — Slice 2 MCP Server (runs inside the `sift` container).

Spawned via stdio from the notebook container:

    docker exec -i \
        --user sansforensics \
        -e FIND_EVIL_CASE_ID=srl-2018-wkstn-05 \
        sift python3 /opt/mcp/server.py

Seven disciplines enforced (see slice-2-runbook.md Step 3):

    1. argv arrays only — never shell=True or string interpolation
    2. Typed tool inputs via Pydantic → MCP JSON Schema
    3. Path allowlist: reads from /mnt/hackathon/**, writes under <case>/analysis/**
    4. Plugin allowlist for regripper (added with the regripper tool)
    5. stdout truncation: 64 KB cap returned to client; full output persisted
    6. Every call appended to <case>/analysis/tool_calls.jsonl (audit trail)
    7. All diagnostics go to stderr — stdout is reserved for MCP protocol framing
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

CASE_ID = os.environ.get("FIND_EVIL_CASE_ID")
if not CASE_ID:
    # Server is case-agnostic by design — the spawning caller (notebook / agent runtime)
    # owns case selection and passes it via env. Fail fast so no tool call ever writes
    # to the wrong case directory by silently falling back to a stale default.
    print(
        "[mcp-server] FATAL: FIND_EVIL_CASE_ID env var not set. "
        "Spawn with: docker exec -i --user sansforensics -e FIND_EVIL_CASE_ID=<case> sift python3 /opt/mcp/server.py",
        file=sys.stderr,
        flush=True,
    )
    sys.exit(2)
# Read-path allowlist. `/mnt/hackathon` is :ro raw evidence (E01s, memory dumps).
# `/mnt/derived` is :rw preprocessed artifacts (raw .dd partitions extracted from
# multi-segment E01s via ewfmount+dd). Both are legitimate read sources for fsstat
# /fls/icat; only /mnt/hackathon is forensic-integrity-protected at the mount layer.
EVIDENCE_ROOTS = tuple(p.resolve() for p in (Path("/mnt/hackathon"), Path("/mnt/derived")))
EVIDENCE_ROOT = EVIDENCE_ROOTS[0]  # retained for backwards-compat where code/errors name the primary root
CASE_ROOT = Path(f"/home/sansforensics/cases/{CASE_ID}")
ANALYSIS_DIR = (CASE_ROOT / "analysis").resolve()
RAW_OUT_DIR = ANALYSIS_DIR / "raw"
EXTRACTED_DIR = ANALYSIS_DIR / "extracted"
TOOL_CALLS_LOG = ANALYSIS_DIR / "tool_calls.jsonl"
STDOUT_CAP_BYTES = 64 * 1024

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

ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUT_DIR.mkdir(parents=True, exist_ok=True)
EXTRACTED_DIR.mkdir(parents=True, exist_ok=True)


def _log(msg: str) -> None:
    print(f"[mcp-server] {msg}", file=sys.stderr, flush=True)


def _check_read_path(path_str: str) -> Path:
    p = Path(path_str).resolve()
    if not any(p == root or str(p).startswith(str(root) + os.sep) for root in EVIDENCE_ROOTS):
        allowed = ", ".join(str(r) for r in EVIDENCE_ROOTS)
        raise ValueError(f"read path {p} outside allowlist ({allowed})")
    if not p.exists():
        raise ValueError(f"read path {p} does not exist")
    return p


def _check_extracted_path(path_str: str) -> Path:
    """Hives passed to regripper MUST live under <case>/analysis/extracted/ — that
    directory is only ever written by icat_extract, so this check is what forces the
    icat-before-regripper dependency at the MCP layer (belt to the PLAN prompt's braces).
    """
    p = Path(path_str).resolve()
    if not str(p).startswith(str(EXTRACTED_DIR) + os.sep):
        raise ValueError(f"hive path {p} must be under {EXTRACTED_DIR}")
    if not p.exists():
        raise ValueError(f"hive path {p} does not exist (run icat_extract first)")
    return p


def _check_dest_filename(name: str) -> Path:
    """icat_extract takes a FILENAME (not a path) — prevents traversal via '..' or '/'."""
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        raise ValueError(f"dest_filename must be a plain filename, got {name!r}")
    return (EXTRACTED_DIR / name).resolve()


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
    tool: str,
    argv: list[str],
    call_args: dict,
    *,
    stdout_target: Optional[Path] = None,
) -> ToolResult:
    """Run `argv`, record the call in the audit trail, return a ToolResult.

    Default (stdout_target=None): capture stdout into memory, write to
    <raw>/<tool_call_id>.stdout, return a UTF-8 excerpt. Right for text tools like
    fsstat / fls / rip.pl.

    With stdout_target: stream stdout straight to that file (used by icat_extract
    for binary hive bytes that would be multi-MB and meaningless as a text excerpt).
    The excerpt is synthesized from size + sha256 so the LLM still sees a short,
    informative summary.
    """
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
        stdout_path = RAW_OUT_DIR / f"{tool_call_id}.stdout"
        stdout_path.write_bytes(raw_stdout)
        truncated = stdout_size > STDOUT_CAP_BYTES
        excerpt = raw_stdout[:STDOUT_CAP_BYTES].decode("utf-8", errors="replace")

    if raw_stderr:
        (RAW_OUT_DIR / f"{tool_call_id}.stderr").write_bytes(raw_stderr)

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
    with TOOL_CALLS_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    _log(
        f"{tool} exit={completed.returncode} dur={duration_ms}ms "
        f"out={stdout_size}B id={tool_call_id}"
    )
    return result


mcp = FastMCP("find-evil-slice2")


@mcp.tool()
def fsstat_e01(e01_path: str) -> ToolResult:
    """Run `fsstat` on an E01 image. Returns filesystem metadata (type, block size, MFT offset for NTFS).

    Args:
        e01_path: absolute path to the E01 under /mnt/hackathon/
    """
    evidence = _check_read_path(e01_path)
    return _run_and_record(
        tool="fsstat_e01",
        argv=["fsstat", str(evidence)],
        call_args={"e01_path": str(evidence)},
    )


@mcp.tool()
def fls_list(
    e01_path: str,
    parent_inode: Optional[int] = None,
    recurse: bool = False,
) -> ToolResult:
    """Run `fls` on an E01 image — list directory entries including deleted ones.

    Args:
        e01_path: absolute path to the E01 under /mnt/hackathon/
        parent_inode: list children of this inode; None lists the root
        recurse: if True, recurse into subdirectories
    """
    evidence = _check_read_path(e01_path)
    argv = ["fls", "-m", "/"]
    if recurse:
        argv.append("-r")
    argv.append(str(evidence))
    if parent_inode is not None:
        argv.append(str(parent_inode))
    return _run_and_record(
        tool="fls_list",
        argv=argv,
        call_args={
            "e01_path": str(evidence),
            "parent_inode": parent_inode,
            "recurse": recurse,
        },
    )


@mcp.tool()
def icat_extract(e01_path: str, inode: int, dest_filename: str) -> ToolResult:
    """Run `icat` to extract a file's bytes by inode out of an E01 image into
    the case's extracted/ directory. Use this to pull registry hive files
    (SOFTWARE, SYSTEM, NTUSER.DAT) off the disk before calling `regripper_run`.

    Args:
        e01_path: absolute path to the E01 under /mnt/hackathon/
        inode: inode number from a prior `fls_list` call
        dest_filename: a plain filename (no path separators), e.g. "SOFTWARE".
            The file lands at <case>/analysis/extracted/<dest_filename>, which
            is the only location `regripper_run` will accept as a hive path.
    """
    evidence = _check_read_path(e01_path)
    dest_path = _check_dest_filename(dest_filename)
    return _run_and_record(
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
def regripper_run(hive_path: str, plugin: str) -> ToolResult:
    """Run a named RegRipper plugin against a Windows Registry hive to extract
    persistence-relevant keys (Run, Services, IFEO, etc.). The hive MUST have
    been produced by a prior `icat_extract` call — only files under the case's
    extracted/ directory are accepted.

    Args:
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
    hive = _check_extracted_path(hive_path)
    if plugin not in REGRIPPER_PLUGIN_ALLOWLIST:
        raise ValueError(
            f"plugin {plugin!r} not in allowlist; "
            f"allowed: {sorted(REGRIPPER_PLUGIN_ALLOWLIST)}"
        )
    return _run_and_record(
        tool="regripper_run",
        argv=["rip.pl", "-r", str(hive), "-p", plugin],
        call_args={"hive_path": str(hive), "plugin": plugin},
    )


if __name__ == "__main__":
    _log(
        f"starting; case={CASE_ID} analysis_dir={ANALYSIS_DIR} "
        f"evidence_root={EVIDENCE_ROOT}"
    )
    mcp.run()  # stdio transport is the default
