"""LangGraph node implementations.

Extracted from slice2.ipynb cells C4 + C6 + C8 + C9 at Slice 5 Step 7 (see
docs/runbooks/slice-5-runbook.md §Step 7a). Each node function has signature
`(state: PipelineState) -> dict` (LangGraph merges the returned dict into
state).

Runtime dependencies the nodes read from module-level globals (set by the
notebook's C1 / by probes before invoking the graph):

    LLM_CLIENT          Langfuse-wrapped OpenAI client (extract_client in C1)
    LANGFUSE            langfuse_instance from `get_client()`
    PLAN_MODEL          model id string (e.g. "anthropic/claude-sonnet-4.6")
    INTERPRET_MODEL     model id string
    CASE_ID             e.g. "srl-2018-wkstn-05"
    E01_PATH            absolute path to the case E01 (used in PLAN prompt)
    OUT_DIR             per-case pipeline out/ directory (defaults to ./out)

The nodes raise `RuntimeError` if a required global is unset at call time —
that's the fail-fast signal that the notebook skipped C1 or a probe forgot to
configure.

Step 7a delivers: `plan_node` fully, the other five nodes as thin stubs.
Step 7b fills in `execute_node` + `interpret_node`.
Step 7c fills in `critic_node` and adapts `pipeline.critic` to EvidenceRecord.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from pipeline.schemas import (
    CriticDisagreement,
    EvidenceRecord,
    Finding,
    Findings,
    ToolPlan,
)
from pipeline.mcp.tokens import compute_plan_digest

if TYPE_CHECKING:
    from pipeline.graph import PipelineState


# ============================================================================
# Module-level runtime configuration
# ============================================================================
# Set by the notebook's C1 before calling graph.invoke(). Probes must set them
# explicitly too. Stays None here so an accidental early import doesn't pull
# a stale reference from a previous kernel.

LLM_CLIENT = None
LANGFUSE = None
PLAN_MODEL: Optional[str] = None
INTERPRET_MODEL: Optional[str] = None
CASE_ID: Optional[str] = None
E01_PATH: Optional[str] = None
OUT_DIR: Path = Path("out")


def _require(name: str, value):
    """Fail-fast guard: a node tried to run before the notebook configured it."""
    if value is None:
        raise RuntimeError(
            f"pipeline.nodes.{name} is unset — call configure() or set the "
            f"module attribute from the notebook C1 cell before invoking the graph."
        )
    return value


# ============================================================================
# Shared helpers
# ============================================================================

def _parse_json_response(raw: str, model_cls):
    """Strip optional ```json markdown fences from LLM output, then Pydantic-validate.

    Claude (Sonnet / Opus) often wraps structured output in ```json…``` fences
    even with `response_format={"type":"json_object"}`. Gemini usually doesn't.
    One helper handles both so every parse step in the pipeline is identical.
    """
    s = raw.strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json|JSON)?\s*", "", s)
        s = re.sub(r"\s*```\s*$", "", s)
    return model_cls.model_validate_json(s)


# ============================================================================
# PLAN — real implementation (lifted from notebook C6)
# ============================================================================

# Placeholder DSL for deferred-resolution args:
#   "{step:N.EXTRACTOR(PARAM)}"
# Resolved by execute_node against the upstream step's structured_fields before
# the MCP call. Kept strict so malformed placeholders fail validation rather
# than silently confusing the executor.
PLACEHOLDER_RE = re.compile(r"^\{step:(\d+)\.(\w+)\(([^)]*)\)\}$")
KNOWN_EXTRACTORS = {"inode_by_name"}


def _available_tools_spec(case_id: str) -> dict:
    """Return the tool/plugin spec advertised to the PLAN model. `case_id` only
    appears in the `regripper_run.args.hive_path` hint; everything else is
    case-agnostic. Kept as a function (not a module const) so two probes with
    different case_ids can't accidentally share a cached dict.
    """
    return {
        "fsstat_e01": {
            "description": "Run `fsstat` on an E01 image. Returns filesystem metadata (type, block size, MFT offset for NTFS).",
            "args": {"e01_path": "absolute path to the E01 under /mnt/hackathon/"},
        },
        "fls_list": {
            "description": "Run `fls` — list directory entries (includes deleted). Use iteratively to locate hive file inodes inside Windows/System32/config/ and user profile folders.",
            "args": {
                "e01_path": "absolute path to the E01",
                "parent_inode": "int OR placeholder OR null; null lists the root",
                "recurse": "bool; True walks the whole subtree (expensive — only use on small subtrees like Users/<name>/)",
            },
        },
        "icat_extract": {
            "description": "Extract a file's bytes by inode out of the E01 into <case>/analysis/extracted/<dest_filename>. Use before regripper_run to stage registry hive bytes.",
            "args": {
                "e01_path": "absolute path to the E01",
                "inode": "int OR placeholder (must come from a prior fls_list step via a binding)",
                "dest_filename": "plain filename (no path separators), e.g. 'SOFTWARE', 'SYSTEM', 'NTUSER-administrator.DAT'",
            },
        },
        "regripper_run": {
            "description": "Run a named RegRipper plugin against a hive previously extracted by icat_extract. The server rejects any hive_path not under <case>/analysis/extracted/, so every regripper_run MUST have an icat_extract upstream in depends_on.",
            "args": {
                "hive_path": f"absolute path; must be exactly /home/sansforensics/cases/{case_id}/analysis/extracted/<dest_filename> where <dest_filename> matches the upstream icat_extract step",
                "plugin": "plugin name from the allowlist below",
            },
            "plugin_allowlist": {
                "run":          "hive: Software or NTUSER.DAT — Run / RunOnce keys (most common persistence)",
                "runonceex":    "hive: Software — RunOnceEx keys",
                "services":     "hive: System — CurrentControlSet\\Services (SYSTEM-privilege persistence)",
                "schedagent":   "hive: Software — scheduled-task tracking",
                "appinitdlls":  "hive: Software — AppInit_DLLs (DLL injection into every GUI process)",
                "imagefile":    "hive: Software — Image File Execution Options / debuggers (IFEO)",
                "winlogon_tln": "hive: Software — Winlogon Userinit / Shell / Notify",
            },
        },
        # Slice 5 Step 6: 5th MCP tool — scheduled_tasks_parse (T1053.005).
        # Intentionally still described in PLAN-time docs even though the
        # notebook hadn't advertised it before the node-lift, so PLAN can
        # produce a step that uses it without a separate Step 7 prompt edit.
        "scheduled_tasks_parse": {
            "description": "Extract a Windows Task XML file by inode from `\\Windows\\System32\\Tasks\\` and parse it server-side. Chains icat + XML parse in one call so one PLAN step can claim T1053.005 coverage.",
            "args": {
                "e01_path": "absolute path to the E01",
                "task_xml_inode": "int OR placeholder from a prior fls_list over Windows/System32/Tasks/",
                "dest_filename": "plain filename; XML lands at <case>/analysis/extracted/<dest_filename>",
            },
        },
    }


def _plan_system_prompt(case_id: str, e01_path: str) -> str:
    """Full PLAN system prompt. Pure function of `(case_id, e01_path)` so
    cache_control: ephemeral hits on the second call with the same case.
    """
    tools_spec = json.dumps(_available_tools_spec(case_id), indent=2)
    tool_plan_schema = json.dumps(ToolPlan.model_json_schema(), indent=2)
    return f"""You design a tool-call plan to answer a forensic question, using ONLY the 5 tools
available below. You are NOT executing anything — only producing a plan that a human
will review before any tool runs.

Return a single JSON object matching exactly this schema (no prose, no markdown fences):

{tool_plan_schema}

Case constants (use these LITERAL values — do NOT invent paths):
- case_id:        {case_id}
- e01_path:       {e01_path}
- extracted_dir:  /home/sansforensics/cases/{case_id}/analysis/extracted

Available tools:
{tools_spec}

Argument templating (READ THIS BEFORE WRITING ANY STEP):
- Inodes are not known at planning time — they come from upstream `fls_list` output.
  DO NOT guess. DO NOT write `"inode": 0` or any made-up number. Write a placeholder:
      "{{step:N.EXTRACTOR(PARAM)}}"
  The executor substitutes it before calling the tool. Step N MUST appear in the same
  step's `depends_on`.
- Available extractor (only one):
      inode_by_name(FILENAME)   # FILENAME is a basename, case-insensitive
          e.g. "inode": "{{step:5.inode_by_name(SOFTWARE)}}"

Filesystem navigation (use placeholders; do NOT emit duplicate fls_list calls):
- To drill from root to /Windows/System32/config, chain fls_list calls via parent_inode:
      step 2: fls_list(parent_inode=null, recurse=false)                                    # list root
      step 3: fls_list(parent_inode="{{step:2.inode_by_name(Windows)}}",  recurse=false)    # list /Windows
      step 4: fls_list(parent_inode="{{step:3.inode_by_name(System32)}}", recurse=false)    # list /Windows/System32
      step 5: fls_list(parent_inode="{{step:4.inode_by_name(config)}}",   recurse=false)    # list /Windows/System32/config
      step 6: icat_extract(inode="{{step:5.inode_by_name(SOFTWARE)}}", dest_filename="SOFTWARE")
      step 7: icat_extract(inode="{{step:5.inode_by_name(SYSTEM)}}",   dest_filename="SYSTEM")
- If two steps would have identical (parent_inode, recurse) args, collapse them into
  ONE step — downstream steps can reference the same fls_list output.

Hard rules:
- To inspect a registry hive you MUST first call `icat_extract` on it, then call
  `regripper_run` with `hive_path` = /home/sansforensics/cases/{case_id}/analysis/extracted/<dest_filename>
  where <dest_filename> matches the upstream icat_extract step. Every `regripper_run`
  step MUST list the corresponding `icat_extract` step_id in `depends_on`.
- `regripper_run.plugin` MUST be one of the allowlisted plugin names above. Do NOT
  invent plugin names. Pick the plugin whose expected hive matches the hive you extracted.
- For per-user persistence (Run keys in NTUSER.DAT), plan one icat_extract per user's
  NTUSER.DAT — use dest_filename like 'NTUSER-<username>.DAT' to keep them distinct.
  User profile directories live under /Users (Windows 10+) or /Documents and Settings (XP).

Soft rules:
- Score `confidence` for each step INDEPENDENTLY. Do not default to "high". Rate each
  step based on how directly its output contributes to answering the question (an
  `fsstat_e01` is usually "high" for confirming layout; an `fls_list` navigation step
  is "medium" because its value is discovering inodes, not producing findings).
- Set `expected_findings_range` based on typical compromised Windows hosts (usually 1-5
  persistence mechanisms). Emit as a 2-element JSON array, e.g. [1, 5].
- Every step MUST have a non-empty `purpose` (one sentence).
- Dependencies: if step N needs output from step M, set depends_on=[M]. Otherwise [].
"""


def plan_node(state: "PipelineState") -> dict:
    """Emit a ToolPlan and compute its digest.

    Slice 3 Phase C idempotency: if `state.tool_plan` is already populated AND
    no Critic-emitted corrective is pending, skip — this lets cell re-runs that
    carry pipeline_state forward stay idempotent. A corrective (re_plan edge)
    always re-fires PLAN because the prompt's second system block changes.

    Slice 5 Step 7 addition: computes + returns `plan_digest` alongside the
    tool_plan so execute_node can bind each MCP call to the approved plan
    without re-hashing.
    """
    if state.tool_plan is not None and not state.corrective_instruction:
        return {}

    client = _require("LLM_CLIENT", LLM_CLIENT)
    langfuse = _require("LANGFUSE", LANGFUSE)
    model = _require("PLAN_MODEL", PLAN_MODEL)
    case_id = _require("CASE_ID", CASE_ID)
    e01_path = _require("E01_PATH", E01_PATH)

    from langfuse import propagate_attributes  # local import — langfuse optional at module load

    with propagate_attributes(
        session_id=state.run_id,
        user_id=case_id,
        tags=["phase:plan"],
        metadata={"phase": "plan"},
    ):
        # Candidates list flattened — double-wrap wasted context in earlier
        # shape (question + candidates:{question, candidates:[...]})
        user_input = json.dumps({
            "question":   state.question,
            "candidates": [c.model_dump() for c in (state.candidates.candidates if state.candidates else [])],
        }, indent=2)

        # Anthropic prompt caching: the ~2k-token system block is stable across
        # runs for a given (case_id, e01_path), so mark it cacheable. The
        # corrective block (when present) is a SECOND system block — keeps the
        # first block byte-identical on first runs and cache-hits remain cheap.
        messages = [
            {"role": "system", "content": [
                {"type": "text", "text": _plan_system_prompt(case_id, e01_path),
                 "cache_control": {"type": "ephemeral"}},
            ]},
        ]
        if state.corrective_instruction:
            messages.append({
                "role": "system",
                "content": f"CRITIC CORRECTION (retry pass)\n\n{state.corrective_instruction}",
            })
        messages.append({"role": "user", "content": user_input})

        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            response_format={"type": "json_object"},
        )
        tool_plan = _parse_json_response(resp.choices[0].message.content, ToolPlan)

        out_path = OUT_DIR / "tool_plan.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(tool_plan.model_dump_json(indent=2).encode("utf-8"))

        # plan_digest locks the approved plan to every downstream MCP call via
        # the capability-token binding. Canonical form (sort_keys + tight
        # separators) — same function used by `issue_token` and by the server-
        # side verifier, so the three plan_digest uses (token.plan_digest,
        # call-arg plan_digest, failed_plan_hashes dedup) all live in one hash
        # space. File at out/tool_plan.json stays pretty-printed for human
        # review; digest is NOT computed from that representation.
        plan_digest = compute_plan_digest(tool_plan)

        n_regripper = sum(1 for s in tool_plan.steps if s.tool == "regripper_run")
        n_icat      = sum(1 for s in tool_plan.steps if s.tool == "icat_extract")
        n_sched     = sum(1 for s in tool_plan.steps if s.tool == "scheduled_tasks_parse")
        langfuse.update_current_span(
            output=tool_plan.model_dump(),
            metadata={
                "n_steps": len(tool_plan.steps),
                "n_icat_extract": n_icat,
                "n_regripper_run": n_regripper,
                "n_scheduled_tasks_parse": n_sched,
                "expected_findings_range": list(tool_plan.expected_findings_range),
                "plan_digest_short": plan_digest[:16],
            },
        )
        return {"tool_plan": tool_plan, "plan_digest": plan_digest}


# ============================================================================
# EXTRACT — stub (real implementation stays in notebook C5 for now; lifts with
# Step 12 notebook slim-down since it doesn't touch the Slice-5 MCP API)
# ============================================================================

def extract_node(state: "PipelineState") -> dict:
    """Stub. Real C5 body stays in the notebook through Step 7; Step 12 lifts
    it alongside the final notebook slim-down. Until then, the notebook's C5
    cell populates `state.candidates` before the graph is invoked, so this
    stub is a no-op pass-through."""
    return {}


# ============================================================================
# EXECUTE — real implementation (lifted from notebook C8, rewritten for the
# Slice-5 MCP API: EvidenceRecord return shape, capability_token + plan_digest
# on every call, placeholder resolver reads `structured_fields` instead of
# raw stdout bodyfile).
# ============================================================================

# Default URL for the streamable-HTTP MCP endpoint. Overridable via the
# `MCP_URL` env var if a probe points at a different endpoint (e.g. ephemeral
# test server). The Slice-5 compose network makes `sift-mcp` the canonical
# hostname inside the `findevil-internal` bridge.
MCP_URL_DEFAULT = "http://sift-mcp:8000/mcp"

# Single-brace DSL — same shape the PLAN prompt teaches: "{step:N.EXTRACTOR(PARAM)}"
# The regex is identical to the one C8 used in stdio days; the resolver below
# is what changed. Slice-5 resolution pulls structured fields off an upstream
# `EvidenceRecord`, no longer parses an `fls -m /` bodyfile from raw stdout.
_EXEC_PLACEHOLDER_RE = re.compile(r"^\{step:(\d+)\.(\w+)\(([^)]*)\)\}$")

# execute_node halt semantics — per ToolExecutionStatus:
#
#   CONTINUE                          HALT
#   --------                          ----
#   ok            full success        timeout              subprocess killed
#   empty         legit null finding  permission_denied    subprocess no-access
#   parse_error   parser degraded     capability_denied    policy refusal
#                 but exit=0                                (Step 8 will relax)
#
# `empty` and `parse_error` produce usable (though degraded) structured_fields
# and the Critic's R_09 / R_12 / R_06 can reason about them; halting loses
# independent downstream steps that could succeed. The three HALT statuses
# represent "tool didn't produce a substantive result" cases where the most
# likely downstream impact is either a resolver error (if dependents chain
# through) or more denials of the same kind — halting early surfaces the real
# problem. Resolver (_resolve_args) keeps a strict "upstream must be ok" rule
# — chaining semantics are intentionally stricter than halt semantics.
_CONTINUABLE_STATUSES = frozenset({"ok", "empty", "parse_error"})


def _status_is_continuable(status: str) -> bool:
    """Decide whether execute_node should keep running after a step returned
    this `tool_execution_status`. Partition enforced by
    `_CONTINUABLE_STATUSES`. Exposed for unit-test probes."""
    return status in _CONTINUABLE_STATUSES


class ResolverError(RuntimeError):
    """Raised when a placeholder in step.args can't be resolved against
    upstream evidence. Caller halts execution and labels the failure in the
    Langfuse span + evidence.jsonl audit record."""


def _resolve_inode_by_name(fls_structured: dict, target_name: str) -> int:
    """Slice-5 `inode_by_name` extractor — works off an upstream `fls_list`
    EvidenceRecord.structured_fields (FlsResult shape: `{entries: [...]}`).

    Case-insensitive match on `filename_safe` (adversarial filename bytes are
    sanitized server-side, so a crafted `ignore previous instructions` filename
    would appear as `<NON_PRINTABLE>` — it won't match any PLAN-supplied
    target_name, so the step errors cleanly and the Critic can re_plan).
    """
    target = target_name.strip().lower()
    hits: set[int] = set()
    for entry in fls_structured.get("entries", []):
        name = str(entry.get("filename_safe", "")).lower()
        if name == target:
            try:
                hits.add(int(entry["inode"]))
            except (KeyError, TypeError, ValueError):
                continue
    if not hits:
        raise ResolverError(f"inode_by_name({target_name}) → no match")
    if len(hits) > 1:
        raise ResolverError(
            f"inode_by_name({target_name}) → ambiguous: {sorted(hits)}"
        )
    return next(iter(hits))


_EXEC_EXTRACTORS = {"inode_by_name": _resolve_inode_by_name}


def _resolve_args(args: dict, evidence_by_step_id: dict[int, "EvidenceRecord"]) -> dict:
    """Walk step.args; resolve any string value matching the placeholder DSL.

    Non-string or non-matching values pass through unchanged (PLAN-emitted
    ints, bools, nulls). Halts on any upstream step that is absent, that
    references an unknown extractor, or whose tool_execution_status is not
    "ok" (dependent tool can't consume a denied/timed-out upstream).
    """
    out: dict = {}
    for k, v in args.items():
        if isinstance(v, str):
            m = _EXEC_PLACEHOLDER_RE.match(v.strip())
            if m:
                step_n = int(m.group(1))
                extractor = m.group(2)
                param = m.group(3)
                if step_n not in evidence_by_step_id:
                    raise ResolverError(
                        f"placeholder refers to step {step_n}, not yet executed"
                    )
                if extractor not in _EXEC_EXTRACTORS:
                    raise ResolverError(
                        f"unknown extractor `{extractor}` — allowed: "
                        f"{sorted(_EXEC_EXTRACTORS)}"
                    )
                upstream = evidence_by_step_id[step_n]
                if upstream.tool_execution_status != "ok":
                    raise ResolverError(
                        f"upstream step {step_n} status="
                        f"{upstream.tool_execution_status}; cannot chain"
                    )
                out[k] = _EXEC_EXTRACTORS[extractor](upstream.structured_fields, param)
                continue
        out[k] = v
    return out


def _unwrap_mcp(result) -> dict:
    """Normalize a FastMCP `CallToolResult` into a plain dict.

    FastMCP wraps a Pydantic return (our `EvidenceRecord`) as `structuredContent`,
    sometimes under a single `result` key. If that's missing, fall back to the
    first text-content block parsed as JSON. Raises on `isError=True` so the
    caller can surface the server-side exception rather than silently pass an
    empty record to `EvidenceRecord.model_validate`.
    """
    if result.isError:
        raise RuntimeError(
            "\n".join(getattr(c, "text", str(c)) for c in result.content)
        )
    data = getattr(result, "structuredContent", None)
    if data is None and result.content:
        data = json.loads(getattr(result.content[0], "text", "{}"))
    data = data or {}
    if set(data.keys()) == {"result"}:
        data = data["result"]
    return data


async def execute_node(state: "PipelineState") -> dict:
    """Run every step in the approved tool_plan against the streamable-HTTP
    MCP endpoint; collect EvidenceRecords; return `{"evidence": [...]}`.

    Slice-5 contract changes vs. C8:
      - Each call carries `capability_token` (JSON-serialized), `plan_digest`,
        and `case_id` in addition to the step's planned args. The server
        `verify_token()`s them all; a denial comes back as an EvidenceRecord
        with `tool_execution_status="capability_denied"`, not a raised exception.
      - Returns EvidenceRecord (not RawResult). The LLM never sees raw stdout
        under the dual-channel boundary — server-parsed `structured_fields` is
        the agent channel (channel B). Raw bytes live server-side in
        `<case>/analysis/raw/<tool_call_id>.raw` for Slice-6 ledger replay.
      - Placeholder resolver iterates the upstream FlsResult instead of
        parsing an `fls -m /` bodyfile from disk.

    Halt semantics — delegated to `_status_is_continuable`. Continues on
    `ok` / `empty` / `parse_error` (tool produced a substantive-or-degraded
    result the Critic can reason about); halts on `timeout` /
    `permission_denied` / `capability_denied` (tool didn't complete). See
    the table above `_CONTINUABLE_STATUSES` for the full partition + why.
    Step 8 will relax the `capability_denied` halt via graph edge re-routing
    so the Critic gets a chance to re_plan.

    Requires: `state.tool_plan`, `state.plan_digest`, `state.capability_token`
    populated upstream. The PipelineState dataclass allows them to be None so
    the graph can load, but execute_node raises a fail-fast RuntimeError if
    any is missing at invocation — the notebook's human-checkpoint cell (C7)
    is the canonical place tokens get minted via `tokens.issue_token`.
    """
    if state.tool_plan is None:
        raise RuntimeError("state.tool_plan is None — run plan_node first")
    if state.plan_digest is None:
        raise RuntimeError("state.plan_digest is None — plan_node must populate it")
    if state.capability_token is None:
        raise RuntimeError(
            "state.capability_token is None — issue it via "
            "pipeline.mcp.tokens.issue_token after human plan approval "
            "(Slice 5 Step 8 wires this into C7)"
        )

    case_id = _require("CASE_ID", CASE_ID)
    langfuse = _require("LANGFUSE", LANGFUSE)
    from langfuse import propagate_attributes  # local — matches plan_node style

    mcp_url = os.environ.get("MCP_URL", MCP_URL_DEFAULT)
    bearer = os.environ.get("MCP_TRANSPORT_TOKEN", "")
    if not bearer:
        raise RuntimeError(
            "MCP_TRANSPORT_TOKEN env var not set — the bearer gate is "
            "pre-capability-token; unset means no connection will even open. "
            "Pin it in docker/.env + pass through to sift-sentinel."
        )
    mcp_headers = {"Authorization": f"Bearer {bearer}"}

    # Topological-order pre-assertion: the PLAN prompt enforces step_id order,
    # but a malformed plan would break the placeholder resolver downstream —
    # belt + braces. Raised here so a bad plan never opens an MCP connection.
    for s in state.tool_plan.steps:
        if s.depends_on and max(s.depends_on) >= s.step_id:
            raise ValueError(
                f"step {s.step_id} depends on {s.depends_on} — not topological"
            )

    # Serialize the capability token once per invocation — same JSON goes on
    # every call. (If a re_plan edge invalidates plan_digest, plan_node re-
    # fires, which updates state.plan_digest; Step 8 will add re-issuance so
    # capability_token's plan_digest stays in sync.)
    token_json = state.capability_token.model_dump_json()

    evidence_by_step_id: dict[int, EvidenceRecord] = {}
    collected: list[EvidenceRecord] = []
    failed_step: Optional[int] = None

    with propagate_attributes(
        session_id=state.run_id,
        user_id=case_id,
        tags=["phase:execute"],
        metadata={"phase": "execute", "n_steps_planned": len(state.tool_plan.steps)},
    ):
        with langfuse.start_as_current_observation(name="execute", as_type="span") as exec_span:
            async with streamablehttp_client(mcp_url, headers=mcp_headers) as (read, write, _sid):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    for step in state.tool_plan.steps:
                        try:
                            resolved = _resolve_args(step.args, evidence_by_step_id)
                        except ResolverError as e:
                            exec_span.update(
                                level="ERROR",
                                status_message=f"resolve step {step.step_id}: {e}",
                            )
                            failed_step = step.step_id
                            break

                        call_args = {
                            **resolved,
                            "case_id": case_id,
                            "capability_token": token_json,
                            "plan_digest": state.plan_digest,
                        }

                        with langfuse.start_as_current_observation(
                            name=step.tool,
                            as_type="tool",
                            input={"step_id": step.step_id, "args": resolved, "purpose": step.purpose},
                        ) as tool_span:
                            data = _unwrap_mcp(await session.call_tool(step.tool, call_args))
                            ev = EvidenceRecord.model_validate(data)
                            evidence_by_step_id[step.step_id] = ev
                            collected.append(ev)

                            tool_span.update(
                                output={
                                    "tool_execution_status": ev.tool_execution_status,
                                    "raw_sha256": ev.raw_sha256,
                                    "n_injection_flags": len(ev.injection_flags),
                                    "expected_paths_covered": ev.expected_paths_covered,
                                },
                                metadata={
                                    "tool_call_id": ev.tool_call_id,
                                    "token_id": ev.token_id,
                                },
                            )

                            # Halt-vs-continue decision delegated to the
                            # module-level helper so the probe can unit-test
                            # the partition against all 6 ToolExecutionStatus
                            # values. See `_CONTINUABLE_STATUSES` above.
                            if not _status_is_continuable(ev.tool_execution_status):
                                tool_span.update(
                                    level="ERROR",
                                    status_message=f"tool_execution_status={ev.tool_execution_status}",
                                )
                                exec_span.update(
                                    level="ERROR",
                                    status_message=f"step {step.step_id} status={ev.tool_execution_status}",
                                )
                                failed_step = step.step_id
                                break

            non_ok_summary = [
                (i + 1, e.tool_execution_status)
                for i, e in enumerate(collected)
                if e.tool_execution_status != "ok"
            ]
            exec_span.update(output={
                "n_steps_executed": len(collected),
                "n_steps_planned": len(state.tool_plan.steps),
                "failed_step": failed_step,
                "n_ok": sum(1 for e in collected if e.tool_execution_status == "ok"),
                "n_empty": sum(1 for e in collected if e.tool_execution_status == "empty"),
                "n_parse_error": sum(1 for e in collected if e.tool_execution_status == "parse_error"),
                "non_ok_steps": non_ok_summary,
            })

    langfuse.flush()

    # Persist evidence.jsonl — audit-trail continuity replacement for C8's
    # raw_results.jsonl. Each line is a full EvidenceRecord (structured_fields
    # + injection_flags + raw_sha256 pointer to the server-side raw bytes).
    evidence_path = OUT_DIR / "evidence.jsonl"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    with evidence_path.open("w", encoding="utf-8") as f:
        for ev in collected:
            f.write(ev.model_dump_json() + "\n")

    # Partial results propagate. A halt on step N (resolver error OR
    # non-continuable status) leaves us with N-1 usable records; raising
    # would lose that signal to the caller's PipelineState.evidence. The
    # Critic + R_06 / R_12 already handle incompleteness; Critic sees a
    # len(state.evidence) < len(state.tool_plan.steps) delta and emits the
    # appropriate SCOPE_INCOMPLETE / ABSENCE_UNSUBSTANTIATED failure.
    # Surface a diagnostic on the print channel only.
    if failed_step is not None:
        print(
            f"  [execute]   halted at step {failed_step}; "
            f"returning {len(collected)}/{len(state.tool_plan.steps)} "
            f"partial EvidenceRecords — see {evidence_path}"
        )

    return {"evidence": collected}


# ============================================================================
# INTERPRET — real implementation (lifted from notebook C9, rewritten for the
# Slice-5 dual-channel boundary: bundle carries `structured_fields` only — raw
# stdout is preserved server-side but NEVER surfaces to the LLM).
# ============================================================================

INTERPRET_SYSTEM_PROMPT = """You are a DFIR (digital forensics and incident response) analyst. You receive the outputs of tool calls run against a Windows E01 disk image (`fsstat`, `fls`, `icat`, `regripper`, `scheduled_tasks_parse`) and the original investigation question. Your job is to produce a Findings JSON.

Under the Slice-5 dual-channel evidence boundary: raw tool stdout is NEVER surfaced to you. Every step's output is delivered as server-parsed `structured_fields` — typed, JSON-safe dicts with known shape per tool. This is the full evidence surface for you. Chain-of-custody raw bytes are preserved on the server side and referenced by `raw_sha256` for post-hoc audit; you do not see them directly.

## Hard rules

1. **Evidence must be real.** Every `Finding.evidence[i]` entry must have:
   - a `tool_call_id` that appears in the bundle's `steps[*].tool_call_id`
   - an `output_excerpt` that is a literal substring of that step's `structured_fields` JSON serialization (case-sensitive). Typical useful excerpts include the value of a `value_data_safe`, `action_command_safe`, `filename_safe`, or `key_path` field.
   NEVER fabricate registry keys, service names, paths, or values. If it isn't in the structured_fields of SOME step, it isn't evidence.

2. **Only report what the tools show.** A Finding means you have structured-field-backed evidence of a persistence mechanism. Do not emit a Finding because "this key usually exists" or "this plugin typically returns X". No evidence → no Finding.

3. **Classify every finding.** Every `Finding` MUST set the `classification` field to one of:
   - `attacker_persistence`       — confidently malicious; `notes` must explicitly rule out benign alternatives (see Disambiguation below)
   - `legitimate_responder_tool`  — DFIR/IR tool installed during incident response
   - `legitimate_vendor_product`  — commercial security or IT product
   - `legitimate_windows_default` — stock Windows component or driver (also use for `NOT_FOUND` findings)
   - `requires_disambiguation`    — signals suggest malicious but you cannot rule out benign; emit as MEDIUM confidence with unresolved alternatives in `notes`
   Findings classified as `legitimate_*` should NOT be emitted unless the caller explicitly asked for an inventory (they are not findings in the investigative sense).

4. **If nothing suspicious is found, emit exactly one Finding with** category="NOT_FOUND", mechanism="none", value="", evidence=[], confidence="high", classification="legitimate_windows_default".

5. **`confidence`** reflects how strongly the evidence implicates persistence:
   - `high`: clear suspicious path + value + category alignment + benign alternatives ruled out
   - `medium`: plausible but could be legitimate; worth deeper review
   - `low`: weak signal; flagging for completeness

6. **Honour `tool_execution_status`.** Each step reports one of: `ok`, `timeout`, `permission_denied`, `parse_error`, `empty`, `capability_denied`. Only `ok` (and sometimes `empty`) carries trustworthy evidence. If a step's status is `capability_denied` you must NOT treat its structured_fields as evidence — the call was refused before the tool ran; the fields carry the denial reason, not tool output.

## Disambiguation requirement (read carefully — Slice 2.5 surfaced this as the dominant failure class)

Before classifying any mechanism as `attacker_persistence`, you MUST rule out benign explanations. A mechanism is NOT attacker persistence if it is:

  **(a) A DFIR / incident-response tool installed by responders.** Ask: does the name, path, or command line match a known forensics product? Examples of DFIR tool signatures (non-exhaustive):
    - F-Response      (`subject_srv.exe`; connects to `*-hunt.*` or `*-examiner.*` hosts on high non-standard ports)
    - Mnemosyne       (`Mnemosyne.sys` kernel driver — memory acquisition)
    - Volatility / `vol.py` (memory analysis)
    - KAPE            (`kape.exe`; Targets/Modules structure)
    - Velociraptor    (`velociraptor.exe`; endpoint agent)
    - Magnet AXIOM, MemProcFS, WinPMEM, DumpIt, FTK Imager, Redline, CyLR, Kansa
    - Sysmon / SysmonDrv — legitimate by default, but note that attackers occasionally install Sysmon for their own monitoring; flag the unusual case rather than auto-exonerate.

  **(b) A commercial security or IT product.** McAfee (`mfe*`, `McAfeeFramework`, `McShield`, `enterceptAgent`, `HipMgmt`, `HipShieldK`), CrowdStrike, SentinelOne, Symantec, Trend Micro, VMware guest tools (`VMTools`, `VGAuthService`, `VMMemCtl`, `vmware-*`), VirtualBox guest, Microsoft Defender (`WinDefend`, `MpsSvc`, `WdNisSvc`), Windows Update (`wuauserv`), `AdobeARMservice`, GoogleUpdate (`gupdate` / `gupdatem`), `MozillaMaintenance`.

  **(c) A Windows default or a legitimate vendor driver.** Perf* services (`PerfDisk`, `PerfHost`, `PerfNet`, `PerfOS`, `PerfProc`), RPC family (`RpcEptMapper`, `RpcSs`, `DcomLaunch`), TCP/IP stack (`Tcpip`, `NetBT`, `NetBIOS`), kernel drivers for storage / input / USB / virtual hardware (`atapi`, `usbhub`, `i8042prt`, `vmbus`, `storvsc`, etc.), `.NET`/`ASP.NET` service family, clr_optimization_*, `aspnet_state`.

**Masquerading counter-rule:** if a name mimics a Windows built-in but the binary/path is NOT the standard one (e.g., a service named "PerfMon" running `perfmonsvc64.exe` when the legitimate Windows perf services are `PerfDisk`, `PerfHost`, `PerfNet`, `PerfOS`, `PerfProc`), that is **evidence of masquerading** and overrides the "looks like Windows default" heuristic. Classify as `attacker_persistence` with notes explaining the name/path mismatch.

**For every `attacker_persistence` finding at `high` confidence, `notes` MUST contain the benign hypotheses you considered and ruled out** — even briefly. Example: "Ruled out DFIR tools (not a known responder product), vendor products (not in McAfee/VMware/Defender path conventions), Windows defaults (not among Perf*/RPC/TCP-IP service families). Binary path under C:\\windows\\ with non-Microsoft name and C2-like outbound connection pattern."

## Output

Emit exactly:

```json
{
  "findings": [
    {
      "category": "<PersistenceCategory literal>",
      "mechanism": "<short human label, e.g. 'HKLM Run key', 'Windows service auto-start'>",
      "value": "<the suspicious path/command/value string>",
      "confidence": "low|medium|high",
      "classification": "attacker_persistence|legitimate_responder_tool|legitimate_vendor_product|legitimate_windows_default|requires_disambiguation",
      "evidence": [
        {"tool_call_id": "<from bundle>", "output_excerpt": "<literal substring of that step's structured_fields JSON>"}
      ],
      "notes": "<for attacker_persistence: which benign hypotheses you ruled out; for requires_disambiguation: what unresolved alternatives remain>"
    }
  ]
}
```

`category` must be one of: `registry_run_key`, `service`, `scheduled_task`, `ifeo_debugger`, `appinit_dll`, `logon_script`, `NOT_FOUND`.

`classification` must be one of the five values listed in Hard Rule 3. DO NOT emit `legitimate_responder_tool`, `legitimate_vendor_product`, or `legitimate_windows_default` findings unless you are compiling an inventory — those are suppressed, not reported. The exception is the single `NOT_FOUND` finding (Hard Rule 4) which uses `classification="legitimate_windows_default"`.
"""


def _build_interpret_bundle(state: "PipelineState") -> dict:
    """Construct the LLM-facing bundle from state. Pure function — no LLM
    call — so probes can test bundle shape + content without hitting the API.

    Positional correlation between `state.evidence[i]` and
    `state.tool_plan.steps[i]`: execute_node iterates the plan in topological
    order and halts on first failure, so state.evidence is a prefix of the
    plan's step sequence. If the two lengths ever diverged under a future
    parallel/out-of-order executor, this would need a tool_call_id → step_id
    side-car; for Slice 5 the linear executor makes the positional shortcut
    unambiguous.
    """
    if state.tool_plan is None:
        raise RuntimeError("state.tool_plan is None — interpret_node needs an approved plan")
    if not state.evidence:
        raise RuntimeError("state.evidence is empty — run execute_node first")

    case_id = _require("CASE_ID", CASE_ID)
    plan_steps = state.tool_plan.steps
    bundle_steps = []
    for i, ev in enumerate(state.evidence):
        if i >= len(plan_steps):
            raise RuntimeError(
                f"state.evidence has {len(state.evidence)} entries but "
                f"tool_plan.steps has {len(plan_steps)} — positional correlation broken"
            )
        plan_step = plan_steps[i]
        bundle_steps.append({
            "step_id": plan_step.step_id,
            "tool_call_id": ev.tool_call_id,
            "tool": plan_step.tool,
            "purpose": plan_step.purpose,
            "args": plan_step.args,
            "tool_execution_status": ev.tool_execution_status,
            "expected_paths_covered": ev.expected_paths_covered,
            "structured_fields": ev.structured_fields,
        })

    return {
        "question": state.tool_plan.question,
        "case_id": case_id,
        "steps": bundle_steps,
    }


def interpret_node(state: "PipelineState") -> dict:
    """Turn structured_fields into Findings. Writes `out/findings.json` +
    `out/findings.SUCCESS` for audit-trail continuity.

    Model input under Slice 5: the bundle's `structured_fields` (channel B).
    Raw stdout is never in the model's context. `plan_digest` is read from
    state (populated by plan_node) rather than re-hashed from disk as C9 did.
    """
    client = _require("LLM_CLIENT", LLM_CLIENT)
    langfuse = _require("LANGFUSE", LANGFUSE)
    model = _require("INTERPRET_MODEL", INTERPRET_MODEL)
    case_id = _require("CASE_ID", CASE_ID)
    from langfuse import propagate_attributes

    plan_digest = state.plan_digest
    if plan_digest is None:
        raise RuntimeError("state.plan_digest is None — plan_node must populate it")

    bundle = _build_interpret_bundle(state)
    started_at = datetime.now(timezone.utc)

    with propagate_attributes(
        session_id=state.run_id,
        user_id=case_id,
        tags=["phase:interpret"],
        metadata={"phase": "interpret", "n_steps": len(state.evidence)},
    ):
        with langfuse.start_as_current_observation(
            name="interpret", as_type="span"
        ) as interpret_span:
            messages = [
                {"role": "system", "content": [
                    {"type": "text", "text": INTERPRET_SYSTEM_PROMPT,
                     "cache_control": {"type": "ephemeral"}},
                ]},
            ]
            if state.corrective_instruction:
                messages.append({
                    "role": "system",
                    "content": f"CRITIC CORRECTION (retry pass)\n\n{state.corrective_instruction}",
                })
            messages.append({"role": "user", "content": json.dumps(bundle, indent=2)})

            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                response_format={"type": "json_object"},
                max_tokens=8000,
            )
            raw = resp.choices[0].message.content
            s = raw.strip()
            if s.startswith("```"):
                s = re.sub(r"^```(?:json|JSON)?\s*", "", s)
                s = re.sub(r"\s*```\s*$", "", s)
            parsed = json.loads(s)

            # Individual Finding validation — a missing `classification` field
            # is caught here (required post-Step-0). Once Slice 3 Critic R_11
            # is wired to INTERPRET retries, pre-commit failure softens to a
            # soft retry; the Pydantic validator still runs but its miss
            # triggers a re_interpret rather than a hard raise.
            finding_objs = [
                Finding.model_validate(f) for f in parsed.get("findings", [])
            ]
            finished_at = datetime.now(timezone.utc)

            findings = Findings(
                case_id=case_id,
                question=state.tool_plan.question,
                findings=finding_objs,
                plan_digest=plan_digest,
                started_at=started_at,
                finished_at=finished_at,
            )

            # Soft-warn on dangling tool_call_ids — Critic's R_01 is the real
            # enforcer; we just surface obvious data issues early.
            valid_ids = {ev.tool_call_id for ev in state.evidence}
            dangling = [
                (i, e.tool_call_id)
                for i, f in enumerate(findings.findings)
                for e in f.evidence
                if e.tool_call_id not in valid_ids
            ]
            if dangling:
                print(
                    f"WARN: {len(dangling)} evidence entries reference unknown "
                    f"tool_call_ids — {dangling[:3]}"
                )

            interpret_span.update(
                output=findings.model_dump(mode="json"),
                metadata={
                    "n_findings": len(findings.findings),
                    "n_high_confidence": sum(1 for f in findings.findings if f.confidence == "high"),
                    "n_attacker_persistence": sum(
                        1 for f in findings.findings if f.classification == "attacker_persistence"
                    ),
                    "n_requires_disambiguation": sum(
                        1 for f in findings.findings if f.classification == "requires_disambiguation"
                    ),
                    "plan_digest_short": plan_digest[:16],
                },
            )

    (OUT_DIR / "findings.json").write_text(
        findings.model_dump_json(indent=2), encoding="utf-8"
    )
    (OUT_DIR / "findings.SUCCESS").touch()
    langfuse.flush()

    return {"findings": findings}


# ============================================================================
# CRITIC — real implementation (lifted from notebook C4, adapted to the
# Slice-5 EvidenceRecord CriticContext shape).
# ============================================================================

def _append_critic_disagreement(
    disagreements_path: Path,
    *,
    plan_digest: str,
    iteration: int,
    original_finding: Finding,
    critique,        # CritiqueResult — typed loosely to avoid forward-ref
    resolution: dict,
    cost_so_far: dict,
) -> None:
    """Append one JSONL line per Critic disagreement. Moved from notebook C13
    at Step 7c. I/O-only — the pure `build_resolution` + `build_new_instruction`
    logic lives in `pipeline.critic`. Caller skips the pass-severity case; we
    don't write a no-op entry.

    `resolution` shape (from critic.build_resolution):
      {action: commit|retry|escalate, strategy: None|re_interpret|re_plan|human_review,
       new_instruction: str|None}

    `cost_so_far` shape:
      {input_tokens: int, output_tokens: int, usd_estimate: float|None}

    Write errors are intentionally NOT swallowed — an unwritable audit log is
    a forensic-integrity failure; fail loudly so the pipeline halts.
    """
    event = CriticDisagreement(
        plan_digest=plan_digest,
        iteration=iteration,
        original_finding=original_finding,
        critic_critique=critique,
        resolution=resolution,
        cost_so_far=cost_so_far,
        timestamp_utc=datetime.now(timezone.utc),
    )
    disagreements_path.parent.mkdir(parents=True, exist_ok=True)
    with disagreements_path.open("a", encoding="utf-8") as fh:
        fh.write(event.model_dump_json() + "\n")


def critic_node(state: "PipelineState") -> dict:
    """Run the deterministic Critic rules on every Finding, write audit entries
    for disagreements, update retry-loop state.

    Slice 5 adaptations (from C4's version):
      - CriticContext takes `state.evidence` (list[EvidenceRecord]) instead of
        `state.raw_results` (list[RawResult]).
      - plan_digest is read from `state.plan_digest` (populated by plan_node)
        rather than `state.findings.plan_digest` — both are present post-
        interpret, but state.plan_digest is the authoritative binding to the
        capability token and is available one node earlier.
      - Phase C L3 primitive (plan-hash dedup): unchanged; `_plan_hash` now
        lives in `pipeline.graph` as `plan_hash` and is the canonical
        compute_plan_digest form (same hash space as the token binding).

    Returns the standard Critic delta:
      `critique_results`, `iteration+1`, `attempts_per_finding`,
      `corrective_instruction`, `failed_plan_hashes`.

    Returns `{}` if upstream state is incomplete (stub-only / partial run) —
    matches C4's guard so the debounce smoke-run at graph compile time
    doesn't raise.
    """
    # Local imports mirror the critic.py location of its exports
    from pipeline.critic import (
        CriticContext,
        critic_evaluate,
        build_resolution,
    )
    from pipeline.graph import plan_hash

    if state.findings is None or state.tool_plan is None or not state.evidence:
        return {}

    current_hash = plan_hash(state.tool_plan)
    plan_already_failed = current_hash in state.failed_plan_hashes

    ctx = CriticContext(state.tool_plan, state.evidence)
    results = [
        critic_evaluate(f, ctx, i)
        for i, f in enumerate(state.findings.findings)
    ]

    if plan_already_failed:
        # L3 primitive: the LLM has produced this exact plan at least once
        # already; retrying would loop. Force any non-pass severity to
        # escalate so control transfers to human_review.
        for r in results:
            if r.severity != "pass":
                r.severity = "escalate"

    # Per-finding retry counter (for the per-finding budget gate in critic_edge)
    attempts = dict(state.attempts_per_finding)
    for r in results:
        if r.severity == "retry":
            attempts[r.finding_index] = attempts.get(r.finding_index, 0) + 1

    # Audit-log writer + corrective-instruction collector
    corrective_bits: list[str] = []
    audit_path = OUT_DIR / "critic_disagreements.jsonl"
    plan_digest = state.plan_digest or "sha256:unknown"
    for r in results:
        if r.severity == "pass":
            continue
        finding = state.findings.findings[r.finding_index]
        resolution = build_resolution(r, finding, ctx)
        _append_critic_disagreement(
            audit_path,
            plan_digest=plan_digest,
            iteration=state.iteration,
            original_finding=finding,
            critique=r,
            resolution=resolution,
            cost_so_far={"input_tokens": 0, "output_tokens": 0, "usd_estimate": None},
        )
        if resolution.get("new_instruction"):
            corrective_bits.append(resolution["new_instruction"])

    # Record the current plan's hash so future cycles detect re-emission
    new_failed = list(state.failed_plan_hashes)
    if any(r.severity != "pass" for r in results) and current_hash not in new_failed:
        new_failed.append(current_hash)

    return {
        "critique_results": results,
        "iteration": state.iteration + 1,
        "attempts_per_finding": attempts,
        "corrective_instruction": "\n\n".join(corrective_bits) if corrective_bits else None,
        "failed_plan_hashes": new_failed,
    }


# ============================================================================
# Debounce + human_review — straight lifts from Phase C
# ============================================================================

def _debounce_log(state: "PipelineState", target: str) -> None:
    retries = {k: v for k, v in state.attempts_per_finding.items() if v > 0}
    print(
        f"  [debounce/{target}] iteration={state.iteration}  "
        f"tokens_used={state.tokens_used}  attempts_so_far={retries or '{}'}"
    )


def debounce_before_plan(state: "PipelineState") -> dict:
    """Observability-only in Phase C (see Slice-3-runbook decision notes).
    Slice 5 adds real state-trimming when EvidenceRecord's raw bytes start
    flowing through state — the Step-7b execute_node lift is that trigger."""
    _debounce_log(state, "plan")
    return {}


def debounce_before_interpret(state: "PipelineState") -> dict:
    _debounce_log(state, "interpret")
    return {}


def human_review_node(state: "PipelineState") -> dict:
    """Terminal node for escalated findings. In production this would block
    commit of findings.json and surface the disagreement log to a reviewer.
    Stub for now: prints a warning."""
    print("  [human_review] ESCALATED — findings.json hold pending human review")
    return {}


__all__ = [
    # Config (module-level; notebook assigns to these)
    "LLM_CLIENT", "LANGFUSE", "PLAN_MODEL", "INTERPRET_MODEL",
    "CASE_ID", "E01_PATH", "OUT_DIR",
    # Helpers
    "PLACEHOLDER_RE", "KNOWN_EXTRACTORS",
    # Nodes
    "extract_node",
    "plan_node",
    "execute_node",
    "interpret_node",
    "critic_node",
    "debounce_before_plan",
    "debounce_before_interpret",
    "human_review_node",
]
