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
import re
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from pipeline.schemas import ToolPlan

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
        plan_bytes = tool_plan.model_dump_json(indent=2).encode("utf-8")
        out_path.write_bytes(plan_bytes)

        # plan_digest locks the approved plan to every downstream MCP call via
        # the capability-token binding. sha256 of the pretty-printed JSON
        # matches what C9 used to compute inline — preserves regression-gate
        # parity against pre-Slice-5 findings.json digests.
        import hashlib
        plan_digest = hashlib.sha256(plan_bytes).hexdigest()

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
# EXECUTE — stub until Step 7b
# ============================================================================

def execute_node(state: "PipelineState") -> dict:
    """Stub pending Step 7b. Real body consumes the approved tool_plan +
    capability_token, runs every step via streamable-HTTP MCP, collects
    EvidenceRecord instances, and returns `{"evidence": [...]}`.
    """
    raise NotImplementedError(
        "execute_node — lands in Slice 5 Step 7b (see slice-5-runbook.md §Step 7a). "
        "Until then, the notebook's C8 cell runs this phase inline."
    )


# ============================================================================
# INTERPRET — stub until Step 7b
# ============================================================================

def interpret_node(state: "PipelineState") -> dict:
    """Stub pending Step 7b. Real body builds the INTERPRET bundle from
    `state.evidence[*].structured_fields` ONLY (channel B) — raw stdout is
    never surfaced to the LLM under the Slice-5 dual-channel boundary."""
    raise NotImplementedError(
        "interpret_node — lands in Slice 5 Step 7b. Until then, the notebook's "
        "C9 cell runs this phase inline."
    )


# ============================================================================
# CRITIC — stub until Step 7c (requires pipeline/critic.py EvidenceRecord adaptation)
# ============================================================================

def critic_node(state: "PipelineState") -> dict:
    """Stub pending Step 7c. Real body constructs a CriticContext from
    (state.tool_plan, state.evidence), runs the 13 rules, updates
    failed_plan_hashes + attempts_per_finding + corrective_instruction.
    """
    raise NotImplementedError(
        "critic_node — lands in Slice 5 Step 7c (critic rules must first be "
        "adapted to EvidenceRecord). Until then, the notebook's C4/C10–C13 "
        "cells run Critic inline."
    )


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
