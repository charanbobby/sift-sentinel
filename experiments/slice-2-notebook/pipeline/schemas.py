"""Pipeline schemas — Pydantic contracts shared across every phase.

Single home for type definitions used by EXTRACT, PLAN, EXECUTE, INTERPRET, and
CRITIC, plus the Slice-5 capability-token / dual-channel-evidence / injection-flag
shapes used by the MCP server-side modules.

Not included here, by design:
  - `PipelineState` — lives in `pipeline/graph.py` (LangGraph runtime, not shared data).
  - `CriticContext` — lives in `pipeline/critic.py` (ephemeral per-invocation context).
"""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, model_validator


Confidence = Literal["low", "medium", "high"]

PersistenceCategory = Literal[
    "registry_run_key", "service", "scheduled_task",
    "ifeo_debugger", "appinit_dll", "logon_script",
    "NOT_FOUND",
]

# Classification — added 2026-04-19 post-Slice-2.5 for R_11 Critic rule.
# Forces INTERPRET to declare what KIND of thing a finding is, not just whether
# it looks suspicious. Catches the responder-tool FP class (F-Response,
# Mnemosyne) that Slice 2.5 surfaced as the dominant Generation-layer failure.
# See docs/runbooks/slice-3-runbook.md Step 0 for rationale.
Classification = Literal[
    "attacker_persistence",        # confidently malicious
    "legitimate_responder_tool",   # DFIR/IR tool installed during response
    "legitimate_vendor_product",   # commercial security/IT product
    "legitimate_windows_default",  # stock Windows component or driver (also used for NOT_FOUND)
    "requires_disambiguation",     # signals suggest malicious but cannot rule out benign
]

# ---- ATT&CK mapping (added 2026-04-19) ----
# Every PersistenceCategory maps 1:1 onto an official MITRE ATT&CK sub-technique
# under TA0003 (Persistence). Source of truth: attack.mitre.org. The LLM emits
# `category`; the Finding validator below derives the T-code deterministically
# — we never trust the model to set attack_id itself.
ATTACK_MAPPING: dict[str, tuple[str | None, str | None]] = {
    "registry_run_key": ("T1547.001", "Registry Run Keys / Startup Folder"),
    "service":          ("T1543.003", "Windows Service"),
    "scheduled_task":   ("T1053.005", "Scheduled Task"),
    "ifeo_debugger":    ("T1546.012", "Image File Execution Options Injection"),
    "appinit_dll":      ("T1546.010", "AppInit DLLs"),
    "logon_script":     ("T1037.001", "Logon Script"),
    "NOT_FOUND":        (None, None),
}
ATTACK_TACTIC_ID = "TA0003"
ATTACK_TACTIC_NAME = "Persistence"

# ---- Phase 1 — EXTRACT output ----
class ArtifactCandidate(BaseModel):
    artifact_type: Literal["registry_hive", "scheduled_task_xml", "service_config"]
    path_hint: str
    reason: str
    priority: Literal[1, 2, 3]

class Candidates(BaseModel):
    question: str
    candidates: list[ArtifactCandidate]

# ---- Phase 2 — PLAN output ----
class PlannedStep(BaseModel):
    step_id: int
    # `scheduled_tasks_parse` added Slice 5 Step 6 as the 5th MCP tool —
    # chains icat + XML parse internally so PLAN can advertise T1053.005
    # coverage in one step without orchestrator-side chaining.
    tool: Literal[
        "fsstat_e01", "fls_list", "icat_extract",
        "regripper_run", "scheduled_tasks_parse",
    ]
    args: dict
    purpose: str
    depends_on: list[int]
    confidence: Confidence

class ToolPlan(BaseModel):
    question: str
    steps: list[PlannedStep]
    expected_findings_range: tuple[int, int]

# ---- Phase 3 — EXECUTE output (JSONL, one line per step) ----
class RawResult(BaseModel):
    step_id: int
    tool_call_id: str
    tool: str
    args: dict
    exit_code: int
    stdout_excerpt: str
    stdout_path: str
    duration_ms: int

# ---- Phase 4 — INTERPRET output ----
class Evidence(BaseModel):
    tool_call_id: str
    output_excerpt: str

class Finding(BaseModel):
    category: PersistenceCategory
    mechanism: str
    value: str
    confidence: Confidence
    classification: Classification  # R_11 gate — required; no default forces model to commit
    evidence: list[Evidence]
    notes: str = ""
    # ATT&CK fields — derived from `category` by the validator below. Included
    # in serialized output so findings.json speaks the judges' language (T-codes
    # under TA0003). LLM output for these is IGNORED; category is the only input.
    attack_id: str | None = None
    attack_name: str | None = None
    attack_tactic_id: str = ATTACK_TACTIC_ID
    attack_tactic_name: str = ATTACK_TACTIC_NAME

    @model_validator(mode="after")
    def _tag_attack(self):
        aid, aname = ATTACK_MAPPING.get(self.category, (None, None))
        self.attack_id = aid
        self.attack_name = aname
        return self

class Findings(BaseModel):
    case_id: str
    question: str
    findings: list[Finding]
    plan_digest: str
    started_at: datetime
    finished_at: datetime

# ---- Phase 5 — CRITIC schema types (added 2026-04-19, slice-3-runbook Step 1) ----
RuleId = Literal[
    'R_01', 'R_02', 'R_03', 'R_04', 'R_05',
    'R_06', 'R_07', 'R_08', 'R_09', 'R_10',
    'R_11',  # Classification — added 2026-04-19 post-2.5
    'R_12',  # Evidence-of-Absence — added 2026-04-20 Phase C
    'R_13',  # Temporal Consistency — added 2026-04-20 Phase C (stub; real impl in Slice 5)
]
FailureCode = Literal[
    'EVID_UNRESOLVED', 'PATH_INCONSISTENCY', 'TOOL_MISMATCH',
    'INVALID_REG_PATH', 'EXCERPT_HALLUCINATION', 'SCOPE_INCOMPLETE',
    'EMPTY_FINDING_DATA', 'CONF_OVERSTATED', 'EVIDENCE_TOOL_EXIT_NONZERO',
    'INJECTION_FLAGGED_EVIDENCE',  # warn-severity injection flag on cited evidence
    'INJECTION_QUARANTINE',        # quarantine-severity flag → mandatory escalate (Step 8)
    'CLASSIFICATION_MISSING',      # R_11 — finding missing required classification field or rationale
    'ABSENCE_UNSUBSTANTIATED',     # R_12 — any tool in the run failed + claim is NOT_FOUND@high
    'TEMPORAL_INCONSISTENT',       # R_13 — claimed timestamp not grounded in cited stdout (stub pre-Slice-5)
]

class RuleFailure(BaseModel):
    rule_id: RuleId
    code: FailureCode
    detail: str  # one sentence — what specifically failed

class CritiqueResult(BaseModel):
    finding_index: int
    rules_passed: list[RuleId]
    rules_failed: list[RuleFailure]
    is_llm_judgment: bool = False  # True only if LLM-fallback was invoked (deferred to Slice 3.5)
    severity: Literal['pass', 'retry', 'escalate']

class CriticDisagreement(BaseModel):
    audit_event: Literal['critic_disagreement'] = 'critic_disagreement'
    plan_digest: str
    iteration: int  # 1..N within this finding's retry budget
    original_finding: Finding
    critic_critique: CritiqueResult
    resolution: dict  # {action, strategy, new_instruction}
    cost_so_far: dict  # {input_tokens, output_tokens, usd_estimate|null}
    timestamp_utc: datetime


# ============================================================================
# Slice 5 Step 2 additions — capability tokens, dual-channel evidence records,
# injection flags, and per-tool structured-field shapes (channel B of the
# dual-channel handler). Declared here; Steps 3/4/5/6 populate their runtime
# uses. No behavior lives in these types — they are shape contracts only.
# ============================================================================

# ---- Capability tokens (Slice 5 Step 3) ----
class CapabilityToken(BaseModel):
    """Per-plan least-privilege scope issued by the orchestrator after human
    approval and verified by the MCP server on every tool call. HMAC-SHA256 over
    the canonical serialization; the shared key lives in the container env.
    """
    token_id: str                      # uuid4 for audit-trail correlation
    case_id: str
    allowed_tools: frozenset[str]      # subset of exposed MCP tool names
    allowed_paths: tuple[str, ...]     # canonical path prefixes; order-sensitive
    plan_digest: str                   # sha256 of the approved ToolPlan — binds the token to the reviewed plan
    expires_at: datetime               # short window (~30 min typical)
    signature: str = Field(..., min_length=64, max_length=64)  # hex-encoded HMAC-SHA256


# ---- Injection flags (Slice 5 Step 5) ----
class InjectionFlag(BaseModel):
    """Pattern-match hit from the injection scanner. Attached to an
    EvidenceRecord so downstream handling can decide whether to quarantine the
    record from the agent context (severity='quarantine') or just record the
    signal for audit (severity='info' / 'warn').
    """
    pattern_id: str                    # e.g. "INJ_IMPERATIVE_IGNORE", "INJ_ATTCK_EMIT"
    excerpt: str = Field(..., max_length=128)  # audit-log locator; scanner must truncate before this
    field_path: str                    # free-form locator into structured_fields, e.g. "entries[3].value_data_safe"
    severity: Literal["info", "warn", "quarantine"]


# ---- Evidence record (Slice 5 Step 6) ----
# `capability_denied` added Slice 5 Step 6 — a denied call never runs the
# subprocess, so the existing subprocess-level statuses (timeout /
# permission_denied / parse_error) would be semantically wrong. The denial
# EvidenceRecord carries the full reason under structured_fields so Critic
# can see WHY without ambiguity.
ToolExecutionStatus = Literal[
    "ok", "timeout", "permission_denied", "parse_error", "empty",
    "capability_denied",
]


class EvidenceRecord(BaseModel):
    """Replaces ToolResult as the MCP server's return shape. Two channels:
      A) raw bytes preserved immutably (raw_sha256 + raw_path on disk)
      B) structured fields parsed server-side and handed to the LLM
    The LLM never sees raw stdout under Slice 5+ — only structured_fields.
    """
    tool_call_id: str
    raw_sha256: str = Field(..., min_length=64, max_length=64)
    raw_path: str                      # absolute path inside sift-mcp; for Slice 6 integrity-ledger replay
    # structured_fields — shape is per-tool; see FsstatResult / FlsResult / etc.
    # Must be JSON-safe at construction time (call `result.model_dump(mode="json")`
    # when nesting a per-tool Result into this dict). The outer `dict` type has
    # no Pydantic validator to re-hydrate nested datetimes on parse, so passing
    # a Python-native dict with datetime values breaks JSON round-trip equality.
    structured_fields: dict
    injection_flags: list[InjectionFlag] = Field(default_factory=list)
    expected_paths_covered: list[str] = Field(default_factory=list)  # feeds R_06 Negative-Result-Metadata
    tool_execution_status: ToolExecutionStatus                        # feeds R_12 Evidence-of-Absence
    issued_at: datetime
    token_id: str                      # audit-link to the CapabilityToken that authorized this call


# ---- Per-tool structured-field shapes (Slice 5 Step 6, channel B) ----
class FsstatResult(BaseModel):
    fs_type: str                       # e.g. "NTFS"
    block_size: int
    mft_offset: int | None = None      # NTFS-only
    volume_serial: str | None = None
    partition_count: int = 1
    install_time: datetime | None = None  # for R_13 Temporal Consistency


class FlsEntry(BaseModel):
    inode: int
    entry_type: Literal["file", "directory", "symlink", "other"]
    size: int
    mtime: datetime | None = None
    atime: datetime | None = None
    ctime: datetime | None = None
    crtime: datetime | None = None
    filename_safe: str                 # adversarial filename bytes replaced with <NON_PRINTABLE>; inode+size preserved so Plan can still chain


class FlsResult(BaseModel):
    entries: list[FlsEntry]


class IcatResult(BaseModel):
    dest_path: str                     # absolute path under <case>/analysis/extracted/
    bytes_written: int
    sha256: str = Field(..., min_length=64, max_length=64)  # of extracted bytes
    magic_bytes: str                   # first 16 bytes as hex


class RegripperEntry(BaseModel):
    key_path: str
    value_name: str
    value_type: str                    # REG_SZ, REG_DWORD, etc.
    value_data_safe: str               # parsed; free-text portions scanner-checked
    last_write: datetime | None = None  # for R_13 Temporal Consistency


class RegripperResult(BaseModel):
    plugin_name: str
    hive_type: str                     # Software | System | NTUSER.DAT
    entries: list[RegripperEntry]


class ScheduledTaskEntry(BaseModel):
    task_name: str
    author_safe: str = ""
    description_safe: str = ""
    trigger_type: str                  # LogonTrigger | TimeTrigger | BootTrigger | ... | Unknown
    action_command_safe: str
    action_arguments_safe: str = ""
    enabled: bool = True
    last_run_time: datetime | None = None
    next_run_time: datetime | None = None


class ScheduledTasksResult(BaseModel):
    tasks: list[ScheduledTaskEntry]


__all__ = [
    # Literals
    "Confidence", "PersistenceCategory", "Classification", "RuleId", "FailureCode",
    "ToolExecutionStatus",
    # ATT&CK
    "ATTACK_MAPPING", "ATTACK_TACTIC_ID", "ATTACK_TACTIC_NAME",
    # Phase 1
    "ArtifactCandidate", "Candidates",
    # Phase 2
    "PlannedStep", "ToolPlan",
    # Phase 3
    "RawResult",
    # Phase 4
    "Evidence", "Finding", "Findings",
    # Phase 5 (CRITIC)
    "RuleFailure", "CritiqueResult", "CriticDisagreement",
    # Slice 5 Step 2 — capability tokens, dual-channel evidence, injection flags
    "CapabilityToken", "InjectionFlag", "EvidenceRecord",
    # Slice 5 Step 2 — per-tool structured-field shapes (channel B)
    "FsstatResult",
    "FlsEntry", "FlsResult",
    "IcatResult",
    "RegripperEntry", "RegripperResult",
    "ScheduledTaskEntry", "ScheduledTasksResult",
]
