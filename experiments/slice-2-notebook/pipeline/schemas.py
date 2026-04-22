"""Pipeline schemas — Pydantic contracts shared across every phase.

Single home for type definitions used by EXTRACT, PLAN, EXECUTE, INTERPRET, and
CRITIC. Extracted from slice2.ipynb C2 at Slice 5 Step 1 (dependency-leaf first).

Not included here, by design:
  - `PipelineState` — lives in `pipeline/graph.py` (LangGraph runtime, not shared data).
  - `CriticContext`  — lives in `pipeline/critic.py` (ephemeral per-invocation context).
  - Slice-5 types (`CapabilityToken`, `EvidenceRecord`, `InjectionFlag`, and the
    structured-field types `FsstatResult`, `FlsEntry`, `IcatResult`,
    `RegripperResult`, `ScheduledTasksResult`) — land here during Slice 5 Step 2.
"""
from datetime import datetime, timezone
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
    tool: Literal["fsstat_e01", "fls_list", "icat_extract", "regripper_run"]
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
    'INJECTION_FLAGGED_EVIDENCE',
    'CLASSIFICATION_MISSING',  # R_11 — finding missing required classification field or rationale
    'ABSENCE_UNSUBSTANTIATED', # R_12 — any tool in the run failed + claim is NOT_FOUND@high
    'TEMPORAL_INCONSISTENT',   # R_13 — claimed timestamp not grounded in cited stdout (stub pre-Slice-5)
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


__all__ = [
    # Literals
    "Confidence", "PersistenceCategory", "Classification", "RuleId", "FailureCode",
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
]
