"""Per-run output filenames, numbered by pipeline phase.

Filenames are prefixed `NN_<phase>_…` so a directory listing sorts by the
order the phase produced the artifact:

    01_extract_candidates.json          EXTRACT  → Candidates
    02_plan_tool_plan.json              PLAN     → ToolPlan
    03_approve.SUCCESS                  APPROVE  → token issued sentinel
    04_execute_evidence.jsonl           EXECUTE  → EvidenceRecord per line
    05_interpret_findings.json          INTERPRET → Findings
    06_critic_disagreements.jsonl       CRITIC   → audit-log disagreements
    07_terminal.SUCCESS / .HUMAN_REVIEW / .QUARANTINED   terminal marker
    integrity_ledger.jsonl              cross-cutting (every phase appends)

Centralizing the names here keeps writers (pipeline/nodes.py, run_case.py,
demos) and readers (score.py) in lockstep on a single source of truth.
"""
from __future__ import annotations

# ---- Per-phase output files ------------------------------------------------
EXTRACT_CANDIDATES         = "01_extract_candidates.json"
PLAN_TOOL_PLAN             = "02_plan_tool_plan.json"
APPROVE_SENTINEL           = "03_approve.SUCCESS"
EXECUTE_EVIDENCE_JSONL     = "04_execute_evidence.jsonl"
INTERPRET_FINDINGS         = "05_interpret_findings.json"
CRITIC_DISAGREEMENTS_JSONL = "06_critic_disagreements.jsonl"

# ---- Terminal markers (one of three) --------------------------------------
TERMINAL_SUCCESS      = "07_terminal.SUCCESS"
TERMINAL_HUMAN_REVIEW = "07_terminal.HUMAN_REVIEW"
TERMINAL_QUARANTINED  = "07_terminal.QUARANTINED"

# ---- Cross-cutting ---------------------------------------------------------
INTEGRITY_LEDGER_JSONL = "integrity_ledger.jsonl"


def terminal_marker_for(decision: str | None) -> str:
    """Map a graph terminal-state to its sentinel filename.

    `decision` is `None` on the commit path (graph went straight to END),
    `"escalated"` on regular human_review escalations, and `"quarantined"`
    when human_review_node sees a quarantine-severity injection flag.
    """
    if decision == "quarantined":
        return TERMINAL_QUARANTINED
    if decision == "escalated":
        return TERMINAL_HUMAN_REVIEW
    return TERMINAL_SUCCESS


__all__ = [
    "EXTRACT_CANDIDATES",
    "PLAN_TOOL_PLAN",
    "APPROVE_SENTINEL",
    "EXECUTE_EVIDENCE_JSONL",
    "INTERPRET_FINDINGS",
    "CRITIC_DISAGREEMENTS_JSONL",
    "TERMINAL_SUCCESS",
    "TERMINAL_HUMAN_REVIEW",
    "TERMINAL_QUARANTINED",
    "INTEGRITY_LEDGER_JSONL",
    "terminal_marker_for",
]
