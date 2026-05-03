"""Re-run INTERPRET on a QUARANTINED run after human approval.

Background. The pipeline strips structured_fields for any evidence record whose
injection_flags include severity=="quarantine", then marks the run terminal as
QUARANTINED. When the quarantine is a false positive (e.g. raw SOFTWARE hive
bytes containing the literal MITRE token "T1033" tripping INJ_ATTCK_EMIT), the
LLM never gets to analyze that evidence and may miss persistence findings on
that channel.

This script reads a quarantined run dir, sets HUMAN_APPROVED_QUARANTINE_OVERRIDE=1,
re-builds the bundle with the previously-stripped evidence restored, calls the
LLM once for a fresh INTERPRET, and writes the new findings to a sibling file
(05b_interpret_findings_post_approval.json) so the original 07_terminal.QUARANTINED
audit trail is preserved.

Usage (inside sift-sentinel container):
    docker exec sift-sentinel /workspace/.venv/bin/python /workspace/scripts/rescan_after_approval.py \\
        --run-dir /workspace/out/runs/srl-2018-base-rd-02-dual/srl-2018-base-rd-02-dual-001
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, "/workspace")

from langfuse import Langfuse
from langfuse.openai import OpenAI as LangfuseOpenAI

import pipeline.nodes as _nodes
from pipeline.graph import PipelineState, mint_canary
from pipeline.schemas import (
    Candidates,
    EvidenceRecord,
    ToolPlan,
    CapabilityToken,
)
from pipeline.mcp.tokens import compute_plan_digest
from pipeline.output_layout import (
    EXTRACT_CANDIDATES,
    PLAN_TOOL_PLAN,
    EXECUTE_EVIDENCE_JSONL,
    INTERPRET_FINDINGS,
)


def _case_id_from_run_dir(run_dir: Path) -> str:
    """run_dir is .../out/runs/<case_id>/<run_id>. Parent dir name is case_id."""
    return run_dir.parent.name


def _load_state(run_dir: Path) -> PipelineState:
    case_id = _case_id_from_run_dir(run_dir)
    cands_path = run_dir / EXTRACT_CANDIDATES
    plan_path = run_dir / PLAN_TOOL_PLAN
    evidence_path = run_dir / EXECUTE_EVIDENCE_JSONL

    if not cands_path.exists():
        raise FileNotFoundError(f"missing {cands_path}")
    if not plan_path.exists():
        raise FileNotFoundError(f"missing {plan_path}")
    if not evidence_path.exists():
        raise FileNotFoundError(f"missing {evidence_path}")

    candidates = Candidates.model_validate_json(cands_path.read_text(encoding="utf-8"))
    tool_plan = ToolPlan.model_validate_json(plan_path.read_text(encoding="utf-8"))
    evidence: list[EvidenceRecord] = []
    with evidence_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                evidence.append(EvidenceRecord.model_validate_json(line))

    quarantined = sum(
        1 for ev in evidence
        if any(f.severity == "quarantine" for f in ev.injection_flags)
    )
    print(f"  loaded state: {len(evidence)} evidence records, {quarantined} quarantined")

    state = PipelineState(
        question="rescan-after-approval re-run",
        run_id=run_dir.name,
        candidates=candidates,
        tool_plan=tool_plan,
        plan_digest=compute_plan_digest(tool_plan),
        evidence=evidence,
        canary="",
    )
    return state


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run-dir", required=True,
                    help="Absolute path to the QUARANTINED run dir.")
    args = ap.parse_args()

    run_dir = Path(args.run_dir).resolve()
    if not run_dir.is_dir():
        print(f"ERROR: run_dir does not exist: {run_dir}", file=sys.stderr)
        return 2

    case_id = _case_id_from_run_dir(run_dir)
    print(f"\n{'='*70}\nRESCAN AFTER APPROVAL\n{'='*70}")
    print(f"  case_id  {case_id}")
    print(f"  run_dir  {run_dir}")

    quarantined_marker = run_dir / "07_terminal.QUARANTINED"
    if not quarantined_marker.exists():
        print(f"  WARN: no 07_terminal.QUARANTINED marker present; rescan still proceeds")

    os.environ["HUMAN_APPROVED_QUARANTINE_OVERRIDE"] = "1"
    print(f"  override HUMAN_APPROVED_QUARANTINE_OVERRIDE=1 set")

    langfuse = Langfuse()
    llm_client = LangfuseOpenAI(
        api_key=os.environ["OPENROUTER_API_KEY"],
        base_url="https://openrouter.ai/api/v1",
    )

    state = _load_state(run_dir)

    _nodes.LLM_CLIENT      = llm_client
    _nodes.LANGFUSE        = langfuse
    _nodes.INTERPRET_MODEL = "anthropic/claude-sonnet-4-6"
    _nodes.CASE_ID         = case_id
    _nodes.OUT_DIR         = run_dir
    _nodes.E01_PATH        = ""
    _nodes.MEMORY_IMAGE_PATH = None
    _nodes.MEMORY_PROFILE  = None

    _nodes._reset_run_cost()

    print(f"\n--- INTERPRET (rescan) ---")
    delta = _nodes.interpret_node(state)
    findings = delta.get("findings")
    if not findings:
        print(f"  no findings returned")
        return 1

    state_after = state.model_copy(update=delta)

    out_path = run_dir / "05b_interpret_findings_post_approval.json"
    out_path.write_text(findings.model_dump_json(indent=2), encoding="utf-8")
    (run_dir / "07_terminal.HUMAN_APPROVED").touch()

    print(f"\n  wrote {out_path}")
    print(f"  marker 07_terminal.HUMAN_APPROVED touched")
    print(f"\n  {len(findings.findings)} findings after rescan:")
    for f in findings.findings:
        v = (f.value or "")[:80]
        print(f"    [{f.confidence}] {f.classification}/{f.category} :: {v}")

    langfuse.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
