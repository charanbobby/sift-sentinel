"""Autonomous pipeline runner — replaces the notebook workflow.

Runs the full pipeline (extract → plan → execute → interpret → critic) for a
single case and saves outputs to out/runs/<case_id>/. No interactive cells,
no Jupyter, no human approval prompt for the capability token — this is the
"u can do it" path where the orchestrator auto-issues the token after plan_node
generates the ToolPlan.

Usage (inside sift-sentinel):
    /workspace/.venv/bin/python /workspace/run_case.py \\
        --case srl-2018-base-dc \\
        --e01 /mnt/derived/base-dc.ntfs.dd

The --case value becomes the case_id in all audit trails and output paths.
The --e01 value is the disk image path the MCP server tools receive.
"""
from __future__ import annotations

import argparse
import shutil
import sys
import uuid
from pathlib import Path

sys.path.insert(0, "/workspace")

from langfuse import Langfuse
from langfuse.openai import OpenAI as LangfuseOpenAI

import pipeline.nodes as _nodes
from pipeline.graph import PipelineState, build_graph, compute_thread_id
from pipeline.mcp.tokens import issue_token

MODELS = {
    "extract":   "google/gemini-2.0-flash-001",
    "plan":      "anthropic/claude-sonnet-4-6",
    "interpret": "anthropic/claude-sonnet-4-6",
}

QUESTION = (
    "Given a Windows disk image suspected of compromise, "
    "what persistence mechanisms did the attacker install?"
)

ALLOWED_PATHS_TEMPLATE = (
    "/mnt/hackathon/",
    "/mnt/derived/",
    "/home/sansforensics/cases/{case_id}/analysis/extracted/",
)


def _configure_nodes(case_id: str, e01_path: str, out_dir: Path, langfuse, llm_client) -> None:
    _nodes.LLM_CLIENT      = llm_client
    _nodes.LANGFUSE        = langfuse
    _nodes.EXTRACT_MODEL   = MODELS["extract"]
    _nodes.PLAN_MODEL      = MODELS["plan"]
    _nodes.INTERPRET_MODEL = MODELS["interpret"]
    _nodes.CASE_ID         = case_id
    _nodes.E01_PATH        = e01_path
    _nodes.OUT_DIR         = out_dir


def run(case_id: str, e01_path: str) -> int:
    run_id = f"{case_id}-{uuid.uuid4().hex[:8]}"
    out_dir = Path("/workspace/out/runs") / case_id
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*70}")
    print(f"PIPELINE RUN")
    print(f"{'='*70}")
    print(f"  case_id   {case_id}")
    print(f"  e01_path  {e01_path}")
    print(f"  run_id    {run_id}")
    print(f"  out_dir   {out_dir}")
    print()

    langfuse   = Langfuse()
    llm_client = LangfuseOpenAI(
        api_key=__import__("os").environ["OPENROUTER_API_KEY"],
        base_url="https://openrouter.ai/api/v1",
    )

    _configure_nodes(case_id, e01_path, out_dir, langfuse, llm_client)

    # Build the graph (extract_node is now the real impl in pipeline.nodes)
    graph = build_graph()
    thread_id = compute_thread_id(case_id, run_id)

    # Initial state — graph starts from START and runs all nodes
    initial = PipelineState(question=QUESTION, run_id=run_id)

    print("--- EXTRACT ---")
    # Run extract manually first so we can see candidates before plan
    extract_delta = _nodes.extract_node(initial)
    state_after_extract = initial.model_copy(update=extract_delta)
    if state_after_extract.candidates:
        cands = state_after_extract.candidates.candidates
        print(f"  {len(cands)} candidates")
        for c in cands:
            print(f"    [{c.priority}] {c.artifact_type:<22} {c.path_hint}")
    print()

    print("--- PLAN ---")
    plan_delta = _nodes.plan_node(state_after_extract)
    state_after_plan = state_after_extract.model_copy(update=plan_delta)
    if state_after_plan.tool_plan:
        tp = state_after_plan.tool_plan
        print(f"  {len(tp.steps)} steps  expected_findings_range={tp.expected_findings_range}")
        for s in tp.steps:
            print(f"    [{s.step_id}] {s.tool:<28} {s.purpose[:55]}")
    print()

    print("--- AUTO-APPROVE + TOKEN ISSUE ---")
    allowed_paths = tuple(
        p.format(case_id=case_id) for p in ALLOWED_PATHS_TEMPLATE
    )
    token = issue_token(
        state_after_plan.tool_plan,
        case_id=case_id,
        allowed_paths=allowed_paths,
        ttl_seconds=3600,
    )
    state_with_token = state_after_plan.model_copy(update={"capability_token": token})
    print(f"  token_id={token.token_id[:8]}…  tools={sorted(token.allowed_tools)}")
    print()

    # Save tool_plan.json to out_dir (mirrors notebook C6 behaviour)
    (out_dir / "tool_plan.json").write_text(
        state_with_token.tool_plan.model_dump_json(indent=2), encoding="utf-8"
    )
    # Write APPROVED sentinel so any code checking for it doesn't block
    (out_dir / "tool_plan.APPROVED").touch()

    print("--- EXECUTE → INTERPRET → CRITIC ---")
    # Feed the pre-built state into the graph. Extract and plan nodes will skip
    # (idempotency guards: candidates and tool_plan are already set).
    final = graph.invoke(
        state_with_token.model_dump(mode="json"),
        config={"configurable": {"thread_id": thread_id}},
    )
    print()

    # Persist findings
    findings = final.get("findings")
    if findings:
        from pipeline.schemas import Findings as FindingsModel
        if isinstance(findings, dict):
            findings_obj = FindingsModel.model_validate(findings)
        else:
            findings_obj = findings
        (out_dir / "findings.json").write_text(
            findings_obj.model_dump_json(indent=2), encoding="utf-8"
        )
        (out_dir / "findings.SUCCESS").touch()
        print(f"findings written: {len(findings_obj.findings)} finding(s)")
        for f in findings_obj.findings:
            print(f"  [{f.confidence}] {f.category}  {f.value}")
    else:
        print("  no findings object in final state")

    # Copy evidence.jsonl if it ended up in the legacy out/ root
    src_ev = Path("/workspace/out/evidence.jsonl")
    if src_ev.exists():
        shutil.copy2(src_ev, out_dir / "evidence.jsonl")

    langfuse.flush()
    print(f"\nDone. Outputs at {out_dir}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--case", required=True, help="case_id, e.g. srl-2018-base-dc")
    ap.add_argument("--e01",  required=True, help="disk image path inside sift-mcp")
    args = ap.parse_args()
    return run(args.case, args.e01)


if __name__ == "__main__":
    sys.exit(main())
