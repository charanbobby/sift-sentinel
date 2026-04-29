"""Autonomous pipeline runner — replaces the notebook workflow.

Runs the full pipeline (extract → plan → execute → interpret → critic) for a
single case and saves outputs to out/runs/<case_id>/<case_id>-NNN/. Each
invocation gets its own zero-padded sequential subfolder (`-001`, `-002`, ...)
so re-runs never overwrite prior runs and a directory listing sorts by run
order. `latest.txt` at the case level points at the most recent run_id.

No interactive cells, no Jupyter, no human approval prompt for the capability
token — this is the "u can do it" path where the orchestrator auto-issues the
token after plan_node generates the ToolPlan.

Usage (inside sift-sentinel):
    /workspace/.venv/bin/python /workspace/run_case.py \\
        --case srl-2018-base-dc \\
        --e01 /mnt/derived/base-dc.ntfs.dd

The --case value becomes the case_id in all audit trails and output paths.
The --e01 value is the disk image path the MCP server tools receive.
"""
from __future__ import annotations

import argparse
import asyncio
import re
import sys
from pathlib import Path

sys.path.insert(0, "/workspace")

from langfuse import Langfuse
from langfuse.openai import OpenAI as LangfuseOpenAI

import pipeline.nodes as _nodes
from pipeline.graph import PipelineState, build_graph, compute_thread_id, mint_canary
from pipeline.mcp.tokens import issue_token
from pipeline.output_layout import (
    PLAN_TOOL_PLAN,
    APPROVE_SENTINEL,
    INTERPRET_FINDINGS,
    EXECUTE_EVIDENCE_JSONL,
    INTEGRITY_LEDGER_JSONL,
    terminal_marker_for,
)

MODELS = {
    "extract":   "google/gemini-3-flash-preview",
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
    "/mnt/working/",    # synthetic workstation daily-loop images
    "/home/sansforensics/cases/{case_id}/analysis/extracted/",
)


def _configure_nodes(
    case_id: str,
    e01_path: str,
    out_dir: Path,
    langfuse,
    llm_client,
    memory_image_path: str | None = None,
    memory_profile: str | None = None,
) -> None:
    _nodes.LLM_CLIENT         = llm_client
    _nodes.LANGFUSE            = langfuse
    _nodes.EXTRACT_MODEL       = MODELS["extract"]
    _nodes.PLAN_MODEL          = MODELS["plan"]
    _nodes.INTERPRET_MODEL     = MODELS["interpret"]
    _nodes.CASE_ID             = case_id
    _nodes.E01_PATH            = e01_path
    _nodes.OUT_DIR             = out_dir
    _nodes.MEMORY_IMAGE_PATH   = memory_image_path
    _nodes.MEMORY_PROFILE      = memory_profile


_RUN_ID_RE = re.compile(r"^.+-(\d{3,})$")


def _next_run_id(case_dir: Path, case_id: str) -> str:
    """Allocate the next sequential run_id under `case_dir`.

    Scans for sibling subdirectories named `<case_id>-NNN` (3+ digits) and
    returns `<case_id>-<N+1, zero-padded to 3>`. Folders that don't match
    the pattern (archived snapshots, pre-step-0, latest.txt) are ignored.
    Replaces the prior `uuid.uuid4().hex[:8]` random suffix so a directory
    listing sorts by run order.
    """
    if not case_dir.exists():
        return f"{case_id}-001"
    highest = 0
    for child in case_dir.iterdir():
        if not child.is_dir():
            continue
        m = _RUN_ID_RE.match(child.name)
        if not m:
            continue
        n = int(m.group(1))
        if n > highest:
            highest = n
    return f"{case_id}-{highest + 1:03d}"


def run(case_id: str, e01_path: str, memory_image_path: str | None = None, memory_profile: str | None = None) -> int:
    case_dir = Path("/workspace/out/runs") / case_id
    run_id = _next_run_id(case_dir, case_id)
    out_dir = case_dir / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    # Update the case-level pointer to the most recent run. Written before any
    # pipeline work so a crashed mid-run still leaves a discoverable run_id;
    # downstream tools that read latest.txt must accept "run dir exists but
    # findings.SUCCESS may be absent" semantics.
    (case_dir / "latest.txt").write_text(run_id + "\n", encoding="utf-8")

    # Slice 6 Step 7 — ablation-row sidecar marker. Set ABLATION_ROW=2 (row 2,
    # capability-token verification disabled) or =4 (row 4, classification
    # field removed) when running on the corresponding ablation branch so
    # `score_ablation.py` can group runs by configuration without parsing
    # branch names. Default-unset runs are treated as row 3 (full Slice 5).
    ablation_row = __import__("os").environ.get("ABLATION_ROW", "").strip()
    if ablation_row:
        (out_dir / "ablation_row.txt").write_text(ablation_row + "\n", encoding="utf-8")

    print(f"\n{'='*70}")
    print(f"PIPELINE RUN")
    print(f"{'='*70}")
    print(f"  case_id        {case_id}")
    print(f"  e01_path       {e01_path}")
    print(f"  run_id         {run_id}")
    print(f"  out_dir        {out_dir}")
    if memory_image_path:
        print(f"  memory_image   {memory_image_path}")
        print(f"  memory_profile {memory_profile}")
    if ablation_row:
        print(f"  ablation_row   {ablation_row}")
    print()

    langfuse   = Langfuse()
    llm_client = LangfuseOpenAI(
        api_key=__import__("os").environ["OPENROUTER_API_KEY"],
        base_url="https://openrouter.ai/api/v1",
    )

    _configure_nodes(case_id, e01_path, out_dir, langfuse, llm_client,
                     memory_image_path=memory_image_path,
                     memory_profile=memory_profile)

    # Slice 6 Step 4b — genesis entry for the integrity ledger. Written once
    # per case; idempotent across resume via LedgerWriter.append_genesis.
    # e01_sha256 is left empty here — preprocess_e01.py captures it at stage
    # time; plumbing that through to run_case is a follow-on. Still a valid
    # genesis; plan_approved + per-event entries anchor the chain downstream.
    _nodes._ledger_genesis(e01_sha256="", plan_digest="")

    # Build the graph (extract_node is now the real impl in pipeline.nodes)
    graph = build_graph()
    thread_id = compute_thread_id(case_id, run_id)

    # Initial state — graph starts from START and runs all nodes.
    # `canary` is the per-run defender-AI-integrity tripwire; interpret_node
    # embeds it in the LLM bundle and halts the run with CANARY_LEAK if the
    # response echoes it. Minted once per invoke; empty string would disable.
    canary = mint_canary()
    print(f"  canary    {canary[:12]}…  (defender-AI tripwire active)")
    print()
    initial = PipelineState(question=QUESTION, run_id=run_id, canary=canary)

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

    # Save the tool_plan to out_dir (mirrors notebook C6 behaviour).
    (out_dir / PLAN_TOOL_PLAN).write_text(
        state_with_token.tool_plan.model_dump_json(indent=2), encoding="utf-8"
    )
    # Approve sentinel — any code checking for it won't block.
    (out_dir / APPROVE_SENTINEL).touch()

    # Slice 6 Step 4b — plan_approved ledger entry.
    _nodes._ledger_append(
        "plan_approved",
        plan_digest=token.plan_digest,
        token_id=token.token_id,
        n_steps=len(state_with_token.tool_plan.steps),
        allowed_tools=sorted(token.allowed_tools),
    )

    print("--- EXECUTE → INTERPRET → CRITIC ---")
    # Feed the pre-built state into the graph. Extract and plan nodes will skip
    # (idempotency guards: candidates and tool_plan are already set).
    final = asyncio.run(graph.ainvoke(
        state_with_token.model_dump(mode="json"),
        config={"configurable": {"thread_id": thread_id}},
    ))
    print()

    # Persist findings. Marker filename reflects the actual route the graph
    # took: 07_terminal.SUCCESS only on commit; .HUMAN_REVIEW or .QUARANTINED
    # on escalate. human_review_node sets state.decision; commit leaves it None.
    marker_name = terminal_marker_for(final.get("decision"))

    findings = final.get("findings")
    if findings:
        from pipeline.schemas import Findings as FindingsModel
        if isinstance(findings, dict):
            findings_obj = FindingsModel.model_validate(findings)
        else:
            findings_obj = findings
        (out_dir / INTERPRET_FINDINGS).write_text(
            findings_obj.model_dump_json(indent=2), encoding="utf-8"
        )
        (out_dir / marker_name).touch()
        print(f"findings written: {len(findings_obj.findings)} finding(s) [{marker_name}]")
        for f in findings_obj.findings:
            print(f"  [{f.confidence}] {f.category}  {f.value}")
    else:
        # No findings can still mean any of the three routes; preserve the
        # marker so audit tools can distinguish a no-findings commit from a
        # no-findings escalate.
        (out_dir / marker_name).touch()
        print(f"  no findings object in final state [{marker_name}]")

    # Persist all evidence records accumulated across all graph passes
    evidence_list = final.get("evidence") or []
    if evidence_list:
        from pipeline.schemas import EvidenceRecord as _EvidenceRecord
        ev_path = out_dir / EXECUTE_EVIDENCE_JSONL
        with ev_path.open("w", encoding="utf-8") as _f:
            for _ev in evidence_list:
                if isinstance(_ev, dict):
                    _ev = _EvidenceRecord.model_validate(_ev)
                _f.write(_ev.model_dump_json() + "\n")
        print(f"evidence written: {len(evidence_list)} record(s)")

    # Slice 6 Step 4b — session_close. Marks the pipeline run as complete.
    # A ledger without this entry verifies as valid-prefix (crashed mid-run);
    # with it, the reviewer can tell the run finished normally.
    findings_count = len(findings_obj.findings) if findings else 0
    _nodes._ledger_append(
        "session_close",
        findings_count=findings_count,
        evidence_count=len(evidence_list),
    )

    # Verify the ledger on the way out — fail loudly if the chain broke
    # during the run (infrastructure problem worth catching before downstream
    # consumers read from it).
    from pipeline.ledger import verify_ledger
    ledger_path = out_dir / INTEGRITY_LEDGER_JSONL
    ok, entries, err = verify_ledger(ledger_path)
    if ok:
        print(f"\nIntegrity ledger: {entries} entries, chain verifies clean.")
    else:
        print(f"\n!!! Integrity ledger BROKEN at entry {entries}: {err}")
        raise RuntimeError(f"ledger chain broken: {err}")

    langfuse.flush()
    print(f"\nDone. Outputs at {out_dir}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--case", required=True, help="case_id, e.g. srl-2018-base-dc")
    ap.add_argument("--e01",  required=True, help="disk image path inside sift-mcp")
    ap.add_argument("--memory-image", default=None, dest="memory_image",
                    help="Memory dump path inside sift-mcp (optional)")
    ap.add_argument("--memory-profile", default=None, dest="memory_profile",
                    help="Volatility 2 profile string, e.g. Win2012R2x64 (optional)")
    args = ap.parse_args()
    return run(args.case, args.e01,
               memory_image_path=args.memory_image,
               memory_profile=args.memory_profile)


if __name__ == "__main__":
    sys.exit(main())
