"""
Read-only FastAPI server that serves run output JSON files for the browser UI.

Endpoints:
  GET /                              → viewer/index.html
  GET /api/cases                     → list cases with run counts + latest status
  GET /api/cases/{case}/runs         → list runs for a case
  GET /api/cases/{case}/runs/{run}   → full run detail (all 7 pipeline files)
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

RUNS_ROOT = Path(os.environ.get("RUNS_ROOT", "/workspace/out/runs"))
VIEWER_HTML = Path(os.environ.get("VIEWER_HTML", "/workspace/viewer/index.html"))

app = FastAPI(title="Sift Sentinel Viewer", docs_url=None, redoc_url=None)


# ── helpers ──────────────────────────────────────────────────────────────────

def _terminal_status(run_path: Path) -> str:
    for suffix in ("SUCCESS", "HUMAN_REVIEW", "FAIL"):
        if (run_path / f"07_terminal.{suffix}").exists():
            return suffix
    return "INCOMPLETE"


def _is_real_run(run_path: Path) -> bool:
    """True if the run reached a terminal state (SUCCESS / HUMAN_REVIEW / FAIL).
    Filters out noise: archived-* dirs, pre-step-0 baselines, aborted runs,
    and crash-mid-flight INCOMPLETE residue."""
    return _terminal_status(run_path) != "INCOMPLETE"


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[Any]:
    if not path.exists():
        return []
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            lines.append(json.loads(line))
    return lines


_MEMORY_CLASSIFICATIONS = {"process_injection", "c2_beacon"}


def _run_summary(case_id: str, run_path: Path) -> dict:
    status = _terminal_status(run_path)
    findings_raw = _read_json(run_path / "05_interpret_findings.json")
    findings = findings_raw.get("findings", []) if findings_raw else []
    finding_count = len(findings)
    memory_finding_count = sum(
        1 for f in findings if f.get("classification") in _MEMORY_CLASSIFICATIONS
    )
    critic_events = _read_jsonl(run_path / "06_critic_disagreements.jsonl")
    started_at = findings_raw.get("started_at") if findings_raw else None
    finished_at = findings_raw.get("finished_at") if findings_raw else None
    return {
        "run_id": run_path.name,
        "case_id": case_id,
        "status": status,
        "finding_count": finding_count,
        "memory_finding_count": memory_finding_count,
        "critic_event_count": len(critic_events),
        "started_at": started_at,
        "finished_at": finished_at,
    }


# ── routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    if not VIEWER_HTML.exists():
        raise HTTPException(status_code=404, detail="viewer/index.html not found")
    return FileResponse(VIEWER_HTML, media_type="text/html")


@app.get("/api/cases")
def list_cases():
    if not RUNS_ROOT.exists():
        return JSONResponse([])
    cases = []
    for case_dir in sorted(RUNS_ROOT.iterdir()):
        if not case_dir.is_dir():
            continue
        run_dirs = sorted(
            [d for d in case_dir.iterdir() if d.is_dir() and _is_real_run(d)],
            key=lambda d: d.name,
        )
        if not run_dirs:
            continue
        latest = run_dirs[-1]
        latest_summary = _run_summary(case_dir.name, latest)
        cases.append({
            "case_id": case_dir.name,
            "run_count": len(run_dirs),
            "latest_run": latest_summary,
        })
    return JSONResponse(cases)


@app.get("/api/cases/{case_id}/runs")
def list_runs(case_id: str):
    case_dir = RUNS_ROOT / case_id
    if not case_dir.exists():
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    run_dirs = sorted(
        [d for d in case_dir.iterdir() if d.is_dir() and _is_real_run(d)],
        key=lambda d: d.name,
    )
    return JSONResponse([_run_summary(case_id, r) for r in reversed(run_dirs)])


@app.get("/api/cases/{case_id}/runs/{run_id}")
def get_run(case_id: str, run_id: str):
    run_path = RUNS_ROOT / case_id / run_id
    if not run_path.exists():
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

    ledger = _read_jsonl(run_path / "integrity_ledger.jsonl")
    evidence = _read_jsonl(run_path / "04_execute_evidence.jsonl")
    plan = _read_json(run_path / "02_plan_tool_plan.json")

    gates = next(
        (e for e in ledger if e.get("event_type") == "plan_approved"),
        None,
    )

    # Evidence rows do not carry the tool name — the executor writes only
    # tool_call_id. Correlate positionally with the plan (both are in execution
    # order). If a plan step was skipped/errored, lengths diverge and trailing
    # rows fall back to "unknown"; the viewer flags this so it is visible.
    plan_steps = (plan or {}).get("steps", [])
    for i, row in enumerate(evidence):
        if i < len(plan_steps):
            row["_derived_tool"] = plan_steps[i].get("tool", "unknown")
            row["_plan_step_index"] = i + 1
        else:
            row["_derived_tool"] = "unknown"
            row["_plan_step_index"] = None

    # Same problem for tool_call_completed ledger entries — they only carry
    # tool_call_id. On a re-iterated run the ledger keeps both batches but
    # evidence only retains the LATEST (iteration-1) batch, so naive
    # tool_call_id → evidence lookup leaves earlier-iteration entries unknown.
    # Strategy: group ledger tool_call entries by token_id (each token batch ≈
    # one iteration), sort by seq, then position-map each batch to plan.steps.
    # Verified on wkstn-05-005: positional mapping aligns 22/22 iter-1 entries
    # with their evidence (sanity check) and gives sensible tool names for the
    # 23 iter-0 entries that have no surviving evidence row.
    from collections import defaultdict
    tc_entries = [e for e in ledger if e.get("event_type") == "tool_call_completed"]
    by_token = defaultdict(list)
    for e in tc_entries:
        by_token[e.get("token_id", "")].append(e)
    for token, batch in by_token.items():
        batch.sort(key=lambda e: e.get("seq", 0))
        for i, e in enumerate(batch):
            if i < len(plan_steps):
                e["_derived_tool"] = plan_steps[i].get("tool", "unknown")
                e["_plan_step_index"] = i + 1
            else:
                e["_derived_tool"] = "unknown"
                e["_plan_step_index"] = None

    return JSONResponse({
        "run_id": run_id,
        "case_id": case_id,
        "status": _terminal_status(run_path),
        "extract": _read_json(run_path / "01_extract_candidates.json"),
        "plan": plan,
        "approved": (run_path / "03_approve.SUCCESS").exists(),
        "gates": gates,
        "evidence": evidence,
        "findings": _read_json(run_path / "05_interpret_findings.json"),
        "critic_events": _read_jsonl(run_path / "06_critic_disagreements.jsonl"),
        "ledger": ledger,
        "ledger_entry_count": len(ledger),
    })
