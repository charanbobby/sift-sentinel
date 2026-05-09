"""Find Evil Sentinel: unified site.

Wraps the existing viewer at /viewer and adds three new sections:
  /                    landing dashboard with live status + learnings + submit
  /api/status          current pipeline activity, latest cron, recent tweaks
  /api/learnings       contents of pipeline/learned_rules.jsonl with provenance
  /api/submissions     list submitted test ideas (community contributions)
  POST /api/submissions  accept a new test idea (validated against the manifest schema)

Mount the existing viewer at /viewer to keep the run-detail UI accessible
under the same site. The viewer's own static-file path (`/viewer/index.html`)
is served by this app at `/viewer`.

Run: uvicorn pipeline.site:app --host 0.0.0.0 --port 8081
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Reuse the existing viewer FastAPI app verbatim. Mounting it under /viewer
# keeps every viewer URL working unchanged at /viewer/api/cases etc.
from pipeline.viewer import app as viewer_app

REPO_ROOT = Path(os.environ.get("REPO_ROOT", "/workspace"))
RUNS_ROOT = Path(os.environ.get("RUNS_ROOT", "/workspace/out/runs"))
LEARNED_RULES_PATH = Path(os.environ.get("LEARNED_RULES_PATH", "/workspace/pipeline/learned_rules.jsonl"))
LOOP_RUNS_DIR = Path(os.environ.get("LOOP_RUNS_DIR", "/loop_runs"))
SUBMISSIONS_PATH = Path(os.environ.get("SUBMISSIONS_PATH", "/workspace/site/submissions.jsonl"))
SITE_HTML = Path(os.environ.get("SITE_HTML", "/workspace/site/index.html"))

app = FastAPI(title="Find Evil Sentinel", docs_url=None, redoc_url=None)


# ── helpers ──────────────────────────────────────────────────────────────────

def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _read_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _git_log(n: int = 10) -> list[dict]:
    """Recent commits touching pipeline/scripts. Returns a list of
    {hash, when, subject, files} dicts. Best-effort; returns [] if git
    or the .git directory is unavailable.
    """
    try:
        out = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT.parent), "log",
             f"-n{n}", "--pretty=format:%h|%cr|%s",
             "--", "experiments/slice-2-notebook/pipeline",
             "experiments/slice-2-notebook/viewer",
             "experiments/slice-2-notebook/site",
             "scripts"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=4,
        )
    except Exception:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split("|", 2)
        if len(parts) == 3:
            rows.append({"hash": parts[0], "when": parts[1], "subject": parts[2]})
    return rows


# ── status endpoint ──────────────────────────────────────────────────────────

@app.get("/api/status")
def status() -> JSONResponse:
    """Snapshot of what is happening right now: latest cron, in-flight pipelines,
    promoted learnings count, recent commits."""
    out: dict[str, Any] = {
        "now_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
    }

    # Latest cron run (newest dated dir under /loop_runs)
    if LOOP_RUNS_DIR.exists():
        date_dirs = sorted(
            [d for d in LOOP_RUNS_DIR.iterdir() if d.is_dir() and re.match(r"\d{4}-\d{2}-\d{2}$", d.name)],
            reverse=True,
        )
        if date_dirs:
            latest = date_dirs[0]
            score = next(latest.glob("score_*.json"), None)
            score_data = _read_json(score) if score else None
            proposed = latest / "learned_rules.proposed.md"
            out["latest_cron"] = {
                "date": latest.name,
                "report_md_exists": (latest / "REPORT.md").exists(),
                "score_path": str(score.relative_to(LOOP_RUNS_DIR)) if score else None,
                "regression_pass": (score_data or {}).get("regression", {}).get("pass", []),
                "regression_fail": (score_data or {}).get("regression", {}).get("fail", []),
                "extension_pass": (score_data or {}).get("extension", {}).get("pass"),
                "extension_miss": (score_data or {}).get("extension", {}).get("miss"),
                "phase_g_proposals_md": (
                    str(proposed.relative_to(LOOP_RUNS_DIR)) if proposed.exists() else None
                ),
            }

    # In-flight runs: scan for cases whose latest run lacks ANY 07_terminal.* marker.
    # Skip entries that are genesis-only (1 ledger event, the run never produced a plan)
    # OR older than 2 hours (a killed-mid-run case otherwise haunts this list forever).
    # Match terminal markers by glob so HUMAN_REJECTED, HUMAN_APPROVED.audit, and
    # similar suffixed variants are recognized; the previous hard-coded set missed them
    # and pushed already-adjudicated runs into "in flight".
    in_flight = []
    stale_cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=2)
    if RUNS_ROOT.exists():
        for case_dir in sorted(RUNS_ROOT.iterdir()):
            if not case_dir.is_dir():
                continue
            latest_txt = case_dir / "latest.txt"
            if not latest_txt.exists():
                continue
            try:
                run_id = latest_txt.read_text(encoding="utf-8").strip()
            except Exception:
                continue
            run_path = case_dir / run_id
            if not run_path.is_dir():
                continue
            terminal_present = any(run_path.glob("07_terminal.*"))
            if terminal_present:
                continue
            ledger = _read_jsonl(run_path / "integrity_ledger.jsonl")
            if len(ledger) <= 1:
                continue
            last_event = ledger[-1] if ledger else None
            last_event_at = (last_event or {}).get("timestamp_utc")
            if last_event_at:
                try:
                    if _dt.datetime.fromisoformat(last_event_at) < stale_cutoff:
                        continue
                except Exception:
                    pass
            in_flight.append({
                "case_id": case_dir.name,
                "run_id": run_id,
                "n_ledger_entries": len(ledger),
                "last_event_type": (last_event or {}).get("event_type"),
                "last_event_at": last_event_at,
            })
    out["in_flight"] = in_flight

    # Promoted learnings count
    rules = _read_jsonl(LEARNED_RULES_PATH)
    by_kind: dict[str, int] = {}
    for r in rules:
        k = r.get("rule_kind", "?")
        by_kind[k] = by_kind.get(k, 0) + 1
    out["learnings"] = {
        "promoted_total": len(rules),
        "by_kind": by_kind,
    }

    # Recent tweaks
    out["recent_tweaks"] = _git_log(8)

    return JSONResponse(out)


# ── learnings endpoint ───────────────────────────────────────────────────────

@app.get("/api/learnings")
def learnings() -> JSONResponse:
    """All promoted rules with provenance."""
    rules = _read_jsonl(LEARNED_RULES_PATH)
    return JSONResponse({"count": len(rules), "rules": rules})


# ── proposed-rules endpoint ──────────────────────────────────────────────────

@app.get("/api/proposed-rules")
def proposed_rules(date: str | None = None) -> JSONResponse:
    """Read learned_rules.staged.jsonl for the given date (default: latest)
    and return the rules that have not yet been promoted or rejected. The
    Today's-run dashboard reads this to render its drafted-rules section.
    """
    if not LOOP_RUNS_DIR.exists():
        return JSONResponse({"detail": "loop-runs dir not present"}, status_code=404)
    if date is None:
        date_dirs = sorted(
            [d for d in LOOP_RUNS_DIR.iterdir()
             if d.is_dir() and re.match(r"\d{4}-\d{2}-\d{2}$", d.name)],
            reverse=True,
        )
        if not date_dirs:
            return JSONResponse({"detail": "no dated cron dirs"}, status_code=404)
        date = date_dirs[0].name
    date_dir = LOOP_RUNS_DIR / date
    if not date_dir.is_dir():
        return JSONResponse({"detail": f"no run for date {date}"}, status_code=404)
    staged = _read_jsonl(date_dir / "learned_rules.staged.jsonl")
    rejected_ids = {r.get("rule_id") for r in _read_jsonl(date_dir / "learned_rules.rejected.jsonl")}
    live_norm = {(r.get("rule_kind"), (r.get("rule_text") or "").strip().lower())
                 for r in _read_jsonl(LEARNED_RULES_PATH)}
    out = []
    for r in staged:
        rid = r.get("id")
        if rid in rejected_ids:
            continue
        key = (r.get("rule_kind"), (r.get("rule_text") or "").strip().lower())
        if key in live_norm:
            continue
        out.append(r)
    return JSONResponse({"date": date, "count": len(out), "rules": out})


# ── reject-rule endpoint ─────────────────────────────────────────────────────

class _RejectBody(BaseModel):
    date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    rule_id: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=2000)


@app.post("/api/reject-rule")
def reject_rule(body: _RejectBody, request: Request) -> JSONResponse:
    """Append a rejection record to learned_rules.rejected.jsonl for the given
    date. The drafter (next cron's learn_from_misses.py run) reads this file
    to skip drafting another rule for the same source_miss_id.
    """
    date_dir = LOOP_RUNS_DIR / body.date
    if not date_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"no run for date {body.date}")
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(status_code=400, detail="reason required")
    if len(reason) > 500:
        reason = reason[:500]
    record = {
        "rule_id": body.rule_id,
        "reason": reason,
        "rejected_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "rejected_by": "site-user",
        "source_ip": request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown"),
    }
    rejected_path = date_dir / "learned_rules.rejected.jsonl"
    with rejected_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    audit_path = LOOP_RUNS_DIR / "promotions.audit.jsonl"
    with audit_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({**record, "action": "reject", "date": body.date}) + "\n")
    return JSONResponse({"ok": True})


# ── research endpoint ────────────────────────────────────────────────────────

@app.get("/api/research")
def research() -> JSONResponse:
    """Latest manifest produced by the autonomous research step.

    Walks LOOP_RUNS_DIR newest-first, picks the first dated dir that contains
    a real `manifest_<date>.json` (excluding `*.wrapper.json` from the Haiku
    CLI envelope), parses it and returns the fields that the dashboard's
    "Recent threat intel" section renders. 404 if no manifest is found.
    """
    if not LOOP_RUNS_DIR.exists():
        return JSONResponse({"detail": "loop-runs dir not present"}, status_code=404)
    date_dirs = sorted(
        [d for d in LOOP_RUNS_DIR.iterdir()
         if d.is_dir() and re.match(r"\d{4}-\d{2}-\d{2}$", d.name)],
        reverse=True,
    )
    for d in date_dirs:
        candidates = [
            p for p in d.glob("manifest_*.json")
            if not p.name.endswith(".wrapper.json")
        ]
        if not candidates:
            continue
        try:
            data = json.loads(candidates[0].read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict) or not data.get("manifest_id"):
            continue
        return JSONResponse({
            "manifest_id": data.get("manifest_id"),
            "intel_window_days": data.get("intel_window_days"),
            "intel_sources": data.get("intel_sources") or [],
            "categories": [
                {
                    "name": c.get("name"),
                    "rationale": c.get("rationale"),
                    "artifacts": [
                        {
                            "id": a.get("id"),
                            "type": a.get("type"),
                            "expected_detection": a.get("expected_detection"),
                        }
                        for a in (c.get("artifacts") or [])
                    ],
                }
                for c in (data.get("categories") or [])
            ],
            "loop_run_date": d.name,
        })
    return JSONResponse({"detail": "no manifest in any loop-run dir"}, status_code=404)


# ── submissions ──────────────────────────────────────────────────────────────

# Submission schema. Anyone can propose a test artifact; the cron picks
# accepted submissions up the next morning. Validation here is structural
# only; semantic validation (does the file_drop content actually break a
# real shell parser?) is done by score.py the next day.
_ALLOWED_TYPES = {"file_drop", "registry_run_key", "scheduled_task_xml"}
_ALLOWED_DETECTIONS = {
    "attacker_persistence",
    "attacker_persistence_ai_assisted",
    "tradecraft_signal",
    "expected_miss_documented_gap",
}
# Reject obvious attempts to abuse the form: live URLs in source_url etc.
# We deliberately allow the example.invalid TLD and ALLCAPS_PLACEHOLDER tokens
# inside content fields, since those are the project's manifest convention.


@app.post("/api/submissions")
async def submit_test(req: Request) -> JSONResponse:
    """Accept a community test submission. Validates structure, writes to a
    JSONL queue. The cron's research step does NOT auto-promote these to
    the live manifest; a human reviews submissions.jsonl first."""
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail="body must be JSON")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")

    required = ["submitter", "artifact_id", "type", "expected_detection", "rationale"]
    missing = [k for k in required if not isinstance(body.get(k), str) or not body[k].strip()]
    if missing:
        raise HTTPException(status_code=400, detail=f"missing required fields: {missing}")

    if body["type"] not in _ALLOWED_TYPES:
        raise HTTPException(status_code=400, detail=f"type must be one of {sorted(_ALLOWED_TYPES)}")
    if body["expected_detection"] not in _ALLOWED_DETECTIONS:
        raise HTTPException(status_code=400, detail=f"expected_detection must be one of {sorted(_ALLOWED_DETECTIONS)}")

    # Per-type sanity check on the payload (mild structural; semantic
    # validation is done downstream).
    t = body["type"]
    if t == "file_drop":
        if not isinstance(body.get("file_path"), str) or not body["file_path"].strip():
            raise HTTPException(status_code=400, detail="file_drop requires file_path")
        if not isinstance(body.get("file_content_text"), str):
            raise HTTPException(status_code=400, detail="file_drop requires file_content_text")
    elif t == "registry_run_key":
        for k in ("hive", "key_path", "value_name", "value_data"):
            if not isinstance(body.get(k), str) or not body[k].strip():
                raise HTTPException(status_code=400, detail=f"registry_run_key requires {k}")
    elif t == "scheduled_task_xml":
        if not isinstance(body.get("task_install_path"), str) or not body["task_install_path"].strip():
            raise HTTPException(status_code=400, detail="scheduled_task_xml requires task_install_path")
        if not isinstance(body.get("task_xml"), str) or not body["task_xml"].strip():
            raise HTTPException(status_code=400, detail="scheduled_task_xml requires task_xml")

    # Source-url is optional but if provided must look like a URL and not a
    # live attacker C2. We do not validate uptime; we just reject anything
    # that does not parse as scheme://host/.
    src = body.get("source_url")
    if src is not None:
        if not isinstance(src, str) or not re.match(r"^https?://[A-Za-z0-9._-]+", src):
            raise HTTPException(status_code=400, detail="source_url must be a valid http(s) URL")

    SUBMISSIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "submitted_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "status": "pending_review",
        **body,
    }
    with SUBMISSIONS_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    return JSONResponse({"ok": True, "queued": record}, status_code=201)


@app.get("/api/submissions")
def list_submissions() -> JSONResponse:
    """List submitted test ideas. Newest first. Filters out smoke-test entries
    (submitter == 'smoke-test') so the public dashboard does not advertise them.
    """
    rows = _read_jsonl(SUBMISSIONS_PATH)
    rows = [r for r in rows if r.get("submitter") != "smoke-test"]
    rows.reverse()
    return JSONResponse({"count": len(rows), "submissions": rows})


# ── landing page ─────────────────────────────────────────────────────────────

@app.get("/")
def index():
    if not SITE_HTML.exists():
        raise HTTPException(status_code=404, detail=f"site/index.html not found at {SITE_HTML}")
    return FileResponse(SITE_HTML, media_type="text/html")


# ── viewer mount ─────────────────────────────────────────────────────────────
# Sub-app sees /viewer/ and forwards to its own routing tree (viewer-relative
# paths now resolve under /viewer/api/cases etc).
app.mount("/viewer", viewer_app, name="viewer")


# ── static for the site directory ────────────────────────────────────────────
if SITE_HTML.parent.exists():
    app.mount("/site", StaticFiles(directory=str(SITE_HTML.parent)), name="site")


# ── static for the daily cron loop_runs output ───────────────────────────────
# The dashboard's "view markdown" link generates /loop_runs/<date>/<file>; this
# mount serves those files (REPORT.md, learned_rules.proposed.md, score JSON,
# etc.) directly. Without this mount the link 404s at the edge.
if LOOP_RUNS_DIR.exists():
    app.mount("/loop_runs", StaticFiles(directory=str(LOOP_RUNS_DIR)), name="loop_runs")
