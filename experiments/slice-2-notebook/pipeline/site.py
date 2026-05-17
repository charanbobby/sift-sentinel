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
import sys
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

@app.get("/api/proposed-rules/dates")
def proposed_rules_dates() -> JSONResponse:
    """List every dated cron dir that has a non-empty learned_rules.staged.jsonl
    with at least one pending rule (not yet promoted or rejected). Sorted
    newest-first. The dashboard's "Older drafted rules" collapsible section
    reads this to surface past dates so a missed day's queue does not get
    silently overwritten by tomorrow's cron.
    """
    if not LOOP_RUNS_DIR.exists():
        return JSONResponse({"dates": [], "count": 0})
    live_norm = {(r.get("rule_kind"), (r.get("rule_text") or "").strip().lower())
                 for r in _read_jsonl(LEARNED_RULES_PATH)}
    out: list[dict] = []
    for d in sorted(LOOP_RUNS_DIR.iterdir(), reverse=True):
        if not d.is_dir() or not re.match(r"\d{4}-\d{2}-\d{2}$", d.name):
            continue
        staged = _read_jsonl(d / "learned_rules.staged.jsonl")
        if not staged:
            continue
        rejected_ids = {r.get("rule_id") for r in _read_jsonl(d / "learned_rules.rejected.jsonl")}
        pending = 0
        for r in staged:
            if r.get("id") in rejected_ids:
                continue
            key = (r.get("rule_kind"), (r.get("rule_text") or "").strip().lower())
            if key in live_norm:
                continue
            pending += 1
        if pending > 0:
            out.append({"date": d.name, "pending_count": pending, "staged_total": len(staged)})
    return JSONResponse({"dates": out, "count": len(out)})


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
    live_norm = {(r.get("rule_kind"), _normalize_rule_text(r.get("rule_text") or ""))
                 for r in _read_jsonl(LEARNED_RULES_PATH)}
    out = []
    for r in staged:
        rid = r.get("id")
        if rid in rejected_ids:
            continue
        key = (r.get("rule_kind"), _normalize_rule_text(r.get("rule_text") or ""))
        if key in live_norm:
            continue
        out.append(r)
    return JSONResponse({"date": date, "count": len(out), "rules": out})


# ── history endpoint ─────────────────────────────────────────────────────────

def _read_score(date_dir: Path) -> dict | None:
    """Read score_{date}.json for the given date dir and return counts.
    Returns None if the file is missing or unreadable.
    """
    candidates = sorted(date_dir.glob("score_*.json"))
    if not candidates:
        return None
    try:
        data = json.loads(candidates[-1].read_text(encoding="utf-8"))
    except Exception:
        return None
    counts = {"hit": 0, "miss": 0, "partial": 0, "total": 0}
    for entry in data.get("per_artifact", []) or []:
        status = (entry.get("status") or "").upper()
        if status == "HIT":
            counts["hit"] += 1
            counts["total"] += 1
        elif status == "MISS":
            counts["miss"] += 1
            counts["total"] += 1
        elif status == "PARTIAL":
            counts["partial"] += 1
            counts["total"] += 1
    return counts


def _load_audit() -> list[dict]:
    """Read promotions.audit.jsonl. Returns [] when the file is missing."""
    return _read_jsonl(LOOP_RUNS_DIR / "promotions.audit.jsonl")


def _history_for_date(date_dir: Path, audit: list[dict]) -> dict:
    """Build the per-date row for /api/history."""
    date = date_dir.name
    staged_by_id = {r.get("id"): r for r in _read_jsonl(date_dir / "learned_rules.staged.jsonl")}
    rejected_by_id = {r.get("rule_id"): r for r in _read_jsonl(date_dir / "learned_rules.rejected.jsonl")}

    promoted: list[dict] = []
    rejected: list[dict] = []
    for row in audit:
        if row.get("date") != date:
            continue
        rid = row.get("rule_id")
        staged = staged_by_id.get(rid, {})
        rule_text = staged.get("rule_text")
        rule_kind = staged.get("rule_kind")
        action = row.get("action")
        if action == "promote":
            promoted.append({
                "rule_id": rid,
                "rule_kind": rule_kind,
                "rule_text": rule_text,
                "promoted_at": row.get("promoted_at"),
            })
        elif action == "reject":
            reason = (rejected_by_id.get(rid) or {}).get("reason") or row.get("reason")
            rejected.append({
                "rule_id": rid,
                "rule_kind": rule_kind,
                "rule_text": rule_text,
                "reason": reason,
                "rejected_at": row.get("rejected_at"),
            })

    live_norm = {(r.get("rule_kind"), _normalize_rule_text(r.get("rule_text") or ""))
                 for r in _read_jsonl(LEARNED_RULES_PATH)}
    pending = 0
    for r in staged_by_id.values():
        if r.get("id") in rejected_by_id:
            continue
        key = (r.get("rule_kind"), _normalize_rule_text(r.get("rule_text") or ""))
        if key in live_norm:
            continue
        pending += 1

    return {
        "date": date,
        "score": _read_score(date_dir),
        "promoted": promoted,
        "rejected": rejected,
        "pending_count": pending,
    }


def _compute_trend(runs: list[dict]) -> dict:
    """HIT rate over last 7 vs prior 7 dated runs. Skips runs with score==None.
    Returns has_enough_data=False when fewer than 5 scoreable runs exist.
    """
    scored = [r for r in runs
              if r.get("score") and (r["score"]["hit"] + r["score"]["miss"]) > 0]
    if len(scored) < 5:
        return {"hit_rate_last_7": None, "delta_vs_prior_7": None, "has_enough_data": False}
    # Trend uses HIT / (HIT + MISS). PARTIAL is informational, not counted either way.
    def rate(rows: list[dict]) -> float:
        h = sum(r["score"]["hit"] for r in rows)
        m = sum(r["score"]["miss"] for r in rows)
        denom = h + m
        return (h / denom) if denom else 0.0
    last7 = scored[:7]
    prior7 = scored[7:14]
    last_rate = rate(last7)
    delta = (last_rate - rate(prior7)) if prior7 else None
    return {
        "hit_rate_last_7": round(last_rate, 4),
        "delta_vs_prior_7": (round(delta, 4) if delta is not None else None),
        "has_enough_data": True,
    }


@app.get("/api/history")
def history(limit: int = 14) -> JSONResponse:
    if not LOOP_RUNS_DIR.exists():
        return JSONResponse({"runs": [], "trend": {"has_enough_data": False}})
    date_dirs = sorted(
        [d for d in LOOP_RUNS_DIR.iterdir()
         if d.is_dir() and re.match(r"\d{4}-\d{2}-\d{2}$", d.name)],
        reverse=True,
    )[:max(1, int(limit))]
    audit = _load_audit()
    runs = [_history_for_date(d, audit) for d in date_dirs]
    return JSONResponse({"runs": runs, "trend": _compute_trend(runs)})


# ── live-prompts endpoint ────────────────────────────────────────────────────

_CANONICAL_EXTRACT_ARGS = {
    "host_type": "windows-workstation",
    "host_description": "Canonical Windows workstation for display only; the rules block is identical to what the agent sees at runtime.",
    "has_memory": True,
    "has_disk": True,
}

_CANONICAL_PLAN_ARGS = {
    "case_id": "canonical-host",
    "e01_path": "/cases/canonical-host/disk.E01",
    "memory_image_path": "/cases/canonical-host/memory.raw",
    "memory_profile": "Win10x64_19041",
}

# Serializes the nodes._LEARNED_RULES_PATH swap inside _render_live_prompts.
# FastAPI dispatches sync handlers on a threadpool, so two concurrent requests
# could otherwise interleave the swap and restore. The lock makes the
# swap+render+restore atomic across requests in the same process.
import threading as _threading
_RENDER_LIVE_PROMPTS_LOCK = _threading.Lock()


def _render_live_prompts() -> list[dict]:
    """Render INTERPRET, EXTRACT, PLAN system prompts with promoted-rule
    blocks spliced out so the UI can tint them.

    Response contract per agent: `agent`, `rendered_with`, `base_before`,
    `appended_block`, `base_after`, `appended_rules`. The UI renders
    `base_before + tinted(appended_block) + base_after`.

    - INTERPRET: the constant `INTERPRET_SYSTEM_PROMPT` does not embed the
      block (it is appended at the call site in nodes.py). `base_before` is
      the constant, `base_after` is empty.
    - EXTRACT: `_build_extract_prompt` embeds the block mid-template via
      `disk_section`. We render the full prompt, then split on the rendered
      block so `base_before` and `base_after` bracket it. If the block does
      not appear in the full prompt (no extract_location rules, or some
      future template change), `base_before` is the full prompt and
      `base_after` is empty; the UI then appends the block at the bottom.
    - PLAN: `_plan_system_prompt` ends with the block. Same split pattern.
    """
    from pipeline import nodes

    live_rules = nodes._load_learned_rules(LEARNED_RULES_PATH)

    def _entries_for(kind: str) -> list[dict]:
        out: list[dict] = []
        for rec in _read_jsonl(LEARNED_RULES_PATH):
            if rec.get("rule_kind") != kind:
                continue
            out.append({
                "rule_id": rec.get("id"),
                "rule_text": rec.get("rule_text"),
                "promoted_at": rec.get("promoted_at"),
                "source_date": rec.get("source_manifest_id"),
            })
        return out

    # Temporarily point nodes._LEARNED_RULES_PATH at our configured store so
    # the embedded blocks inside _plan_system_prompt / _build_extract_prompt
    # reflect the same rules the UI displays in `appended_block`. The lock
    # makes the swap+render+restore atomic across concurrent requests.
    _RENDER_LIVE_PROMPTS_LOCK.acquire()
    _orig_rules_path = nodes._LEARNED_RULES_PATH
    nodes._LEARNED_RULES_PATH = LEARNED_RULES_PATH
    try:
        interp_block = nodes._render_learned_block(
            live_rules.get("counter_rule", []), "Learned counter-rules"
        )
        interp_prompt = {
            "agent": "INTERPRET",
            "rendered_with": {"context": "verbatim, no args needed"},
            "base_before": nodes.INTERPRET_SYSTEM_PROMPT,
            "appended_block": interp_block or "",
            "base_after": "",
            "appended_rules": _entries_for("counter_rule"),
        }

        extract_full = nodes._build_extract_prompt(
            _CANONICAL_EXTRACT_ARGS["host_type"],
            _CANONICAL_EXTRACT_ARGS["host_description"],
            _CANONICAL_EXTRACT_ARGS["has_memory"],
            has_disk=_CANONICAL_EXTRACT_ARGS["has_disk"],
        )
        # Header literal mirrors nodes._build_extract_prompt at nodes.py:1126.
        extract_block = nodes._render_learned_block(
            live_rules.get("extract_location", []), "Learned extract locations"
        )
        if extract_block and extract_block in extract_full:
            ext_parts = extract_full.split(extract_block, 1)
            ext_before, ext_after = ext_parts[0], ext_parts[1]
        else:
            # Either no rules (block is empty) or the header literal failed
            # to match. Fall back to base_before=full so the UI still renders
            # the prompt; the appended_block (possibly empty) is shown at the
            # bottom, matching the old EXTRACT behavior but rendered once.
            ext_before, ext_after = extract_full, ""
        extract_prompt = {
            "agent": "EXTRACT",
            "rendered_with": dict(_CANONICAL_EXTRACT_ARGS),
            "base_before": ext_before,
            "appended_block": extract_block or "",
            "base_after": ext_after,
            "appended_rules": _entries_for("extract_location"),
        }

        plan_full = nodes._plan_system_prompt(
            case_id=_CANONICAL_PLAN_ARGS["case_id"],
            e01_path=_CANONICAL_PLAN_ARGS["e01_path"],
            memory_image_path=_CANONICAL_PLAN_ARGS["memory_image_path"],
            memory_profile=_CANONICAL_PLAN_ARGS["memory_profile"],
        )
        plan_block = nodes._render_learned_block(
            live_rules.get("planner_hint", []), "Learned planner hints"
        )
        if plan_block and plan_block in plan_full:
            plan_parts = plan_full.split(plan_block, 1)
            plan_before, plan_after = plan_parts[0], plan_parts[1]
        else:
            plan_before, plan_after = plan_full, ""
        plan_prompt = {
            "agent": "PLAN",
            "rendered_with": dict(_CANONICAL_PLAN_ARGS),
            "base_before": plan_before,
            "appended_block": plan_block or "",
            "base_after": plan_after,
            "appended_rules": _entries_for("planner_hint"),
        }
    finally:
        nodes._LEARNED_RULES_PATH = _orig_rules_path
        _RENDER_LIVE_PROMPTS_LOCK.release()

    return [interp_prompt, extract_prompt, plan_prompt]


@app.get("/api/live-prompts")
def live_prompts() -> JSONResponse:
    try:
        prompts = _render_live_prompts()
    except Exception as e:
        print(f"ERROR /api/live-prompts: {e!r}", flush=True)
        raise HTTPException(status_code=500, detail="could not render live prompts; see server logs")
    return JSONResponse({"prompts": prompts})


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
    _append_audit_best_effort({**record, "action": "reject", "date": body.date})
    return JSONResponse({"ok": True})


# ── promote-rule endpoint ────────────────────────────────────────────────────

class _PromoteBody(BaseModel):
    date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    rule_id: str = Field(min_length=1, max_length=200)


_ALLOWED_RULE_KINDS = ("counter_rule", "extract_location", "planner_hint")


def _normalize_rule_text(text: str) -> str:
    return " ".join((text or "").lower().split())


def _promote_rule_inline(date: str, rule_id: str) -> dict:
    """Promote a single staged rule by appending it to the live store.
    Self-contained: no subprocess to scripts/regression_gate.py because that
    path is not mounted into the sift-sentinel container. Returns the appended
    rule dict on success or raises HTTPException on a contract violation.
    """
    staged = _read_jsonl(LOOP_RUNS_DIR / date / "learned_rules.staged.jsonl")
    match = next((r for r in staged if r.get("id") == rule_id), None)
    if match is None:
        raise HTTPException(status_code=400, detail=f"rule_id {rule_id!r} not in staged file for {date}")
    if match.get("rule_kind") not in _ALLOWED_RULE_KINDS:
        raise HTTPException(status_code=400, detail=f"rule_kind {match.get('rule_kind')!r} not in allowlist")
    if not (match.get("rule_text") or "").strip():
        raise HTTPException(status_code=400, detail="rule_text empty; refuse to promote")
    live = _read_jsonl(LEARNED_RULES_PATH)
    live_keys = {(r.get("rule_kind"), _normalize_rule_text(r.get("rule_text") or "")) for r in live}
    new_key = (match.get("rule_kind"), _normalize_rule_text(match.get("rule_text") or ""))
    if new_key in live_keys:
        raise HTTPException(status_code=409, detail="rule already promoted (dedup)")
    promoted = dict(match)
    promoted["promoted_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    promoted["promote_count"] = int(match.get("promote_count") or 0) + 1
    LEARNED_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LEARNED_RULES_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(promoted) + "\n")
    return promoted


@app.post("/api/promote-rule")
def promote_rule(body: _PromoteBody, request: Request) -> JSONResponse:
    """Promote a single staged rule into the live learned_rules.jsonl. The
    next cron run picks it up automatically. Reversible by editing the live
    file and committing.
    """
    date_dir = LOOP_RUNS_DIR / body.date
    if not date_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"no run for date {body.date}")
    promoted = _promote_rule_inline(body.date, body.rule_id)
    _append_audit_best_effort({
        "rule_id": body.rule_id,
        "date": body.date,
        "action": "promote",
        "promoted_at": promoted["promoted_at"],
        "source_ip": request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown"),
    })
    return JSONResponse({"ok": True, "promoted": promoted})


def _append_audit_best_effort(record: dict) -> None:
    """Append to LOOP_RUNS_DIR/promotions.audit.jsonl if the path is writable.
    Audit failure must NOT 500 the user-facing call; the user-visible action
    (the promote or reject) already landed by the time we reach here. Silently
    log to stderr if the audit path cannot be written.
    """
    audit_path = LOOP_RUNS_DIR / "promotions.audit.jsonl"
    try:
        with audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError as e:
        print(f"WARN audit write failed for {audit_path}: {e}", flush=True)


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
