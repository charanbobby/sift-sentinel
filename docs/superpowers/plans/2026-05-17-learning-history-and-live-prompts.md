# Learning History + Live Prompts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two read-only surfaces to the Today's run dashboard: a "View live agent prompts" modal that proves promoted rules actually land in the agent system prompts, and a "Learning history" horizontal date strip that shows per-day HIT/MISS counts plus what was promoted or rejected, so the user can scan trend and approval history at a glance.

**Architecture:** Two new FastAPI endpoints in `pipeline/site.py` (`/api/history` and `/api/live-prompts`) that read existing on-disk artifacts (`LOOP_RUNS_DIR/{date}/score_*.json`, `promotions.audit.jsonl`, `learned_rules.staged.jsonl`, `learned_rules.rejected.jsonl`, live `learned_rules.jsonl`) and call existing prompt helpers in `pipeline/nodes.py` (`_load_learned_rules`, `_format_learned_rules_block`, `INTERPRET_SYSTEM_PROMPT`, `_build_extract_prompt`, `_plan_system_prompt`). Two new HTML sections on `dashboard.html` consume the endpoints. No new persistent state, no LLM calls.

**Tech Stack:** Python 3.12, FastAPI, pytest with `fastapi.testclient.TestClient`, vanilla HTML/CSS/JS (no framework). All work happens inside the sift-sentinel container at `/workspace/...` paths.

**Spec reference:** `docs/superpowers/specs/2026-05-17-learning-history-and-live-prompts-design.md`

---

## File Structure

**Modify:**
- `experiments/slice-2-notebook/pipeline/site.py`: add `_read_score`, `_history_for_date`, `_compute_trend`, `_render_live_prompts` helpers and two endpoint handlers.
- `experiments/slice-2-notebook/site/dashboard.html`: add "What sentinel has learned" section under the existing "Drafted rules awaiting review" section. Pure additions; no removals.

**Create:**
- `experiments/slice-2-notebook/tests/test_site_history.py`: unit tests for `/api/history`.
- `experiments/slice-2-notebook/tests/test_site_live_prompts.py`: unit tests for `/api/live-prompts`.

The two new endpoint handlers stay in `site.py` (file is only 556 lines today). Helpers are private (`_`-prefixed) so the public surface stays small.

---

## Task 1: Add `_read_score` and `/api/history` happy-path

**Files:**
- Modify: `experiments/slice-2-notebook/pipeline/site.py` (insert after line 236, before `# ── reject-rule endpoint`)
- Create: `experiments/slice-2-notebook/tests/test_site_history.py`

- [ ] **Step 1: Create test file with happy-path fixture**

Create `experiments/slice-2-notebook/tests/test_site_history.py`:

```python
"""Tests for GET /api/history on pipeline/site.py."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def tmp_loop_runs_history(tmp_path: Path) -> Path:
    loop_runs = tmp_path / "loop_runs"
    # date with score + audit + staged
    d1 = loop_runs / "2026-05-09"
    d1.mkdir(parents=True)
    (d1 / "score_2026-05-09.json").write_text(json.dumps({
        "per_artifact": [
            {"id": "a1", "status": "HIT"},
            {"id": "a2", "status": "HIT"},
            {"id": "a3", "status": "MISS"},
        ]
    }), encoding="utf-8")
    (d1 / "learned_rules.staged.jsonl").write_text(json.dumps({
        "id": "r_05_09_x", "rule_kind": "counter_rule",
        "rule_text": "Flag X.", "rationale": "x missed",
        "generated_at": "2026-05-09T10:00:00+00:00",
    }) + "\n", encoding="utf-8")

    # date with promote audit row
    d2 = loop_runs / "2026-05-08"
    d2.mkdir(parents=True)
    (d2 / "score_2026-05-08.json").write_text(json.dumps({
        "per_artifact": [{"id": "b1", "status": "HIT"}]
    }), encoding="utf-8")
    (d2 / "learned_rules.staged.jsonl").write_text(json.dumps({
        "id": "r_05_08_y", "rule_kind": "extract_location",
        "rule_text": "Scan C:\\foo.", "rationale": "foo missed",
        "generated_at": "2026-05-08T10:00:00+00:00",
    }) + "\n", encoding="utf-8")

    # cross-date audit log
    (loop_runs / "promotions.audit.jsonl").write_text(
        json.dumps({"action": "promote", "rule_id": "r_05_08_y",
                    "date": "2026-05-08", "promoted_at": "2026-05-08T11:00:00+00:00"}) + "\n" +
        json.dumps({"action": "reject", "rule_id": "r_05_09_x",
                    "date": "2026-05-09", "reason": "duplicate of R_03",
                    "rejected_at": "2026-05-09T12:00:00+00:00"}) + "\n",
        encoding="utf-8",
    )
    return loop_runs


@pytest.fixture
def tmp_live_rules(tmp_path: Path) -> Path:
    p = tmp_path / "learned_rules.jsonl"
    p.write_text("", encoding="utf-8")
    return p


@pytest.fixture
def site_client(tmp_loop_runs_history: Path, tmp_live_rules: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LOOP_RUNS_DIR", str(tmp_loop_runs_history))
    monkeypatch.setenv("LEARNED_RULES_PATH", str(tmp_live_rules))
    monkeypatch.setenv("SITE_HTML", str(tmp_path / "index.html"))
    (tmp_path / "index.html").write_text("<html></html>", encoding="utf-8")
    monkeypatch.setenv("SUBMISSIONS_PATH", str(tmp_path / "submissions.jsonl"))
    if "pipeline.site" in sys.modules:
        del sys.modules["pipeline.site"]
    import pipeline as _p
    if hasattr(_p, "site"):
        delattr(_p, "site")
    from pipeline import site
    return TestClient(site.app)


def test_history_returns_runs_newest_first(site_client):
    r = site_client.get("/api/history")
    assert r.status_code == 200
    body = r.json()
    assert "runs" in body
    assert [run["date"] for run in body["runs"]] == ["2026-05-09", "2026-05-08"]


def test_history_score_counts(site_client):
    r = site_client.get("/api/history")
    body = r.json()
    by_date = {run["date"]: run for run in body["runs"]}
    assert by_date["2026-05-09"]["score"] == {"hit": 2, "miss": 1, "partial": 0, "total": 3}
    assert by_date["2026-05-08"]["score"] == {"hit": 1, "miss": 0, "partial": 0, "total": 1}


def test_history_joins_audit_with_staged(site_client):
    r = site_client.get("/api/history")
    body = r.json()
    by_date = {run["date"]: run for run in body["runs"]}
    assert len(by_date["2026-05-08"]["promoted"]) == 1
    assert by_date["2026-05-08"]["promoted"][0]["rule_id"] == "r_05_08_y"
    assert by_date["2026-05-08"]["promoted"][0]["rule_text"] == "Scan C:\\foo."
    assert by_date["2026-05-08"]["promoted"][0]["rule_kind"] == "extract_location"
    assert len(by_date["2026-05-09"]["rejected"]) == 1
    assert by_date["2026-05-09"]["rejected"][0]["reason"] == "duplicate of R_03"
```

- [ ] **Step 2: Run test, expect FAIL**

Run inside the container:

```bash
docker exec sift-sentinel /workspace/.venv/bin/python -m pytest \
    /workspace/tests/test_site_history.py::test_history_returns_runs_newest_first -v
```

Expected: 404 from `TestClient.get("/api/history")` because the endpoint does not exist yet.

- [ ] **Step 3: Add helpers + endpoint to `site.py`**

Insert immediately after the `/api/proposed-rules` endpoint block in `pipeline/site.py` (after line 272, before `# ── reject-rule endpoint`):

```python
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
        elif status == "MISS":
            counts["miss"] += 1
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
            promoted_entry_reason = (rejected_by_id.get(rid) or {}).get("reason") or row.get("reason")
            rejected.append({
                "rule_id": rid,
                "rule_kind": rule_kind,
                "rule_text": rule_text,
                "reason": promoted_entry_reason,
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
    scored = [r for r in runs if r.get("score") and r["score"]["total"] > 0]
    if len(scored) < 5:
        return {"hit_rate_last_7": None, "delta_vs_prior_7": None, "has_enough_data": False}
    def rate(rows: list[dict]) -> float:
        h = sum(r["score"]["hit"] for r in rows)
        t = sum(r["score"]["total"] for r in rows)
        return (h / t) if t else 0.0
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
```

- [ ] **Step 4: Run all three Task-1 tests, expect PASS**

```bash
docker exec sift-sentinel /workspace/.venv/bin/python -m pytest \
    /workspace/tests/test_site_history.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add experiments/slice-2-notebook/pipeline/site.py experiments/slice-2-notebook/tests/test_site_history.py
git commit -m "site: GET /api/history returns per-date score + promote/reject rows"
```

---

## Task 2: `/api/history` edge cases (missing score, missing staged, no audit, trend)

**Files:**
- Modify: `experiments/slice-2-notebook/tests/test_site_history.py` (append tests)

- [ ] **Step 1: Add edge-case tests**

Append to `test_site_history.py`:

```python
def test_history_missing_score(site_client, tmp_loop_runs_history):
    # Make a third date with NO score file
    d3 = tmp_loop_runs_history / "2026-05-07"
    d3.mkdir()
    (d3 / "learned_rules.staged.jsonl").write_text("", encoding="utf-8")
    r = site_client.get("/api/history")
    body = r.json()
    by_date = {run["date"]: run for run in body["runs"]}
    assert by_date["2026-05-07"]["score"] is None
    assert by_date["2026-05-07"]["promoted"] == []
    assert by_date["2026-05-07"]["rejected"] == []


def test_history_audit_references_missing_staged(site_client, tmp_loop_runs_history):
    # Add an audit row whose rule_id is not in the staged file for that date
    audit_path = tmp_loop_runs_history / "promotions.audit.jsonl"
    with audit_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"action": "promote", "rule_id": "ghost_id",
                             "date": "2026-05-09",
                             "promoted_at": "2026-05-09T13:00:00+00:00"}) + "\n")
    r = site_client.get("/api/history")
    body = r.json()
    by_date = {run["date"]: run for run in body["runs"]}
    ghost = [p for p in by_date["2026-05-09"]["promoted"] if p["rule_id"] == "ghost_id"]
    assert len(ghost) == 1
    assert ghost[0]["rule_text"] is None
    assert ghost[0]["rule_kind"] is None


def test_history_no_audit_file(site_client, tmp_loop_runs_history):
    (tmp_loop_runs_history / "promotions.audit.jsonl").unlink()
    r = site_client.get("/api/history")
    body = r.json()
    by_date = {run["date"]: run for run in body["runs"]}
    assert by_date["2026-05-09"]["promoted"] == []
    assert by_date["2026-05-09"]["rejected"] == []


def test_history_trend_not_enough_data(site_client):
    r = site_client.get("/api/history")
    body = r.json()
    assert body["trend"]["has_enough_data"] is False
    assert body["trend"]["hit_rate_last_7"] is None


def test_history_trend_with_eight_dates(tmp_path: Path, monkeypatch):
    loop_runs = tmp_path / "loop_runs"
    for i, date in enumerate([
        "2026-05-14", "2026-05-13", "2026-05-12", "2026-05-11",
        "2026-05-10", "2026-05-09", "2026-05-08", "2026-05-07",
    ]):
        d = loop_runs / date
        d.mkdir(parents=True)
        # last 7 get HIT 7/10, prior 1 gets HIT 4/10
        hits = 7 if i < 7 else 4
        (d / f"score_{date}.json").write_text(json.dumps({
            "per_artifact": [{"id": f"x{j}", "status": "HIT" if j < hits else "MISS"} for j in range(10)]
        }), encoding="utf-8")
    live = tmp_path / "learned_rules.jsonl"
    live.write_text("", encoding="utf-8")
    monkeypatch.setenv("LOOP_RUNS_DIR", str(loop_runs))
    monkeypatch.setenv("LEARNED_RULES_PATH", str(live))
    monkeypatch.setenv("SITE_HTML", str(tmp_path / "index.html"))
    (tmp_path / "index.html").write_text("<html></html>", encoding="utf-8")
    monkeypatch.setenv("SUBMISSIONS_PATH", str(tmp_path / "submissions.jsonl"))
    if "pipeline.site" in sys.modules:
        del sys.modules["pipeline.site"]
    import pipeline as _p
    if hasattr(_p, "site"):
        delattr(_p, "site")
    from pipeline import site
    client = TestClient(site.app)
    body = client.get("/api/history").json()
    assert body["trend"]["has_enough_data"] is True
    assert body["trend"]["hit_rate_last_7"] == 0.7
    assert body["trend"]["delta_vs_prior_7"] == 0.3
```

- [ ] **Step 2: Run all Task-2 tests, expect PASS (no implementation changes needed if Task 1 was complete)**

```bash
docker exec sift-sentinel /workspace/.venv/bin/python -m pytest \
    /workspace/tests/test_site_history.py -v
```

Expected: 8 passed total (3 from Task 1 + 5 new).

If any fail, fix in `site.py` and re-run before committing.

- [ ] **Step 3: Commit**

```bash
git add experiments/slice-2-notebook/tests/test_site_history.py
git commit -m "site: /api/history handles missing score, ghost rule_id, no audit, trend"
```

---

## Task 3: `/api/live-prompts` endpoint

**Files:**
- Modify: `experiments/slice-2-notebook/pipeline/site.py` (insert after the `/api/history` block)
- Create: `experiments/slice-2-notebook/tests/test_site_live_prompts.py`

- [ ] **Step 1: Write failing test**

Create `experiments/slice-2-notebook/tests/test_site_live_prompts.py`:

```python
"""Tests for GET /api/live-prompts on pipeline/site.py."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def tmp_live_rules_seeded(tmp_path: Path) -> Path:
    p = tmp_path / "learned_rules.jsonl"
    rules = [
        {"id": "r1", "rule_kind": "counter_rule",
         "rule_text": "Flag X as malicious.",
         "promoted_at": "2026-05-03T11:55:22+00:00",
         "source_manifest_id": "2026-05-02"},
        {"id": "r2", "rule_kind": "extract_location",
         "rule_text": "Scan C:\\opt for foo.",
         "promoted_at": "2026-05-03T11:55:22+00:00",
         "source_manifest_id": "2026-05-02"},
        {"id": "r3", "rule_kind": "planner_hint",
         "rule_text": "Enumerate scheduled tasks first.",
         "promoted_at": "2026-05-03T11:55:22+00:00",
         "source_manifest_id": "2026-05-02"},
    ]
    p.write_text("\n".join(json.dumps(r) for r in rules) + "\n", encoding="utf-8")
    return p


@pytest.fixture
def site_client(tmp_live_rules_seeded: Path, tmp_path: Path, monkeypatch):
    loop_runs = tmp_path / "loop_runs"
    loop_runs.mkdir()
    monkeypatch.setenv("LOOP_RUNS_DIR", str(loop_runs))
    monkeypatch.setenv("LEARNED_RULES_PATH", str(tmp_live_rules_seeded))
    monkeypatch.setenv("SITE_HTML", str(tmp_path / "index.html"))
    (tmp_path / "index.html").write_text("<html></html>", encoding="utf-8")
    monkeypatch.setenv("SUBMISSIONS_PATH", str(tmp_path / "submissions.jsonl"))
    if "pipeline.site" in sys.modules:
        del sys.modules["pipeline.site"]
    import pipeline as _p
    if hasattr(_p, "site"):
        delattr(_p, "site")
    from pipeline import site
    return TestClient(site.app)


def test_live_prompts_returns_three_agents(site_client):
    r = site_client.get("/api/live-prompts")
    assert r.status_code == 200
    body = r.json()
    assert [p["agent"] for p in body["prompts"]] == ["INTERPRET", "EXTRACT", "PLAN"]


def test_live_prompts_appends_counter_rule_to_interpret(site_client):
    body = site_client.get("/api/live-prompts").json()
    by_agent = {p["agent"]: p for p in body["prompts"]}
    interp = by_agent["INTERPRET"]
    assert "Flag X as malicious." in interp["appended_block"]
    assert any(r["rule_id"] == "r1" for r in interp["appended_rules"])


def test_live_prompts_extract_uses_canonical_args(site_client):
    body = site_client.get("/api/live-prompts").json()
    by_agent = {p["agent"]: p for p in body["prompts"]}
    extract = by_agent["EXTRACT"]
    assert extract["rendered_with"]["host_type"] == "windows-workstation"
    assert extract["rendered_with"]["has_disk"] is True
    assert "Scan C:\\opt for foo." in extract["appended_block"]


def test_live_prompts_plan_has_planner_hint(site_client):
    body = site_client.get("/api/live-prompts").json()
    by_agent = {p["agent"]: p for p in body["prompts"]}
    plan = by_agent["PLAN"]
    assert "Enumerate scheduled tasks first." in plan["appended_block"]


def test_live_prompts_empty_store(tmp_path: Path, monkeypatch):
    empty_live = tmp_path / "learned_rules.jsonl"
    empty_live.write_text("", encoding="utf-8")
    monkeypatch.setenv("LOOP_RUNS_DIR", str(tmp_path / "loop_runs"))
    (tmp_path / "loop_runs").mkdir()
    monkeypatch.setenv("LEARNED_RULES_PATH", str(empty_live))
    monkeypatch.setenv("SITE_HTML", str(tmp_path / "index.html"))
    (tmp_path / "index.html").write_text("<html></html>", encoding="utf-8")
    monkeypatch.setenv("SUBMISSIONS_PATH", str(tmp_path / "submissions.jsonl"))
    if "pipeline.site" in sys.modules:
        del sys.modules["pipeline.site"]
    import pipeline as _p
    if hasattr(_p, "site"):
        delattr(_p, "site")
    from pipeline import site
    client = TestClient(site.app)
    body = client.get("/api/live-prompts").json()
    for p in body["prompts"]:
        assert p["appended_rules"] == []
        assert p["appended_block"] in ("", None)
```

- [ ] **Step 2: Run test, expect FAIL**

```bash
docker exec sift-sentinel /workspace/.venv/bin/python -m pytest \
    /workspace/tests/test_site_live_prompts.py::test_live_prompts_returns_three_agents -v
```

Expected: 404 (endpoint not yet defined).

- [ ] **Step 3: Add endpoint to `site.py`**

Insert after the `/api/history` block in `pipeline/site.py`:

```python
# ── live-prompts endpoint ────────────────────────────────────────────────────

_CANONICAL_EXTRACT_ARGS = {
    "host_type": "windows-workstation",
    "host_description": "Canonical Windows workstation for display only; the rules block is identical to what the agent sees at runtime.",
    "has_memory": True,
    "has_disk": True,
}


def _render_live_prompts() -> list[dict]:
    """Render INTERPRET, EXTRACT, PLAN system prompts with promoted rules
    spliced in. Returns the list-of-dicts the endpoint serializes.
    """
    from pipeline import nodes  # imported lazily so test envs without the pipeline still load site

    live_rules = nodes._load_learned_rules(LEARNED_RULES_PATH)

    def _entries_for(kind: str) -> list[dict]:
        """Match live-store rules of a kind to {rule_id, rule_text, promoted_at, source_date}.
        We re-read the live store here because _load_learned_rules drops metadata.
        """
        out = []
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

    # INTERPRET: static base + counter_rule block
    interp_block = nodes._format_learned_rules_block(
        live_rules.get("counter_rule", []), header="Counter-rules"
    )
    interp_prompt = {
        "agent": "INTERPRET",
        "rendered_with": {"context": "verbatim, no args needed"},
        "base_text": nodes.INTERPRET_SYSTEM_PROMPT,
        "appended_block": interp_block or "",
        "appended_rules": _entries_for("counter_rule"),
    }

    # EXTRACT: dynamic builder + extract_location block
    extract_full = nodes._build_extract_prompt(
        _CANONICAL_EXTRACT_ARGS["host_type"],
        _CANONICAL_EXTRACT_ARGS["host_description"],
        _CANONICAL_EXTRACT_ARGS["has_memory"],
        has_disk=_CANONICAL_EXTRACT_ARGS["has_disk"],
    )
    extract_block = nodes._format_learned_rules_block(
        live_rules.get("extract_location", []), header="Learned extract locations"
    )
    extract_base = extract_full[: -len(extract_block)] if (extract_block and extract_full.endswith(extract_block)) else extract_full
    extract_prompt = {
        "agent": "EXTRACT",
        "rendered_with": dict(_CANONICAL_EXTRACT_ARGS),
        "base_text": extract_base,
        "appended_block": extract_block or "",
        "appended_rules": _entries_for("extract_location"),
    }

    # PLAN: dynamic builder + planner_hint block
    plan_full = nodes._plan_system_prompt()
    plan_block = nodes._format_learned_rules_block(
        live_rules.get("planner_hint", []), header="Planner hints"
    )
    plan_base = plan_full[: -len(plan_block)] if (plan_block and plan_full.endswith(plan_block)) else plan_full
    plan_prompt = {
        "agent": "PLAN",
        "rendered_with": {"context": "canonical defaults"},
        "base_text": plan_base,
        "appended_block": plan_block or "",
        "appended_rules": _entries_for("planner_hint"),
    }

    return [interp_prompt, extract_prompt, plan_prompt]


@app.get("/api/live-prompts")
def live_prompts() -> JSONResponse:
    try:
        prompts = _render_live_prompts()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"could not render live prompts: {e!r}")
    return JSONResponse({"prompts": prompts})
```

Note: `nodes._plan_system_prompt` may require positional arguments. Probe its signature inside the container before writing the call:

```bash
docker exec sift-sentinel /workspace/.venv/bin/python -c \
    "import inspect, pipeline.nodes as n; print(inspect.signature(n._plan_system_prompt))"
```

If it requires args, pass canonical defaults (`question="<canonical question>"`, etc.) and add the resolved arg dict to the `rendered_with` field for PLAN.

- [ ] **Step 4: Run all Task-3 tests, expect PASS**

```bash
docker exec sift-sentinel /workspace/.venv/bin/python -m pytest \
    /workspace/tests/test_site_live_prompts.py -v
```

Expected: 5 passed.

If `nodes._format_learned_rules_block` is not the actual symbol name in `nodes.py`, run:

```bash
docker exec sift-sentinel /workspace/.venv/bin/python -c \
    "import pipeline.nodes as n; print([s for s in dir(n) if 'rules' in s.lower() or 'format' in s.lower()])"
```

Adjust the import names in `_render_live_prompts` accordingly.

- [ ] **Step 5: Commit**

```bash
git add experiments/slice-2-notebook/pipeline/site.py experiments/slice-2-notebook/tests/test_site_live_prompts.py
git commit -m "site: GET /api/live-prompts renders INTERPRET/EXTRACT/PLAN with promoted-rule blocks"
```

---

## Task 4: Live-prompts modal UI

**Files:**
- Modify: `experiments/slice-2-notebook/site/dashboard.html`

- [ ] **Step 1: Probe current section structure to find insertion point**

```bash
grep -n "Drafted rules\|<section\|</main>" experiments/slice-2-notebook/site/dashboard.html | head -20
```

Note the line where the "Drafted rules awaiting review" section closes. The new section goes immediately after.

- [ ] **Step 2: Add new section markup after the Drafted-rules section**

Insert after the closing `</section>` of the Drafted-rules section:

```html
<section id="learnings-section">
  <h2>What sentinel has learned</h2>
  <p class="caption">Two views into the rules you have approved over time: a live view of what is in each agent's system prompt right now, and a per-day history of what got promoted or rejected.</p>

  <div style="margin: 12px 0 20px;">
    <button id="open-live-prompts-btn" class="primary-btn"
            style="background: var(--accent); color: var(--bg); border: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; font-size: 13px; cursor: pointer;">
      View live agent prompts
    </button>
  </div>

  <h3 style="font-size: 16px; margin: 20px 0 8px;">Learning history</h3>
  <p class="caption" style="margin: 0 0 12px;">Each card is one nightly loop-run. Numbers show how well sentinel scored on the day's planted artifacts and what rules you promoted or rejected on that date.</p>
  <div id="history-trend" class="caption" style="margin: 0 0 12px; font-style: italic;"></div>
  <div id="history-strip" style="display: flex; gap: 12px; overflow-x: auto; padding-bottom: 8px;"></div>
</section>

<div id="live-prompts-modal" style="display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6); z-index: 200; padding: 40px;">
  <div style="background: var(--surface); border: 1px solid var(--line); border-radius: 10px; max-width: 980px; margin: 0 auto; max-height: 90vh; overflow: hidden; display: flex; flex-direction: column;">
    <div style="padding: 16px 20px; border-bottom: 1px solid var(--line); display: flex; justify-content: space-between; align-items: center;">
      <h3 style="margin: 0;">Live agent prompts</h3>
      <button onclick="closeLivePromptsModal()" style="background: transparent; color: var(--muted); border: 1px solid var(--line); border-radius: 6px; padding: 4px 12px; cursor: pointer;">close</button>
    </div>
    <div id="live-prompts-tabs" style="padding: 12px 20px 0; display: flex; gap: 8px; border-bottom: 1px solid var(--line);"></div>
    <div id="live-prompts-body" style="padding: 20px; overflow-y: auto;"></div>
  </div>
</div>
```

- [ ] **Step 3: Add JS for the live-prompts modal**

Add inside the existing `<script>` block at the bottom of the file (next to the existing `openApproveModal` / `confirmPromote` functions):

```javascript
let _livePromptsCache = null;

document.getElementById('open-live-prompts-btn').addEventListener('click', async () => {
  const modal = document.getElementById('live-prompts-modal');
  modal.style.display = 'block';
  if (_livePromptsCache === null) {
    try {
      const r = await fetch('/api/live-prompts');
      if (!r.ok) {
        const detail = (await r.json()).detail || r.statusText;
        document.getElementById('live-prompts-body').innerHTML =
          `<div style="color: var(--red);">Could not render live prompts: ${detail}</div>`;
        return;
      }
      _livePromptsCache = (await r.json()).prompts;
    } catch (e) {
      document.getElementById('live-prompts-body').innerHTML =
        `<div style="color: var(--red);">Network error: ${e.message}</div>`;
      return;
    }
  }
  renderLivePromptsTabs(_livePromptsCache, 'INTERPRET');
});

function closeLivePromptsModal() {
  document.getElementById('live-prompts-modal').style.display = 'none';
}

function renderLivePromptsTabs(prompts, activeAgent) {
  const tabsEl = document.getElementById('live-prompts-tabs');
  tabsEl.innerHTML = prompts.map(p => `
    <button onclick="renderLivePromptsTabs(_livePromptsCache, '${p.agent}')"
            style="background: ${p.agent === activeAgent ? 'var(--accent-soft)' : 'transparent'};
                   color: ${p.agent === activeAgent ? 'var(--accent)' : 'var(--muted)'};
                   border: none; padding: 8px 14px; border-radius: 6px 6px 0 0;
                   font-weight: 600; font-size: 13px; cursor: pointer; border-bottom: ${p.agent === activeAgent ? '2px solid var(--accent)' : 'none'};">
      ${p.agent} (${p.appended_rules.length})
    </button>
  `).join('');
  const active = prompts.find(p => p.agent === activeAgent);
  const rwLines = Object.entries(active.rendered_with).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', ');
  const chipsHtml = active.appended_rules.length === 0
    ? `<div style="color: var(--muted-2); font-size: 12px; margin-bottom: 12px;">No promoted rules of this kind yet; this is the base prompt the agent uses.</div>`
    : `<div style="margin-bottom: 12px; display: flex; flex-wrap: wrap; gap: 6px;">${
        active.appended_rules.map(r => `<span class="pill pill-blue">${escHtml(r.rule_id)} · ${escHtml(r.source_date || '?')}</span>`).join('')
      }</div>`;
  document.getElementById('live-prompts-body').innerHTML = `
    <div style="color: var(--muted-2); font-size: 11px; margin-bottom: 8px;">Rendered with ${escHtml(rwLines)}</div>
    ${chipsHtml}
    <pre class="mono" style="background: var(--surface-2); border: 1px solid var(--line-soft); border-radius: 8px; padding: 14px; font-size: 12px; line-height: 1.55; white-space: pre-wrap; word-break: break-word; max-height: 60vh; overflow-y: auto;">${escHtml(active.base_text)}<span style="background: var(--accent-soft); display: block; padding: 4px 0;">${escHtml(active.appended_block)}</span></pre>
  `;
}
```

Note: `escHtml` already exists in `dashboard.html`; reuse it.

- [ ] **Step 4: Visual smoke check in browser**

Restart the site container so the new HTML is picked up (the HTML is bind-mounted, but a hard refresh is required):

```bash
docker exec sift-sentinel pkill -f uvicorn || true
# Container restart strategy depends on the deploy; the user runs the restart.
```

Open `http://localhost:8081/site/dashboard.html` (or the deployed URL). Click "View live agent prompts." Confirm:
- Modal opens with three tabs INTERPRET / EXTRACT / PLAN with counts.
- Each tab shows the base prompt plus a tinted appended block (or the empty-state caption if no rules of that kind exist).
- "Rendered with" caption shows the canonical args.
- Close button works.

- [ ] **Step 5: Commit**

```bash
git add experiments/slice-2-notebook/site/dashboard.html
git commit -m "dashboard: View live agent prompts modal with three-tab prompt viewer"
```

---

## Task 5: Learning-history strip UI

**Files:**
- Modify: `experiments/slice-2-notebook/site/dashboard.html`

- [ ] **Step 1: Add JS to fetch and render the history strip**

Append to the same `<script>` block as Task 4:

```javascript
(async function loadHistoryStrip() {
  const stripEl = document.getElementById('history-strip');
  const trendEl = document.getElementById('history-trend');
  try {
    const r = await fetch('/api/history');
    if (!r.ok) {
      stripEl.innerHTML = `<div style="color: var(--red); font-size: 13px;">Could not load history: ${r.status}</div>`;
      return;
    }
    const body = await r.json();
    if (!body.runs || body.runs.length === 0) {
      document.getElementById('learnings-section').style.display = 'none';
      return;
    }
    // trend line
    if (body.trend && body.trend.has_enough_data) {
      const d = body.trend.delta_vs_prior_7;
      if (d === null) {
        trendEl.textContent = `HIT rate over last 7 runs: ${Math.round(body.trend.hit_rate_last_7 * 100)}%.`;
      } else if (d > 0) {
        trendEl.textContent = `HIT rate up ${Math.round(d * 100)} points vs the prior week (now ${Math.round(body.trend.hit_rate_last_7 * 100)}%).`;
      } else if (d < 0) {
        trendEl.textContent = `HIT rate down ${Math.round(-d * 100)} points vs the prior week (now ${Math.round(body.trend.hit_rate_last_7 * 100)}%).`;
      } else {
        trendEl.textContent = `HIT rate flat vs the prior week (${Math.round(body.trend.hit_rate_last_7 * 100)}%).`;
      }
    } else {
      trendEl.textContent = 'Not enough runs yet to show a trend.';
    }
    // cards
    stripEl.innerHTML = body.runs.map(renderHistoryCard).join('');
  } catch (e) {
    stripEl.innerHTML = `<div style="color: var(--red); font-size: 13px;">Network error: ${escHtml(e.message)}</div>`;
  }
})();

function renderHistoryCard(run) {
  let scoreLine;
  let scoreColor = 'var(--muted)';
  if (run.score && run.score.total > 0) {
    const pct = run.score.hit / run.score.total;
    scoreColor = pct >= 0.7 ? 'var(--green)' : (pct >= 0.4 ? 'var(--amber)' : 'var(--red)');
    scoreLine = `<div style="font-size: 18px; font-weight: 700; color: ${scoreColor};">HIT ${run.score.hit}/${run.score.total}</div>`;
  } else {
    scoreLine = `<div style="font-size: 12px; color: var(--muted-2); font-style: italic;">no scoring on this date</div>`;
  }
  const promoCount = run.promoted.length;
  const rejectCount = run.rejected.length;
  const chips = `<div style="margin: 6px 0; font-size: 12px;">
    <span style="color: var(--green);">+${promoCount}</span>
    <span style="color: var(--muted-2);"> · </span>
    <span style="color: var(--red);">-${rejectCount}</span>
  </div>`;
  const pendLine = run.pending_count > 0
    ? `<div style="font-size: 11px; color: var(--amber);">pend ${run.pending_count}</div>`
    : '';
  const detailId = `hist-detail-${run.date}`;
  return `
    <div style="flex: 0 0 160px; background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 12px;">
      <div style="font-size: 12px; color: var(--muted-2); margin-bottom: 4px;">${escHtml(run.date)}</div>
      ${scoreLine}
      ${chips}
      ${pendLine}
      <button onclick="toggleHistoryDetail('${escHtml(detailId)}', '${escHtml(run.date)}')"
              style="background: transparent; color: var(--accent); border: none; padding: 4px 0; font-size: 12px; cursor: pointer; text-align: left;">
        view ▾
      </button>
      <div id="${detailId}" style="display: none; margin-top: 8px; font-size: 11px;"></div>
    </div>`;
}

function toggleHistoryDetail(detailId, date) {
  const el = document.getElementById(detailId);
  if (el.style.display === 'none') {
    const run = (window._historyCache || []).find(r => r.date === date);
    el.innerHTML = renderHistoryDetail(run);
    el.style.display = 'block';
  } else {
    el.style.display = 'none';
  }
}

function renderHistoryDetail(run) {
  if (!run) return '';
  const kindLabel = { counter_rule: 'INTERPRET prompt', extract_location: 'EXTRACT catalog', planner_hint: 'PLAN soft rules' };
  const promotedRows = run.promoted.map(p => `
    <div style="border-left: 2px solid var(--green); padding: 6px 8px; margin: 4px 0; background: var(--green-soft);">
      <div><span class="pill pill-green">${escHtml(p.rule_kind || '?')}</span></div>
      <div style="margin-top: 4px;">${escHtml(p.rule_text || '(rule text no longer on disk)')}</div>
      <div style="color: var(--muted-2); margin-top: 4px;">landed in ${escHtml(kindLabel[p.rule_kind] || p.rule_kind || 'unknown')}</div>
    </div>`).join('');
  const rejectedRows = run.rejected.map(p => `
    <div style="border-left: 2px solid var(--muted); padding: 6px 8px; margin: 4px 0;">
      <div><span class="pill pill-neutral">${escHtml(p.rule_kind || '?')}</span></div>
      <div style="margin-top: 4px;">${escHtml(p.rule_text || '(rule text no longer on disk)')}</div>
      <div style="color: var(--muted-2); margin-top: 4px;">reason: ${escHtml(p.reason || '(no reason recorded)')}</div>
    </div>`).join('');
  if (!promotedRows && !rejectedRows) {
    return `<div style="color: var(--muted-2);">No promote or reject events on this date.</div>`;
  }
  return promotedRows + rejectedRows;
}
```

- [ ] **Step 2: Stash the history payload for detail rendering**

The detail toggle needs the full per-date payload; the strip render only displays summary. Update the IIFE so it caches the runs into `window._historyCache`:

In the `loadHistoryStrip` function, immediately before `stripEl.innerHTML = body.runs.map(...)`, add:

```javascript
    window._historyCache = body.runs;
```

- [ ] **Step 3: Visual smoke check**

Hard-refresh the dashboard in the browser. Confirm:
- "Learning history" header appears under the live-prompts button.
- Either the trend line shows a real percentage or "Not enough runs yet to show a trend."
- Strip renders one card per loop-run date with score color, +N -M chips, and a `view ▾` button.
- Clicking `view ▾` expands per-rule detail with the green/muted left-borders.

- [ ] **Step 4: Commit**

```bash
git add experiments/slice-2-notebook/site/dashboard.html
git commit -m "dashboard: Learning history strip with per-date cards and rule detail expander"
```

---

## Task 6: End-to-end container smoke test

**Files:**
- None (read-only validation)

- [ ] **Step 1: Hit both endpoints on the live container**

```bash
curl -s http://localhost:8081/api/history | python3 -m json.tool | head -40
curl -s http://localhost:8081/api/live-prompts | python3 -m json.tool | head -40
```

Expected: valid JSON for both, with `runs` (possibly empty list) and `prompts` (length 3) keys.

- [ ] **Step 2: Walk through the UI manually**

Open the deployed dashboard URL. Confirm everything from Task 4 Step 4 and Task 5 Step 3 in the live browser. If anything looks wrong, note it as a follow-up before declaring done.

- [ ] **Step 3: Run the full pytest suite to catch any regressions**

```bash
docker exec sift-sentinel /workspace/.venv/bin/python -m pytest /workspace/tests/ -v
```

Expected: all tests pass, no new failures introduced.

- [ ] **Step 4: Commit nothing (this is verification only)**

If anything broke, return to the relevant task and fix before declaring the plan complete.

---

## Self-review

**Spec coverage:**
- `/api/history` endpoint: Tasks 1-2.
- `/api/live-prompts` endpoint: Task 3.
- Live-prompts modal (Piece A): Task 4.
- Learning history strip (Piece B): Task 5.
- Edge cases (missing score, ghost rule_id, no audit, <5 runs, 0 runs, empty live store): covered by Task 2 tests and Task 5 empty-state branch.
- Smoke test: Task 6.

**Placeholder scan:** No TBDs, no "appropriate handling" without code, every code step has the literal code or command. The one conditional ("if `_format_learned_rules_block` is not the actual symbol name") gives the engineer the probe command to confirm and adjust.

**Type consistency:** Endpoint response shapes match across plan and tests. `rule_kind` strings (`counter_rule`, `extract_location`, `planner_hint`) consistent. Field names (`appended_block`, `appended_rules`, `rendered_with`, `pending_count`, `has_enough_data`) consistent between site.py code and dashboard.html JS.
