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


def test_history_score_skips_unknown_status(tmp_path: Path, monkeypatch):
    loop_runs = tmp_path / "loop_runs"
    d = loop_runs / "2026-05-09"
    d.mkdir(parents=True)
    (d / "score_2026-05-09.json").write_text(json.dumps({
        "per_artifact": [
            {"id": "a1", "status": "HIT"},
            {"id": "a2", "status": "MISS"},
            {"id": "a3", "status": "PARTIAL"},
            {"id": "a4", "status": "BOGUS"},
        ]
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
    score = body["runs"][0]["score"]
    assert score == {"hit": 1, "miss": 1, "partial": 1, "total": 3}


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
