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
