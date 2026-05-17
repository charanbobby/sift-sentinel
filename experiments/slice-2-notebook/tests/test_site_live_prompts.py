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


def test_live_prompts_500_on_render_failure(site_client, monkeypatch):
    from pipeline import site
    def boom():
        raise RuntimeError("synthetic failure for test")
    monkeypatch.setattr(site, "_render_live_prompts", boom)
    r = site_client.get("/api/live-prompts")
    assert r.status_code == 500
    assert "see server logs" in r.json()["detail"]
