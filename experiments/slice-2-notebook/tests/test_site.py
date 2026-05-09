"""Tests for pipeline/site.py endpoints introduced by the today's run redesign.

Fixtures construct a temporary LOOP_RUNS_DIR with a known staged.jsonl so the
GET /api/proposed-rules endpoint has something to read, and a temporary live
learned_rules.jsonl so promotions do not touch the real store.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def tmp_loop_runs(tmp_path: Path) -> Path:
    loop_runs = tmp_path / "loop_runs"
    date_dir = loop_runs / "2026-05-08"
    date_dir.mkdir(parents=True)
    staged = date_dir / "learned_rules.staged.jsonl"
    rules = [
        {
            "id": "rule_a-aaaa",
            "source_miss_id": "miss_a",
            "source_manifest_id": "2026-05-08",
            "rule_kind": "counter_rule",
            "rule_text": "Flag X as malicious.",
            "rationale": "Y was missed.",
            "generated_by_model": "haiku",
            "generated_by_version": "test",
            "generated_at": "2026-05-08T22:47:07+00:00",
            "regression_passed": False,
            "promote_count": 0,
        },
        {
            "id": "rule_b-bbbb",
            "source_miss_id": "miss_b",
            "source_manifest_id": "2026-05-08",
            "rule_kind": "extract_location",
            "rule_text": "Scan C:\\foo for bar.",
            "rationale": "bar was missed in foo.",
            "generated_by_model": "haiku",
            "generated_by_version": "test",
            "generated_at": "2026-05-08T22:48:25+00:00",
            "regression_passed": False,
            "promote_count": 0,
        },
    ]
    staged.write_text("\n".join(json.dumps(r) for r in rules) + "\n", encoding="utf-8")
    return loop_runs


@pytest.fixture
def tmp_live_rules(tmp_path: Path) -> Path:
    p = tmp_path / "learned_rules.jsonl"
    p.write_text("", encoding="utf-8")
    return p


@pytest.fixture
def site_client(tmp_loop_runs: Path, tmp_live_rules: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LOOP_RUNS_DIR", str(tmp_loop_runs))
    monkeypatch.setenv("LEARNED_RULES_PATH", str(tmp_live_rules))
    monkeypatch.setenv("SITE_HTML", str(tmp_path / "index.html"))
    (tmp_path / "index.html").write_text("<html></html>", encoding="utf-8")
    monkeypatch.setenv("SUBMISSIONS_PATH", str(tmp_path / "submissions.jsonl"))
    if "pipeline.site" in sys.modules:
        del sys.modules["pipeline.site"]
    from pipeline import site
    return TestClient(site.app)


def test_proposed_rules_returns_staged(site_client):
    r = site_client.get("/api/proposed-rules?date=2026-05-08")
    assert r.status_code == 200
    body = r.json()
    assert body["date"] == "2026-05-08"
    assert body["count"] == 2
    assert {x["id"] for x in body["rules"]} == {"rule_a-aaaa", "rule_b-bbbb"}
