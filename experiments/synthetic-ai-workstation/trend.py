#!/usr/bin/env python3
"""Longitudinal trend reporter for daily synthetic-workstation runs.

Walks the loop-runs directory and collects per-day scores into a summary
table and JSON file. Run this after each daily loop to update the judge-facing
trend view.

Usage:
    python3 trend.py \
        --runs-dir /opt/find-evil/out/loop-runs \
        --out-md trend.md \
        --out-json trend.json

Or on Windows (local dev):
    python3 trend.py --runs-dir . --out-md trend.md --out-json trend.json
"""
from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path


def info(msg: str):
    print(f"[TREND] {msg}", flush=True)


def load_day(day_dir: Path) -> dict | None:
    """Load and summarise one day's run directory.
    Returns None if the directory has no usable score file."""
    score_files = sorted(day_dir.glob("score_*.json"))
    if not score_files:
        return None

    score_path = score_files[-1]
    try:
        score = json.loads(score_path.read_text())
    except Exception as e:
        info(f"  skip {day_dir.name}: score unreadable ({e})")
        return None

    # Per-artifact breakdown
    per_art = score.get("per_artifact", [])
    planted = sum(1 for r in per_art if r.get("status") in ("PASS", "MISS"))
    detected = sum(1 for r in per_art if r.get("status") == "PASS")
    missed = sum(1 for r in per_art if r.get("status") == "MISS")
    bonus = sum(1 for r in per_art if r.get("status") == "BONUS")
    expected_miss = sum(1 for r in per_art if r.get("status") == "AS-EXPECTED-MISS")
    missed_ids = [r["id"] for r in per_art if r.get("status") == "MISS"]

    # Regression
    reg = score.get("regression", {})
    reg_pass = len(reg.get("pass", []))
    reg_expected = len(reg.get("expected", []))
    reg_ok = len(reg.get("fail", [])) == 0

    # Intel sources count from manifest
    intel_count = 0
    manifest_files = sorted(day_dir.glob("manifest_*.json"))
    categories = []
    intel_sources = []
    if manifest_files:
        try:
            m = json.loads(manifest_files[-1].read_text())
            intel_sources = m.get("intel_sources", [])
            intel_count = len(intel_sources)
            categories = [c["name"] for c in m.get("categories", [])]
        except Exception:
            pass

    detection_rate = f"{detected / planted * 100:.0f}%" if planted else "n/a"

    return {
        "date": day_dir.name,
        "planted": planted,
        "detected": detected,
        "missed": missed,
        "detection_rate": detection_rate,
        "expected_miss": expected_miss,
        "bonus": bonus,
        "regression_ok": reg_ok,
        "regression_detail": f"{reg_pass}/{reg_expected}",
        "missed_ids": missed_ids,
        "categories": categories,
        "intel_sources_count": intel_count,
        "intel_sources": intel_sources,
    }


def render_markdown(rows: list[dict]) -> str:
    lines = []
    lines.append("# Synthetic workstation: daily trend")
    lines.append("")
    lines.append(f"_Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}_")
    lines.append("")
    lines.append("This table shows, for each daily run, how many attacker techniques were planted "
                 "vs. detected. The 'Missed' column names specific artifacts the pipeline did not "
                 "surface. Cross-reference with `corrections_log.md` to see what was tuned and when.")
    lines.append("")

    lines.append("| Date | Planted | Detected | Rate | Missed | Regression | Sources |")
    lines.append("|------|---------|----------|------|--------|------------|---------|")
    for r in rows:
        missed_str = ", ".join(r["missed_ids"]) if r["missed_ids"] else "-"
        reg_str = "PASS" if r["regression_ok"] else "**FAIL**"
        lines.append(
            f"| {r['date']} "
            f"| {r['planted']} "
            f"| {r['detected']} "
            f"| {r['detection_rate']} "
            f"| {missed_str} "
            f"| {reg_str} {r['regression_detail']} "
            f"| {r['intel_sources_count']} |"
        )
    lines.append("")

    lines.append("## Per-day detail")
    lines.append("")
    for r in rows:
        lines.append(f"### {r['date']}")
        lines.append(f"- Categories covered: {', '.join(r['categories']) if r['categories'] else 'n/a'}")
        if r["missed_ids"]:
            lines.append(f"- Missed artifacts: {', '.join(r['missed_ids'])}")
        if r["expected_miss"]:
            lines.append(f"- Acknowledged gaps (expected miss): {r['expected_miss']}")
        if r["bonus"]:
            lines.append(f"- Bonus detections (expected miss but pipeline found anyway): {r['bonus']}")
        if r["intel_sources"]:
            lines.append("- Intel sources:")
            for src in r["intel_sources"][:5]:
                lines.append(f"  - {src}")
            if len(r["intel_sources"]) > 5:
                lines.append(f"  - ... and {len(r['intel_sources']) - 5} more")
        lines.append("")

    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs-dir", default="/opt/find-evil/out/loop-runs",
                    help="Directory containing per-day run subfolders")
    ap.add_argument("--out-md", default=None,
                    help="Write Markdown trend table to this file")
    ap.add_argument("--out-json", default=None,
                    help="Write JSON trend data to this file")
    args = ap.parse_args()

    runs_dir = Path(args.runs_dir)
    if not runs_dir.exists():
        info(f"runs-dir not found: {runs_dir} (no runs yet)")
        return

    rows = []
    for day_dir in sorted(runs_dir.iterdir()):
        if not day_dir.is_dir():
            continue
        # Only process YYYY-MM-DD named directories
        if not (len(day_dir.name) == 10 and day_dir.name[4] == "-" and day_dir.name[7] == "-"):
            continue
        result = load_day(day_dir)
        if result:
            rows.append(result)
            info(f"  {result['date']}: {result['detected']}/{result['planted']} detected "
                 f"({result['detection_rate']}), regression={'OK' if result['regression_ok'] else 'FAIL'}")

    if not rows:
        info("no scored runs found")
        return

    info(f"found {len(rows)} scored run(s)")

    md = render_markdown(rows)

    if args.out_md:
        Path(args.out_md).write_text(md)
        info(f"Markdown written: {args.out_md}")
    else:
        print(md)

    if args.out_json:
        Path(args.out_json).write_text(json.dumps(rows, indent=2))
        info(f"JSON written: {args.out_json}")


if __name__ == "__main__":
    main()
