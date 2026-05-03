#!/usr/bin/env python3
"""Mark a HUMAN_REVIEW run as approved.

Touches `07_terminal.HUMAN_APPROVED` in the run dir alongside the existing
`07_terminal.HUMAN_REVIEW` marker. The viewer has HUMAN_APPROVED first in
the terminal-marker tuple, so the case will now show as approved.

Use this when a human has read the findings and decided the medium-confidence
escalations are accepted (e.g. cross-host campaign correlation, masquerading
service patterns that match a known signature).

Usage:
  python3 scripts/approve_human_review.py <case_id> [<case_id> ...]

Example:
  python3 scripts/approve_human_review.py \\
    srl-2018-base-rd-05-memonly \\
    srl-2018-base-wkstn-03-memonly \\
    srl-2018-base-wkstn-06-memonly
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
from pathlib import Path

RUNS_ROOT_DEFAULT = Path("experiments/slice-2-notebook/out/runs")


def approve_one(case_id: str, runs_root: Path, note: str | None) -> int:
    case_dir = runs_root / case_id
    latest_txt = case_dir / "latest.txt"
    if not latest_txt.exists():
        print(f"FAIL: {case_id}: no latest.txt at {latest_txt}", file=sys.stderr)
        return 2
    run_id = latest_txt.read_text(encoding="utf-8").strip()
    run_path = case_dir / run_id
    if not run_path.exists():
        print(f"FAIL: {case_id}: latest run dir {run_path} missing", file=sys.stderr)
        return 2
    review_marker = run_path / "07_terminal.HUMAN_REVIEW"
    if not review_marker.exists():
        print(f"WARN: {case_id}: no 07_terminal.HUMAN_REVIEW marker (status may already be SUCCESS or never escalated)")
    approved_marker = run_path / "07_terminal.HUMAN_APPROVED"
    if approved_marker.exists():
        print(f"  {case_id}: already approved at {run_id}")
        return 0
    approved_marker.touch()
    sidecar = run_path / "human_approval.json"
    payload = {
        "case_id": case_id,
        "run_id": run_id,
        "approved_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "approved_by": "human",
        "note": note,
        "previous_status": "HUMAN_REVIEW" if review_marker.exists() else "unknown",
    }
    import json as _json
    sidecar.write_text(_json.dumps(payload, indent=2), encoding="utf-8")
    print(f"  {case_id}: approved {run_id} (sidecar: {sidecar.relative_to(case_dir.parent.parent.parent)})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Approve HUMAN_REVIEW runs")
    ap.add_argument("case_ids", nargs="+", help="Case ids to approve")
    ap.add_argument("--runs-root", type=Path, default=RUNS_ROOT_DEFAULT,
                    help="Runs root (default: experiments/slice-2-notebook/out/runs)")
    ap.add_argument("--note", default=None,
                    help="Optional note recorded in human_approval.json")
    args = ap.parse_args()

    print(f"=== approve_human_review: {len(args.case_ids)} case(s) ===")
    fails = 0
    for cid in args.case_ids:
        if approve_one(cid, args.runs_root, args.note) != 0:
            fails += 1
    if fails:
        print(f"=== {fails} failure(s) ===", file=sys.stderr)
        return 1
    print(f"=== done ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
