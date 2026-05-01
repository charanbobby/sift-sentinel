#!/usr/bin/env python3
"""Snapshot the daily-loop state.

Reads the run-lock file, formats current state, and shows recent run
history. Foundation for the Stage-4 activity-feed page; works as a
standalone CLI today so we can replace ad-hoc grep / cat invocations
during loop debugging.

Usage:
    python3 loop_status.py             # current run + last 5 scorecards
    python3 loop_status.py --history N # last N scorecards
    python3 loop_status.py --json      # machine-readable JSON output

VPS one-liner:
    ssh -i ~/.ssh/id_hetzner sri@46.62.255.66 \
        python3 /opt/find-evil/repo/experiments/synthetic-ai-workstation/loop_status.py
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from pathlib import Path


LOCK_FILE = Path("/opt/find-evil/state/active_run.json")
LOOP_RUNS = Path("/opt/find-evil/out/loop-runs")


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _parse_iso(s: str) -> datetime.datetime | None:
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _fmt_age(dt: datetime.datetime | None) -> str:
    if dt is None:
        return "unknown"
    age = (_utcnow() - dt).total_seconds()
    if age < 60:
        return f"{int(age)}s"
    if age < 3600:
        return f"{int(age // 60)}m {int(age % 60)}s"
    return f"{age / 3600:.1f}h"


def read_lock() -> dict | None:
    """Return the current lock state, or None if no active lock file.

    Annotates with derived fields: pid_alive, heartbeat_age_s, is_stale.
    """
    if not LOCK_FILE.exists():
        return None
    try:
        data = json.loads(LOCK_FILE.read_text())
    except Exception as e:
        return {"error": f"could not parse {LOCK_FILE}: {e}"}
    pid = int(data.get("pid", 0))
    hb_dt = _parse_iso(data.get("last_heartbeat_iso", ""))
    started_dt = _parse_iso(data.get("started_iso", ""))
    age_s = (_utcnow() - hb_dt).total_seconds() if hb_dt else None
    pid_alive = _pid_alive(pid)
    is_stale = (not pid_alive) or (age_s is not None and age_s > 60 * 60)
    data["_derived"] = {
        "pid_alive": pid_alive,
        "heartbeat_age_s": age_s,
        "started_age": _fmt_age(started_dt),
        "heartbeat_age": _fmt_age(hb_dt),
        "is_stale": is_stale,
    }
    return data


def list_recent_scorecards(n: int) -> list[dict]:
    """Return up to n most-recent scorecards from /opt/find-evil/out/loop-runs/.

    One scorecard per date dir; sorted newest first. Each item carries
    summary stats only (per_artifact list dropped for brevity).
    """
    if not LOOP_RUNS.exists():
        return []
    out: list[dict] = []
    for date_dir in sorted(LOOP_RUNS.iterdir(), reverse=True):
        if not date_dir.is_dir():
            continue
        for score_path in sorted(date_dir.glob("score_*.json"), reverse=True):
            if "rerun" in score_path.name or "run2" in score_path.name:
                # Multiple scorecards per day from manual reruns; keep the
                # canonical one only (without rerun/run2 in its name).
                continue
            try:
                s = json.loads(score_path.read_text())
            except Exception:
                continue
            ext = s.get("extension", {})
            reg = s.get("regression", {})
            mtime = datetime.datetime.fromtimestamp(
                score_path.stat().st_mtime, tz=datetime.timezone.utc,
            )
            out.append({
                "date": date_dir.name,
                "score_file": score_path.name,
                "manifest_id": s.get("manifest_id"),
                "extension_pass": ext.get("pass"),
                "extension_total": ext.get("total"),
                "expected_miss_pass": ext.get("expected_miss_pass", 0),
                "regression_pass": len(reg.get("pass", [])),
                "regression_total": len(reg.get("expected", [])),
                "scored_age": _fmt_age(mtime),
            })
            if len(out) >= n:
                return out
    return out


def render_text(lock: dict | None, recent: list[dict]) -> str:
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("FIND-EVIL DAILY LOOP STATUS")
    lines.append("=" * 60)
    lines.append("")
    lines.append("Current lock:")
    if lock is None:
        lines.append("  IDLE (no active run)")
    elif "error" in lock:
        lines.append(f"  ERROR: {lock['error']}")
    else:
        d = lock["_derived"]
        status = "STALE" if d["is_stale"] else "ACTIVE"
        lines.append(f"  Status:    {status}")
        lines.append(f"  Owner:     {lock.get('owner', '?')}")
        lines.append(f"  PID:       {lock.get('pid', '?')} ({'alive' if d['pid_alive'] else 'DEAD'})")
        lines.append(f"  Phase:     {lock.get('phase', '?')}")
        lines.append(f"  Started:   {lock.get('started_iso', '?')} ({d['started_age']} ago)")
        lines.append(f"  Heartbeat: {lock.get('last_heartbeat_iso', '?')} ({d['heartbeat_age']} ago)")
    lines.append("")
    lines.append(f"Recent scorecards (last {len(recent)}):")
    if not recent:
        lines.append("  (no scorecards on disk)")
    else:
        lines.append(f"  {'Date':<12} {'Manifest':<14} {'Ext':<7} {'Reg':<5} {'Scored':<10}")
        for r in recent:
            ext = f"{r.get('extension_pass', '?')}/{r.get('extension_total', '?')}"
            reg = f"{r.get('regression_pass', '?')}/{r.get('regression_total', '?')}"
            lines.append(
                f"  {r['date']:<12} {(r.get('manifest_id') or '?')[:14]:<14} "
                f"{ext:<7} {reg:<5} {r['scored_age']:<10} ago"
            )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--history", type=int, default=5,
                    help="Number of recent scorecards to show (default 5).")
    ap.add_argument("--json", action="store_true",
                    help="Emit machine-readable JSON instead of formatted text.")
    args = ap.parse_args()

    lock = read_lock()
    recent = list_recent_scorecards(args.history)

    if args.json:
        print(json.dumps({"lock": lock, "recent": recent}, indent=2))
    else:
        print(render_text(lock, recent))
    return 0


if __name__ == "__main__":
    sys.exit(main())
