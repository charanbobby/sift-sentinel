"""Human-review adjudication CLI.

When a pipeline run lands in HUMAN_REVIEW or QUARANTINED, this tool lets a
human review the held findings + critic critiques and decide which to commit.
Writes 08_human_decision.json, appends a human_review_completed entry to the
integrity ledger, and renames the terminal marker to SUCCESS so the viewer
shows the run as Committed.

Usage:
    # Inspect (read-only)
    python approve_run.py --case CASE --run RUN --show

    # Accept everything held
    python approve_run.py --case CASE --run RUN --accept-all --reason "..."

    # Reject everything held (still finalizes the run; nothing is committed)
    python approve_run.py --case CASE --run RUN --reject-all --reason "..."

    # Per-finding (0-indexed, comma separated)
    python approve_run.py --case CASE --run RUN \\
        --accept 0,2 --reject 1 --reason "..."

The reviewer name defaults to the OS user; override with --reviewer.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/workspace")

from pipeline.ledger import LedgerWriter, verify_ledger
from pipeline.output_layout import (
    INTERPRET_FINDINGS,
    CRITIC_DISAGREEMENTS_JSONL,
    INTEGRITY_LEDGER_JSONL,
    TERMINAL_SUCCESS,
    TERMINAL_HUMAN_REVIEW,
    TERMINAL_QUARANTINED,
)

RUNS_ROOT = Path(os.environ.get("RUNS_ROOT", "/workspace/out/runs"))
DECISION_FILE = "08_human_decision.json"


def _parse_indices(spec: str | None, total: int) -> set[int]:
    if not spec:
        return set()
    out: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            i = int(token)
        except ValueError:
            raise SystemExit(f"--accept/--reject expects integers, got {token!r}")
        if i < 0 or i >= total:
            raise SystemExit(f"index {i} out of range (have {total} findings)")
        out.add(i)
    return out


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text("utf-8").splitlines():
        s = line.strip()
        if s:
            out.append(json.loads(s))
    return out


def _current_terminal_marker(run_dir: Path) -> Path | None:
    for name in (TERMINAL_HUMAN_REVIEW, TERMINAL_QUARANTINED, TERMINAL_SUCCESS):
        p = run_dir / name
        if p.exists():
            return p
    return None


def _print_findings(findings: list[dict], critic_events: list[dict]) -> None:
    by_index = {}
    for ev in critic_events:
        if ev.get("audit_event") != "critic_disagreement":
            continue
        idx = (ev.get("critic_critique") or {}).get("finding_index")
        if idx is not None:
            by_index[idx] = ev

    print(f"\n{len(findings)} finding(s) held for review:\n")
    for i, f in enumerate(findings):
        print(f"[{i}]  {f.get('confidence', '?').upper()}  {f.get('classification', '?')}")
        print(f"     mechanism: {f.get('mechanism', '')}")
        val = f.get("value", "")
        if len(val) > 200:
            val = val[:200] + "..."
        print(f"     value    : {val}")
        if f.get("attack_id"):
            print(f"     ATT&CK   : {f['attack_id']} {f.get('attack_name', '')}")
        ev = by_index.get(i)
        if ev:
            crit = ev.get("critic_critique") or {}
            res = ev.get("resolution") or {}
            print(f"     critic   : severity={crit.get('severity')} action={res.get('action')} strategy={res.get('strategy')}")
            failed = crit.get("rules_failed") or []
            if failed:
                print(f"     failed   : {failed}")
        else:
            print(f"     critic   : (no disagreement event)")
        print()


def _quarantine_summary(critic_events: list[dict]) -> list[dict]:
    return [e for e in critic_events if e.get("event") == "INJECTION_QUARANTINE"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--case", required=True)
    ap.add_argument("--run", required=True, help="run_id, e.g. srl-2018-base-file-003")
    ap.add_argument("--show", action="store_true", help="Print held findings + critic events and exit")
    ap.add_argument("--accept", default=None, help="Comma-separated 0-based finding indices to accept")
    ap.add_argument("--reject", default=None, help="Comma-separated 0-based finding indices to reject")
    ap.add_argument("--accept-all", action="store_true")
    ap.add_argument("--reject-all", action="store_true")
    ap.add_argument("--reason", default="", help="Free-text justification recorded in 08_human_decision.json")
    ap.add_argument("--reviewer", default=None, help="Reviewer name (defaults to $USER)")
    args = ap.parse_args()

    run_dir = RUNS_ROOT / args.case / args.run
    if not run_dir.exists():
        print(f"ERROR: run dir not found: {run_dir}", file=sys.stderr)
        return 2

    findings_path = run_dir / INTERPRET_FINDINGS
    if not findings_path.exists():
        print(f"ERROR: findings file not found: {findings_path}", file=sys.stderr)
        return 2

    findings_doc = json.loads(findings_path.read_text("utf-8"))
    findings = findings_doc.get("findings", [])
    critic_events = _read_jsonl(run_dir / CRITIC_DISAGREEMENTS_JSONL)

    if args.show:
        marker = _current_terminal_marker(run_dir)
        print(f"Run     : {args.case} / {args.run}")
        print(f"Marker  : {marker.name if marker else '(none)'}")
        qs = _quarantine_summary(critic_events)
        if qs:
            print(f"Quarantine flags: {len(qs)} (injection-guard fired)")
        _print_findings(findings, critic_events)
        return 0

    if args.accept_all and args.reject_all:
        print("ERROR: --accept-all and --reject-all are mutually exclusive", file=sys.stderr)
        return 2

    total = len(findings)
    if args.accept_all:
        accept = set(range(total))
        reject: set[int] = set()
    elif args.reject_all:
        accept = set()
        reject = set(range(total))
    else:
        accept = _parse_indices(args.accept, total)
        reject = _parse_indices(args.reject, total)

    overlap = accept & reject
    if overlap:
        print(f"ERROR: indices listed in both --accept and --reject: {sorted(overlap)}", file=sys.stderr)
        return 2

    decided = accept | reject
    undecided = set(range(total)) - decided
    if undecided:
        print(
            f"ERROR: undecided findings: {sorted(undecided)}. "
            f"Pass them via --accept / --reject, or use --accept-all / --reject-all.",
            file=sys.stderr,
        )
        return 2

    marker = _current_terminal_marker(run_dir)
    if marker is None:
        print(f"ERROR: no terminal marker in {run_dir}; run may not be finished.", file=sys.stderr)
        return 2

    decisions = []
    for i, f in enumerate(findings):
        verdict = "accept" if i in accept else "reject"
        decisions.append({
            "finding_index": i,
            "verdict": verdict,
            "classification": f.get("classification", ""),
            "mechanism": f.get("mechanism", ""),
        })

    reviewer = args.reviewer or os.environ.get("USER") or getpass.getuser()
    now = datetime.now(timezone.utc).isoformat()
    decision_doc = {
        "case_id": args.case,
        "run_id": args.run,
        "reviewed_by": reviewer,
        "reviewed_at": now,
        "prior_terminal_marker": marker.name,
        "reason": args.reason,
        "accepted_count": len(accept),
        "rejected_count": len(reject),
        "decisions": decisions,
    }

    decision_path = run_dir / DECISION_FILE
    decision_payload = json.dumps(decision_doc, indent=2, ensure_ascii=False).encode("utf-8")
    decision_sha256 = hashlib.sha256(decision_payload).hexdigest()
    decision_path.write_bytes(decision_payload)

    ledger_path = run_dir / INTEGRITY_LEDGER_JSONL
    ok, n_before, err = verify_ledger(ledger_path)
    if not ok:
        print(f"ERROR: ledger broken before append at entry {n_before}: {err}", file=sys.stderr)
        return 3
    with LedgerWriter(ledger_path, case_id=args.case) as w:
        w.append(
            event_type="human_review_completed",
            accepted=len(accept),
            rejected=len(reject),
            reviewed_by=reviewer,
            decision_sha256=decision_sha256,
            prior_marker=marker.name,
        )
    ok, n_after, err = verify_ledger(ledger_path)
    if not ok:
        print(f"ERROR: ledger broken after append at entry {n_after}: {err}", file=sys.stderr)
        return 3

    new_marker = run_dir / TERMINAL_SUCCESS
    if marker.name != TERMINAL_SUCCESS:
        marker.rename(new_marker)

    print(f"\nRun finalized: {args.case}/{args.run}")
    print(f"  prior marker     : {marker.name}")
    print(f"  new marker       : {new_marker.name}")
    print(f"  reviewer         : {reviewer}")
    print(f"  accepted         : {sorted(accept)}")
    print(f"  rejected         : {sorted(reject)}")
    print(f"  ledger entries   : {n_before} -> {n_after}")
    print(f"  decision doc     : {decision_path}")
    print(f"  decision sha256  : {decision_sha256[:16]}...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
