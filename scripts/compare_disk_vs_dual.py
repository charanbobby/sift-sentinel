#!/usr/bin/env python3
"""scripts/compare_disk_vs_dual.py

Compare findings between a host's disk-only sweep run and its dual-channel
sweep run. Surfaces:
  - Per-host counts (disk vs dual)
  - Findings present in disk-only that did NOT appear in dual (potential regression)
  - Findings present in dual that did NOT appear in disk-only (memory-channel adds)

Output: a markdown report at docs/submission/disk-vs-dual-regression-<date>.md.

Usage:
    scripts/compare_disk_vs_dual.py
    scripts/compare_disk_vs_dual.py --root experiments/slice-2-notebook/out/runs

Exit codes:
    0 = success
    1 = no host pairs found
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ROOT = REPO_ROOT / "experiments" / "slice-2-notebook" / "out" / "runs"
DEFAULT_OUT = REPO_ROOT / "docs" / "submission" / "disk-vs-dual-regression-2026-05-02.md"


@dataclass
class HostPair:
    host: str  # short host name e.g. "wkstn-05"
    disk_dir: Path
    dual_dir: Path
    disk_findings: list[dict] = field(default_factory=list)
    dual_findings: list[dict] = field(default_factory=list)


def _resolve_canonical(case_dir: Path) -> Path | None:
    latest = case_dir / "latest.txt"
    if not latest.exists():
        return None
    sub = latest.read_text(encoding="utf-8").strip()
    rd = case_dir / sub
    return rd if rd.exists() else None


def _findings_of(run_dir: Path) -> list[dict]:
    p = run_dir / "05_interpret_findings.json"
    if not p.exists():
        return []
    return json.loads(p.read_text(encoding="utf-8")).get("findings", []) or []


def find_pairs(root: Path) -> list[HostPair]:
    """For each `<root>/srl-2018-base-<host>` that has a sibling
    `<root>/srl-2018-base-<host>-dual`, return a HostPair with both canonical
    run dirs resolved.
    """
    pairs: list[HostPair] = []
    if not root.exists():
        return pairs
    for case_dir in sorted(root.iterdir()):
        if not case_dir.is_dir():
            continue
        name = case_dir.name
        if name.endswith("-dual") or "-memonly" in name:
            continue
        if not name.startswith("srl-2018-base-"):
            continue
        host = name[len("srl-2018-base-"):]
        dual_dir_name = f"{name}-dual"
        dual_case = root / dual_dir_name
        if not dual_case.exists():
            continue
        disk_canonical = _resolve_canonical(case_dir)
        dual_canonical = _resolve_canonical(dual_case)
        if disk_canonical is None or dual_canonical is None:
            continue
        pairs.append(HostPair(
            host=host,
            disk_dir=disk_canonical,
            dual_dir=dual_canonical,
            disk_findings=_findings_of(disk_canonical),
            dual_findings=_findings_of(dual_canonical),
        ))
    return pairs


def _signature(f: dict) -> str:
    """A stable string signature for a finding so we can do set-diff.

    The `value` field carries the concrete artifact path / service binary /
    connection tuple and is stable across runs; `mechanism` is freeform LLM
    prose that varies in capitalization and word choice between runs (e.g.
    "PsExec" vs "psexec") even when the underlying finding is identical. So
    the signature anchors on (classification, value) and only falls back to
    mechanism when value is missing.
    """
    cls = (f.get("classification") or "(no-class)").lower()
    val = (f.get("value") or "").strip()
    if val:
        return f"{cls} | {val}"
    mech = (f.get("mechanism") or "").strip().lower()
    return f"{cls} | (no-value) | {mech}"


def diff(disk: list[dict], dual: list[dict]) -> tuple[list[dict], list[dict]]:
    """Return (only_in_disk, only_in_dual) by signature."""
    disk_sigs = {_signature(f): f for f in disk}
    dual_sigs = {_signature(f): f for f in dual}
    only_in_disk = [disk_sigs[s] for s in disk_sigs if s not in dual_sigs]
    only_in_dual = [dual_sigs[s] for s in dual_sigs if s not in disk_sigs]
    return only_in_disk, only_in_dual


def render_report(pairs: list[HostPair], today: str) -> str:
    lines: list[str] = []
    lines.append(f"# Disk-only vs dual-channel regression check, {today}")
    lines.append("")
    lines.append("## TL;DR")
    lines.append("")
    total_regressions = sum(
        len(diff(p.disk_findings, p.dual_findings)[0]) for p in pairs
    )
    total_dual_adds = sum(
        len(diff(p.disk_findings, p.dual_findings)[1]) for p in pairs
    )
    lines.append(
        f"Compared {len(pairs)} host pairs (disk-only + dual sweep). "
        f"{total_regressions} disk-only findings did not appear in the matching "
        f"dual run (potential regressions, listed below). "
        f"{total_dual_adds} dual-only findings did not appear in the disk-only run "
        f"(memory-channel adds, the value the dual sweep produced)."
    )
    lines.append("")

    lines.append("## Per-host counts")
    lines.append("")
    lines.append("| Host | Disk-only count | Dual count | Lost in dual | Added in dual |")
    lines.append("|---|---|---|---|---|")
    for p in pairs:
        only_disk, only_dual = diff(p.disk_findings, p.dual_findings)
        lines.append(
            f"| {p.host} | {len(p.disk_findings)} | {len(p.dual_findings)} | "
            f"{len(only_disk)} | {len(only_dual)} |"
        )
    lines.append("")

    lines.append("## Per-host detail")
    lines.append("")
    for p in pairs:
        only_disk, only_dual = diff(p.disk_findings, p.dual_findings)
        lines.append(f"### {p.host}")
        lines.append("")
        lines.append(f"- disk-only run: `{p.disk_dir.relative_to(REPO_ROOT)}` ({len(p.disk_findings)} findings)")
        lines.append(f"- dual run:      `{p.dual_dir.relative_to(REPO_ROOT)}` ({len(p.dual_findings)} findings)")
        if only_disk:
            lines.append("")
            lines.append("**Lost in dual (regression candidates):**")
            for f in only_disk:
                lines.append(
                    f"- `{f.get('classification')}` / `{f.get('confidence')}` "
                    f"| {f.get('mechanism') or '(no mechanism)'} "
                    f"| value: {(f.get('value') or '')[:140]}"
                )
        if only_dual:
            lines.append("")
            lines.append("**Added in dual (memory-channel adds):**")
            for f in only_dual:
                lines.append(
                    f"- `{f.get('classification')}` / `{f.get('confidence')}` "
                    f"| {f.get('mechanism') or '(no mechanism)'} "
                    f"| value: {(f.get('value') or '')[:140]}"
                )
        if not only_disk and not only_dual:
            lines.append("")
            lines.append("_No diff: dual run produced exactly the same findings as the disk-only run._")
        lines.append("")

    lines.append("## How to read this")
    lines.append("")
    lines.append(
        "A regression is when a finding appears in the disk-only sweep but is "
        "missing from the dual sweep. Common causes: PLAN drift (the dual "
        "PLAN dropped the relevant tool call), INTERPRET drift (the dual "
        "INTERPRET classified the same evidence differently), or evidence "
        "trimming (a tool output got truncated upstream). Each entry should be "
        "investigated; not every diff is a real regression (the dual INTERPRET "
        "may legitimately re-classify a finding that was over-claimed in disk-"
        "only mode)."
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--today", default=None)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    today = args.today or _dt.datetime.utcnow().strftime("%Y-%m-%d")

    pairs = find_pairs(args.root)
    if not pairs:
        print("no host pairs found (need both disk-only and dual run dirs)", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"[compare] {len(pairs)} host pair(s) found", file=sys.stderr)
        for p_ in pairs:
            disk_only, dual_only = diff(p_.disk_findings, p_.dual_findings)
            print(
                f"  {p_.host}: disk={len(p_.disk_findings)} dual={len(p_.dual_findings)} "
                f"lost_in_dual={len(disk_only)} added_in_dual={len(dual_only)}",
                file=sys.stderr,
            )

    report = render_report(pairs, today)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    if not args.quiet:
        print(f"[compare] wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
