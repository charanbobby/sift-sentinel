#!/usr/bin/env python3
"""Promote staged rules from learn_from_misses.py into the live store.

A staged rule is just a Haiku proposal. It must clear three gates before it
earns a place in `pipeline/learned_rules.jsonl`:

  1. LINT   (deterministic): valid kind, non-empty text, length cap, no
            unsafe patterns (broken JSON quotes, regex backreferences, etc.).
  2. DEDUP  (deterministic): collapse near-duplicate rule_text within and
            against the existing live store. Same (rule_kind, normalized text)
            is a duplicate.
  3. PROMOTE (manual or replay): caller picks which surviving rules to write
            to the live store. Live-replay mode (catches historical miss?
            no new FPs on baseline?) is a TODO for the next iteration; for
            now this script supports `--mode lint` and `--mode promote` (with
            an explicit `--promote-id <id>` allowlist so nothing leaks in by
            mistake).

Usage:
  # Lint + dedupe a staged file, print survivors and reasons:
  python3 scripts/regression_gate.py --staged <staged.jsonl> --mode lint

  # Promote one or more rules by id:
  python3 scripts/regression_gate.py --staged <staged.jsonl> --mode promote \\
      --live experiments/slice-2-notebook/pipeline/learned_rules.jsonl \\
      --promote-id <id1> --promote-id <id2>
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from pathlib import Path

ALLOWED_KINDS = ("counter_rule", "extract_location", "planner_hint")
MAX_RULE_TEXT_CHARS = 600


def _load_jsonl(p: Path) -> list[dict]:
    if not p.exists():
        return []
    out = []
    for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"WARN {p}:{n}: not JSON ({e}), skipped", file=sys.stderr)
            continue
        out.append(obj)
    return out


def _normalize(text: str) -> str:
    """Collapse whitespace + lowercase for dedup comparison only. The stored
    rule_text keeps its original capitalisation."""
    return re.sub(r"\s+", " ", text).strip().lower()


def _lint(rule: dict) -> tuple[bool, str]:
    """Return (ok, reason). Reason populated only on failure."""
    kind = rule.get("rule_kind")
    text = rule.get("rule_text")
    if kind not in ALLOWED_KINDS:
        return False, f"bad rule_kind={kind!r}"
    if not isinstance(text, str) or not text.strip():
        return False, "empty rule_text"
    if len(text) > MAX_RULE_TEXT_CHARS:
        return False, f"rule_text too long ({len(text)} > {MAX_RULE_TEXT_CHARS})"
    # Reject anything that looks like an attempt to inject prompt-control
    # tokens or broken markdown fences.
    bad_tokens = ["```", "<|", "|>", "<system>", "</system>"]
    for t in bad_tokens:
        if t in text:
            return False, f"contains forbidden token {t!r}"
    return True, ""


def _dedup(staged: list[dict], live: list[dict]) -> tuple[list[dict], list[tuple[dict, str]]]:
    """Return (survivors, dropped_with_reason). A rule is dropped if its
    (kind, normalized_text) already appears either earlier in `staged` or
    in `live`. The first occurrence in staged wins.
    """
    survivors: list[dict] = []
    dropped: list[tuple[dict, str]] = []
    seen: set[tuple[str, str]] = set()
    for r in live:
        k = r.get("rule_kind")
        t = r.get("rule_text") or ""
        if k and t:
            seen.add((k, _normalize(t)))
    for r in staged:
        key = (r.get("rule_kind"), _normalize(r.get("rule_text") or ""))
        if key in seen:
            dropped.append((r, "duplicate of an existing live rule or earlier staged entry"))
            continue
        seen.add(key)
        survivors.append(r)
    return survivors, dropped


def _print_summary(label: str, items: list[dict]) -> None:
    print(f"--- {label}: {len(items)} ---")
    for r in items:
        rid = r.get("id", "?")
        kind = r.get("rule_kind", "?")
        text = (r.get("rule_text") or "").replace("\n", " ")
        if len(text) > 110:
            text = text[:110] + "..."
        print(f"  [{kind:18}] {rid}")
        print(f"                       {text}")


def _mode_lint(args) -> int:
    staged = _load_jsonl(args.staged)
    live = _load_jsonl(args.live) if args.live and args.live.exists() else []

    print(f"=== regression_gate lint ===")
    print(f"staged file:  {args.staged}  ({len(staged)} rule(s))")
    if args.live:
        print(f"live file:    {args.live}  ({len(live)} rule(s))")
    print()

    lint_pass: list[dict] = []
    lint_fail: list[tuple[dict, str]] = []
    for r in staged:
        ok, reason = _lint(r)
        if ok:
            lint_pass.append(r)
        else:
            lint_fail.append((r, reason))

    survivors, dedup_drops = _dedup(lint_pass, live)

    _print_summary("survivors (lint+dedup PASS)", survivors)
    print()
    if lint_fail:
        print(f"--- lint FAIL: {len(lint_fail)} ---")
        for r, reason in lint_fail:
            print(f"  {r.get('id','?')}: {reason}")
        print()
    if dedup_drops:
        print(f"--- dedup DROP: {len(dedup_drops)} ---")
        for r, reason in dedup_drops:
            print(f"  {r.get('id','?')}: {reason}")
        print()

    print(f"=== summary: pass={len(survivors)} lint_fail={len(lint_fail)} dedup_drop={len(dedup_drops)} ===")
    return 0 if survivors else 1


def _mode_promote(args) -> int:
    if not args.live:
        print("FAIL: --live required in promote mode", file=sys.stderr)
        return 2
    if not args.promote_id:
        print("FAIL: at least one --promote-id required (use lint mode to see ids)", file=sys.stderr)
        return 2

    staged = _load_jsonl(args.staged)
    live = _load_jsonl(args.live) if args.live.exists() else []
    by_id = {r.get("id"): r for r in staged}

    chosen: list[dict] = []
    missing: list[str] = []
    for rid in args.promote_id:
        if rid in by_id:
            chosen.append(by_id[rid])
        else:
            missing.append(rid)

    if missing:
        print(f"FAIL: ids not in staged file: {missing}", file=sys.stderr)
        return 2

    # Run lint + dedup on the chosen subset only. This catches the case
    # where someone promotes an id that fails lint OR is a duplicate of a
    # live rule. Both are blocking.
    lint_failures = []
    for r in chosen:
        ok, reason = _lint(r)
        if not ok:
            lint_failures.append((r, reason))
    if lint_failures:
        print("FAIL: chosen rule(s) failed lint:", file=sys.stderr)
        for r, reason in lint_failures:
            print(f"  {r.get('id')}: {reason}", file=sys.stderr)
        return 3

    survivors, dedup_drops = _dedup(chosen, live)
    if dedup_drops:
        print("FAIL: chosen rule(s) duplicate something already live:", file=sys.stderr)
        for r, reason in dedup_drops:
            print(f"  {r.get('id')}: {reason}", file=sys.stderr)
        return 4

    promoted_at = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    with args.live.open("a", encoding="utf-8") as fh:
        for r in survivors:
            entry = dict(r)
            entry["promoted_at"] = promoted_at
            entry["regression_passed"] = "lint_dedup_only"
            entry["promote_count"] = int(r.get("promote_count") or 0) + 1
            fh.write(json.dumps(entry) + "\n")
    print(f"=== promoted {len(survivors)} rule(s) to {args.live} ===")
    for r in survivors:
        print(f"  {r.get('id')}  {r.get('rule_kind')}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--staged", required=True, type=Path,
                    help="staged JSONL produced by learn_from_misses.py")
    ap.add_argument("--live", type=Path,
                    default=Path("experiments/slice-2-notebook/pipeline/learned_rules.jsonl"),
                    help="live rule store (default: pipeline/learned_rules.jsonl)")
    ap.add_argument("--mode", choices=["lint", "promote"], required=True)
    ap.add_argument("--promote-id", action="append", default=[],
                    help="rule id to promote (repeatable; required in promote mode)")
    args = ap.parse_args()

    if args.mode == "lint":
        return _mode_lint(args)
    if args.mode == "promote":
        return _mode_promote(args)
    print(f"unknown mode: {args.mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
