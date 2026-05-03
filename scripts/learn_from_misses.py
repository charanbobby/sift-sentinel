#!/usr/bin/env python3
"""Phase G of the daily learning loop: turn yesterday's MISSes into staged rules.

For every `[MISS]` in `score_<date>.json`, fetch the matching artifact spec
from `manifest_<date>.json` plus the actual `findings.json` sentinel produced,
then ask Haiku via the local `claude` CLI to draft the smallest rule that
would have caught this miss. Three rule shapes are allowed:

    counter_rule       -> appended to INTERPRET_SYSTEM_PROMPT (LLM-side)
    extract_location   -> appended to _DISK_PERSISTENCE_SECTION (extract-side)
    planner_hint       -> appended to PLAN system prompt soft-rules (planner-side)

Output rules are STAGED, not promoted. They land in
`<run_dir>/learned_rules.staged.jsonl`. Promotion into the live store
happens via `scripts/regression_gate.py` after each candidate proves it
catches the historical miss AND does not false-positive on the clean
baseline AND does not false-positive on a clean DFIR host.

Usage:
    python3 scripts/learn_from_misses.py \\
        --run-dir /opt/find-evil/out/loop-runs/2026-05-02 \\
        --out-staged /opt/find-evil/out/loop-runs/2026-05-02/learned_rules.staged.jsonl

Cost: each MISS is ONE `claude` CLI call (Haiku 4.5). Under Max plan the CLI
is free; if you flip --use-api this would route through the SDK and would
require both prompt caching and a cost print on every call (CLAUDE.md rule).
This script does NOT use --use-api yet.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

GENERATOR_MODEL = "haiku"
GENERATOR_VERSION = "learn_from_misses.v1"

ALLOWED_KINDS = ("counter_rule", "extract_location", "planner_hint")

PROMPT_TEMPLATE = """You are tuning the rule set of a DFIR pipeline named `sentinel`. Yesterday it ran against a planted Windows host and missed a known-malicious artifact. Your job: write the smallest rule that would have caught it without inflating false positives.

## The artifact sentinel missed

ID                 : {artifact_id}
Category           : {category}
Type               : {artifact_type}
Expected detection : {expected_detection}
Rationale (intel)  : {rationale}

Full manifest spec :
```json
{artifact_json}
```

## What sentinel actually emitted

Sentinel produced these {n_findings} findings on the same run:

```json
{findings_summary}
```

Note: sentinel emits a Finding only when it has structured-field-backed evidence. A miss means either (a) the planner did not call the right tool (so no evidence existed), (b) the extracted candidate set did not include the right location (so the planner had no reason to look), or (c) the interpret step saw the evidence but classified it as benign.

## How sentinel can learn

You may propose 1 to 3 rules to add to the live rule store. Each rule has:

- `rule_kind`: one of {kinds}
    * counter_rule       - appended to the INTERPRET system prompt; tells the LLM to flag a pattern it would otherwise dismiss as benign. Best for misses where the evidence WAS in the bundle but interpret undercalled it.
    * extract_location   - appended to the disk-persistence catalog the EXTRACT step uses to enumerate where to look. Best for misses where the candidate location was not on the catalog (e.g. a vendor webapp directory, a non-default scheduled-task path).
    * planner_hint       - appended to the PLAN system prompt; tells the planner to call a specific tool or shape its plan a specific way. Best for misses where the right candidate was on the catalog but the planner did not call the right tool against it.
- `rule_text`: the literal sentence that will be spliced into the prompt. Self-contained, plain English, under 250 chars. Cite the threat-intel source compactly inline (e.g., "(CISA AA24-109A)").
- `rationale`: 1 sentence explaining why this rule plugs THIS specific miss without obvious false positives.

Return ONLY a JSON object matching this schema (no prose, no markdown fences):

```json
{{
  "proposed_rules": [
    {{
      "rule_kind": "counter_rule | extract_location | planner_hint",
      "rule_text": "...",
      "rationale": "..."
    }}
  ]
}}
```
"""


def _summarize_findings(findings_json: dict, max_findings: int = 12) -> str:
    """Produce a compact, model-friendly summary of what sentinel emitted.
    Strip the verbose `notes` and `evidence[].output_excerpt` so the prompt
    stays small but the model still sees category / mechanism / classification.
    """
    out = []
    items = findings_json.get("findings", []) or []
    for f in items[:max_findings]:
        out.append({
            "category": f.get("category"),
            "classification": f.get("classification"),
            "confidence": f.get("confidence"),
            "mechanism": (f.get("mechanism") or "")[:200],
            "value_excerpt": (f.get("value") or "")[:200],
        })
    return json.dumps({"n": len(items), "findings": out}, indent=2)


def _call_haiku(prompt: str, timeout_s: int = 180) -> tuple[str, dict]:
    """Invoke `claude --model haiku --print --output-format json` and return
    (raw_text_response, wrapper_dict). Caller parses the JSON from raw_text.

    On Windows the `claude` shim is a .ps1 / .cmd wrapper, not an exe, so we
    let the shell resolve it via PATHEXT instead of execve-ing a literal
    binary. shutil.which finds the right thing on POSIX and on Windows.
    """
    import shutil
    claude_path = shutil.which("claude") or shutil.which("claude.cmd")
    if not claude_path:
        raise RuntimeError("`claude` CLI not found on PATH; install with `npm i -g @anthropic-ai/claude-code`")
    cmd = [
        claude_path,
        "--model", GENERATOR_MODEL,
        "--print",
        "--output-format", "json",
    ]
    proc = subprocess.run(
        cmd,
        input=prompt,
        text=True,
        capture_output=True,
        timeout=timeout_s,
        shell=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"claude CLI exited {proc.returncode}: stderr={proc.stderr[:500]}"
        )
    try:
        wrapper = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"claude CLI stdout not JSON: {e}; head={proc.stdout[:500]}"
        )
    raw = wrapper.get("result", "")
    if not isinstance(raw, str):
        raise RuntimeError(
            f"claude CLI wrapper lacks string `result`: keys={list(wrapper.keys())}"
        )
    return raw, wrapper


_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _parse_proposed(raw: str) -> list[dict]:
    """Extract the `proposed_rules` list from the model's raw output. Tolerates
    code fences around the JSON. Drops entries missing rule_kind or rule_text;
    drops entries where rule_kind is not in ALLOWED_KINDS.
    """
    text = raw.strip()
    m = _FENCE_RE.search(text)
    if m:
        text = m.group(1)
    else:
        # Try to find the first {...} block.
        first = text.find("{")
        last = text.rfind("}")
        if first != -1 and last != -1 and last > first:
            text = text[first : last + 1]
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        print(f"  WARN could not parse JSON from model output: {e}", file=sys.stderr)
        return []
    if not isinstance(obj, dict):
        print(f"  WARN model output not an object", file=sys.stderr)
        return []
    rules = obj.get("proposed_rules", []) or []
    cleaned = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        kind = r.get("rule_kind")
        text = r.get("rule_text")
        if kind not in ALLOWED_KINDS:
            print(f"  WARN dropped rule with unknown rule_kind={kind!r}", file=sys.stderr)
            continue
        if not isinstance(text, str) or not text.strip():
            print(f"  WARN dropped rule with empty rule_text", file=sys.stderr)
            continue
        cleaned.append({
            "rule_kind": kind,
            "rule_text": text.strip(),
            "rationale": (r.get("rationale") or "").strip(),
        })
    return cleaned


def _stable_id(source_miss_id: str, rule_text: str) -> str:
    """Deterministic short id for a staged rule so re-runs do not duplicate."""
    h = hashlib.sha256(f"{source_miss_id}|{rule_text}".encode("utf-8")).hexdigest()
    return f"{source_miss_id}-{h[:10]}"


def _print_pre(idx: int, total: int, miss_id: str, prompt_chars: int) -> None:
    """Cost-pre print. Free under Max plan but kept for visibility per CLAUDE.md."""
    print(
        f"  [{idx}/{total}] miss={miss_id}\n"
        f"           PRE  model={GENERATOR_MODEL}  prompt_chars={prompt_chars}  cost=Max plan: $0.00 (CLI)",
        flush=True,
    )


def _print_post(wrapper: dict, n_rules: int) -> None:
    """Cost-post print. Use the wrapper.usage if present so we can see the
    actual cost even though the user is on Max."""
    usage = wrapper.get("usage", {}) or {}
    cost = wrapper.get("total_cost_usd")
    in_t = usage.get("input_tokens", 0)
    out_t = usage.get("output_tokens", 0)
    cache_r = usage.get("cache_read_input_tokens", 0)
    cache_w = usage.get("cache_creation_input_tokens", 0)
    cost_str = f"${cost:.4f}" if isinstance(cost, (int, float)) else "n/a"
    print(
        f"           POST input={in_t} cache_r={cache_r} cache_w={cache_w} "
        f"output={out_t} cost={cost_str} (Max plan, $0.00 to user) "
        f"-> {n_rules} proposed rule(s)",
        flush=True,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Synthesise staged rules from yesterday's misses")
    ap.add_argument("--run-dir", required=True, type=Path,
                    help="Loop-run dir containing score_<date>.json, manifest_<date>.json, pipeline_output/findings.json")
    ap.add_argument("--out-staged", required=True, type=Path,
                    help="Where to write the staged JSONL")
    ap.add_argument("--limit", type=int, default=None,
                    help="Process only the first N misses (for fast iteration)")
    ap.add_argument("--timeout-s", type=int, default=180)
    ap.add_argument("--dry-run", action="store_true",
                    help="Build prompts and print summary, do not call the CLI")
    args = ap.parse_args()

    run_dir: Path = args.run_dir
    if not run_dir.exists():
        print(f"FAIL: run-dir does not exist: {run_dir}", file=sys.stderr)
        return 2

    score_files = sorted(run_dir.glob("score_*.json"))
    manifest_files = sorted(run_dir.glob("manifest_*.json"))
    findings_path = run_dir / "pipeline_output" / "findings.json"
    if not score_files:
        print(f"FAIL: no score_*.json in {run_dir}", file=sys.stderr)
        return 2
    if not manifest_files:
        print(f"FAIL: no manifest_*.json in {run_dir}", file=sys.stderr)
        return 2
    if not findings_path.exists():
        print(f"FAIL: no pipeline_output/findings.json in {run_dir}", file=sys.stderr)
        return 2

    score = json.loads(score_files[-1].read_text(encoding="utf-8"))
    manifest = json.loads(manifest_files[-1].read_text(encoding="utf-8"))
    findings = json.loads(findings_path.read_text(encoding="utf-8"))

    manifest_id = score.get("manifest_id") or manifest.get("manifest_id") or run_dir.name
    findings_summary = _summarize_findings(findings)
    n_findings = len(findings.get("findings", []) or [])

    # Build a {artifact_id -> spec} lookup from the manifest.
    spec_by_id: dict[str, dict] = {}
    for cat in manifest.get("categories", []) or []:
        for art in cat.get("artifacts", []) or []:
            aid = art.get("id")
            if aid:
                spec_by_id[aid] = {**art, "_category_name": cat.get("name")}

    # Filter score per_artifact for genuine misses (skip documented gaps).
    misses = []
    for entry in score.get("per_artifact", []) or []:
        if entry.get("status") != "MISS":
            continue
        if entry.get("expected_detection") == "expected_miss_documented_gap":
            continue
        misses.append(entry)

    if args.limit:
        misses = misses[: args.limit]

    print(f"=== learn_from_misses for {manifest_id} ===")
    print(f"misses to process: {len(misses)}")
    print()

    args.out_staged.parent.mkdir(parents=True, exist_ok=True)

    n_total_rules = 0
    with args.out_staged.open("w", encoding="utf-8") as out_fh:
        for i, miss in enumerate(misses, 1):
            aid = miss.get("id")
            spec = spec_by_id.get(aid, {})
            prompt = PROMPT_TEMPLATE.format(
                artifact_id=aid,
                category=miss.get("category", "?"),
                artifact_type=miss.get("type", "?"),
                expected_detection=miss.get("expected_detection", "?"),
                rationale=miss.get("rationale", "?"),
                artifact_json=json.dumps(spec, indent=2),
                n_findings=n_findings,
                findings_summary=findings_summary,
                kinds=", ".join(ALLOWED_KINDS),
            )
            _print_pre(i, len(misses), aid, len(prompt))
            if args.dry_run:
                print(f"           DRY-RUN: would call claude with {len(prompt)} chars")
                continue
            try:
                raw, wrapper = _call_haiku(prompt, timeout_s=args.timeout_s)
            except Exception as e:
                print(f"           FAIL: {e}", file=sys.stderr)
                continue
            proposed = _parse_proposed(raw)
            _print_post(wrapper, len(proposed))
            now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
            for r in proposed:
                entry = {
                    "id": _stable_id(aid, r["rule_text"]),
                    "source_miss_id": aid,
                    "source_manifest_id": manifest_id,
                    "rule_kind": r["rule_kind"],
                    "rule_text": r["rule_text"],
                    "rationale": r["rationale"],
                    "generated_by_model": GENERATOR_MODEL,
                    "generated_by_version": GENERATOR_VERSION,
                    "generated_at": now,
                    "regression_passed": False,
                    "promote_count": 0,
                }
                out_fh.write(json.dumps(entry) + "\n")
                n_total_rules += 1

    print()
    print(f"=== done: {n_total_rules} staged rule(s) -> {args.out_staged} ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
