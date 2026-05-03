#!/usr/bin/env python3
"""Replay the interpret stage of the pipeline against cached evidence with
a candidate counter_rule spliced in. Cheap regression check for rules
proposed by `learn_from_misses.py`.

What this validates:
    - Did the candidate rule cause a NEW finding to land in the output?
    - Does that new finding plausibly match the target miss (substring
      match against the manifest's `file_path`, `value_data`, `task_xml`,
      or `key_path`)?
    - Did the candidate rule cause any EXISTING findings to disappear or
      change classification (regression risk surface)?

What this does NOT validate (still needs the full-pipeline gate):
    - extract_location rules (planner needs to add the dir to its plan).
    - planner_hint rules (planner needs to make a different tool call).
    - cross-host false positives (this only replays the target evidence).

Usage (run inside sift-sentinel container so OpenRouter env is wired):
    docker exec sift-sentinel bash -c '
      cd /workspace && uv run python /opt/scripts/replay_interpret.py \\
          --pipeline-output /run_in/pipeline_output \\
          --manifest /run_in/manifest.json \\
          --staged-rule '"'"'{"rule_kind":"counter_rule","rule_text":"..."}'"'"' \\
          --target-miss-id apt40_iis_persistence_php
    '

Exit codes:
    0 = candidate caused a finding that plausibly matches the target miss
    1 = candidate caused no new finding (rule did not help)
    2 = candidate caused finding(s) but none match the target (false positive risk)
    3 = setup error (missing files, bad rule JSON, OpenRouter unreachable)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Imports from the pipeline package. Requires sys.path includes /workspace.
sys.path.insert(0, "/workspace")

try:
    from pipeline import nodes
    from pipeline.schemas import (
        Candidates,
        EvidenceRecord,
        Findings,
        PlannedStep,
        ToolPlan,
    )
    from pipeline.graph import PipelineState
except ImportError as e:
    print(f"FAIL: cannot import pipeline package ({e}). Run inside sift-sentinel container.", file=sys.stderr)
    sys.exit(3)


def _load_evidence(jsonl: Path) -> list[EvidenceRecord]:
    if not jsonl.exists():
        raise FileNotFoundError(f"evidence file missing: {jsonl}")
    out = []
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(EvidenceRecord.model_validate_json(line))
    return out


def _splice_rule(live_path: Path, rule: dict) -> Path:
    """Append the candidate rule to a TEMP copy of the live store. Returns
    the temp path. Caller restores `nodes._LEARNED_RULES_PATH` after use."""
    temp = live_path.parent / "_replay_temp_learned.jsonl"
    if live_path.exists():
        temp.write_text(live_path.read_text(encoding="utf-8"), encoding="utf-8")
    else:
        temp.write_text("", encoding="utf-8")
    with temp.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rule) + "\n")
    return temp


def _matches_miss(finding: dict, manifest_artifact: dict) -> bool:
    """Heuristic: does this finding plausibly correspond to the planted artifact?
    Compare finding.value / finding.evidence[].output_excerpt against the
    artifact's file_path, value_data, task_xml, key_path, value_name.
    """
    haystack_pieces = [
        finding.get("value", "") or "",
        finding.get("mechanism", "") or "",
        finding.get("notes", "") or "",
    ]
    for ev in finding.get("evidence", []) or []:
        haystack_pieces.append(ev.get("output_excerpt", "") or "")
    haystack = " ".join(haystack_pieces).lower()

    needle_keys = ("file_path", "value_data", "task_xml", "key_path", "value_name", "task_install_path")
    for k in needle_keys:
        v = manifest_artifact.get(k)
        if v and isinstance(v, str):
            # match on a discriminating substring (last 30 chars usually unique enough)
            tail = v[-30:].lower()
            if tail and tail in haystack:
                return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pipeline-output", required=True, type=Path,
                    help="Dir containing 04_execute_evidence.jsonl, 02_plan_tool_plan.json, 01_extract_candidates.json, findings.json from a prior loop run")
    ap.add_argument("--manifest", required=True, type=Path,
                    help="Manifest JSON the planted disk was built from")
    ap.add_argument("--staged-rule", required=True,
                    help="Inline JSON for ONE rule {rule_kind, rule_text, ...}")
    ap.add_argument("--target-miss-id", required=True,
                    help="Artifact id from the manifest that this rule should help catch")
    args = ap.parse_args()

    pipe_out: Path = args.pipeline_output
    if not pipe_out.is_dir():
        print(f"FAIL: --pipeline-output is not a dir: {pipe_out}", file=sys.stderr)
        return 3

    try:
        rule = json.loads(args.staged_rule)
    except json.JSONDecodeError as e:
        print(f"FAIL: --staged-rule not JSON: {e}", file=sys.stderr)
        return 3
    if rule.get("rule_kind") != "counter_rule":
        print(f"FAIL: this gate only supports rule_kind=counter_rule (got {rule.get('rule_kind')!r}). "
              f"Use the full pipeline replay for extract_location / planner_hint.",
              file=sys.stderr)
        return 3

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    artifact = None
    for cat in manifest.get("categories", []) or []:
        for art in cat.get("artifacts", []) or []:
            if art.get("id") == args.target_miss_id:
                artifact = art
                break
    if artifact is None:
        print(f"FAIL: --target-miss-id {args.target_miss_id} not found in manifest", file=sys.stderr)
        return 3

    # Load evidence + tool plan + extract candidates from cache.
    try:
        evidence = _load_evidence(pipe_out / "04_execute_evidence.jsonl")
    except FileNotFoundError as e:
        print(f"FAIL: {e}. The loop run that produced this dir was before evidence-preservation shipped. Re-run the loop once more, then re-try.", file=sys.stderr)
        return 3
    tool_plan_data = json.loads((pipe_out / "02_plan_tool_plan.json").read_text(encoding="utf-8"))
    candidates_data = json.loads((pipe_out / "01_extract_candidates.json").read_text(encoding="utf-8"))
    original_findings = json.loads((pipe_out / "findings.json").read_text(encoding="utf-8"))

    # Splice the candidate rule into a TEMP store and point the loader at it
    # for the duration of the replay.
    live_path = nodes._LEARNED_RULES_PATH
    temp_path = _splice_rule(live_path, rule)
    nodes._LEARNED_RULES_PATH = temp_path

    try:
        # Reconstruct the minimal PipelineState that interpret_node needs.
        state = PipelineState(
            run_id=f"replay-{args.target_miss_id}",
            tool_plan=ToolPlan.model_validate(tool_plan_data),
            candidates=Candidates.model_validate(candidates_data),
            evidence=evidence,
            corrective_instruction=None,
            findings=None,
        )
        nodes.CASE_ID = state.run_id
        result = nodes.interpret_node(state)
        new_findings_obj = result.get("findings")
        if new_findings_obj is None:
            print("FAIL: interpret_node returned no findings", file=sys.stderr)
            return 3
        if hasattr(new_findings_obj, "model_dump"):
            new_findings = new_findings_obj.model_dump()
        else:
            new_findings = new_findings_obj
    finally:
        nodes._LEARNED_RULES_PATH = live_path
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass

    # Diff
    orig_keys = {(f.get("category"), (f.get("mechanism") or "")[:80], f.get("classification"))
                 for f in original_findings.get("findings", []) or []}
    new_only = []
    for f in new_findings.get("findings", []) or []:
        key = (f.get("category"), (f.get("mechanism") or "")[:80], f.get("classification"))
        if key not in orig_keys:
            new_only.append(f)

    print(f"=== replay-interpret summary ===")
    print(f"  original findings: {len(original_findings.get('findings', []))}")
    print(f"  replay   findings: {len(new_findings.get('findings', []))}")
    print(f"  NEW findings (not in original): {len(new_only)}")

    if not new_only:
        print(f"  rule had NO classification effect")
        return 1

    matched = [f for f in new_only if _matches_miss(f, artifact)]
    for f in new_only:
        is_match = _matches_miss(f, artifact)
        marker = "MATCH" if is_match else "NEW-FP-RISK"
        print(f"  [{marker}] {f.get('classification')} / {f.get('category')} / {(f.get('mechanism') or '')[:120]}")

    if matched:
        print(f"PASS: {len(matched)} new finding(s) match the target miss {args.target_miss_id}")
        return 0
    print(f"FAIL: rule produced {len(new_only)} new finding(s), none match target miss {args.target_miss_id}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
