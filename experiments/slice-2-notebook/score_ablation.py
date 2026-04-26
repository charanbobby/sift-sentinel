"""score_ablation.py — Slice 6 Step 7 ablation result aggregator.

Walks every run folder under `out/runs/<case>/<case>-NNN/`, groups by
ablation row (read from the `ablation_row.txt` sidecar that `run_case.py`
writes when `ABLATION_ROW=2|4` is set; default-unset = row 3 = full Slice 5),
and produces a row × case comparison table.

For GT-annotated cases (`out/runs/<case>/ground_truth.json` present):
  Re-applies ground-truth verdicts to each run by matching findings on the
  (category, mechanism, value) triple. Computes TP / FP / FN / TN and
  precision / recall per cell. Mismatches against GT (a finding that doesn't
  match any GT entry, or a GT TP entry not matched by any finding) are
  flagged for human spot-check; the aggregator does not silently classify
  them.

For non-GT cases:
  Reports findings count, critic terminal state, and INJECTION_QUARANTINE
  count. No precision/recall (no GT to compare against).

Output (written next to the script, since `docs/` is not bind-mounted into
the sift-sentinel container where this typically runs):
  - `experiments/slice-2-notebook/out/ablation/ablation-table.md`
  - `experiments/slice-2-notebook/out/ablation/ablation-table.json`

The Accuracy Report references those paths directly. If you want them under
`docs/submission/`, copy them manually or use a symlink — the script does
not do filesystem-spanning writes from inside the container.

Pure stdlib + Pydantic (already in the slice-2-notebook venv); no LLM
calls, no network.

Row 1 (Slice 2.5 baseline) is intentionally NOT computed by this script —
those numbers come from the Slice 2.5 closeout in `docs/planning/PLAN.md`
and are filled into the Accuracy Report manually.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Repo layout: this script sits at experiments/slice-2-notebook/score_ablation.py.
HERE = Path(__file__).resolve().parent
RUNS_ROOT = HERE / "out" / "runs"
# `docs/` is NOT bind-mounted into the sift-sentinel container, so output
# goes next to the script (under bind-mounted `out/`). Copy or symlink to
# `docs/submission/` if you want it there.
OUTPUT_DIR = HERE / "out" / "ablation"

DEFAULT_ROW = 3  # rows without a sidecar marker are full Slice 5
ROWS_TO_REPORT = (2, 3, 4)
RUN_ID_RE = re.compile(r"^.+-(\d{3,})$")


# ---- data shapes -----------------------------------------------------------


@dataclass
class CellScore:
    """One cell in the row × case comparison table."""
    row: int
    case_id: str
    run_id: str | None = None
    has_gt: bool = False
    n_findings: int = 0
    n_high_confidence: int = 0
    terminal: str = "UNKNOWN"
    n_quarantine: int = 0
    # GT-grounded
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    precision: float | None = None
    recall: float | None = None
    unmatched_findings: list[str] = field(default_factory=list)
    unmatched_gt: list[str] = field(default_factory=list)
    # Empty cell (no run for this row+case yet)
    is_empty: bool = False


# ---- helpers ---------------------------------------------------------------


def _list_runs(case_dir: Path) -> list[Path]:
    """All run folders under a case, oldest first."""
    if not case_dir.exists():
        return []
    runs = []
    for p in sorted(case_dir.iterdir()):
        if not p.is_dir():
            continue
        if RUN_ID_RE.match(p.name):
            runs.append(p)
    return runs


def _read_ablation_row(run_dir: Path) -> int:
    sidecar = run_dir / "ablation_row.txt"
    if not sidecar.exists():
        return DEFAULT_ROW
    try:
        return int(sidecar.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return DEFAULT_ROW


def _read_findings(run_dir: Path) -> dict | None:
    f = run_dir / "05_interpret_findings.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _read_terminal(run_dir: Path) -> str:
    for marker in ("07_terminal.SUCCESS", "07_terminal.HUMAN_REVIEW",
                   "07_terminal.QUARANTINED", "07_terminal.FAILED"):
        if (run_dir / marker).exists():
            return marker.split(".", 1)[1]
    return "INCOMPLETE"


def _count_quarantine(run_dir: Path) -> int:
    f = run_dir / "06_critic_disagreements.jsonl"
    if not f.exists():
        return 0
    n = 0
    try:
        with f.open("r", encoding="utf-8") as fh:
            for line in fh:
                if '"event": "INJECTION_QUARANTINE"' in line:
                    n += 1
    except OSError:
        return 0
    return n


def _read_gt(case_dir: Path) -> dict | None:
    f = case_dir / "ground_truth.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _match_findings_to_gt(findings: list[dict], gt: dict) -> tuple[int, int, int, int, list[str], list[str]]:
    """Match each finding to a GT verdict by (category, mechanism, value).

    Returns (TP, FP, FN, TN, unmatched_findings, unmatched_gt).
    GT TPs unmatched by any finding count as FN. Findings not in GT are
    flagged as 'unmatched_findings' for human spot-check (NOT silently FP).
    GT TNs unmatched by any finding don't change the cell — TN means the
    pipeline correctly did not surface this entry.
    """
    gt_verdicts = gt.get("agent_findings_verdicts", [])
    if not gt_verdicts:
        # Pure negative-control case (e.g. base-dc) — GT has no verdicts at
        # the agent_findings level, only a scorecard. Use the scorecard.
        sc = gt.get("scorecard", {})
        return (sc.get("TP", 0), sc.get("FP", 0), sc.get("FN", 0), sc.get("TN", 0), [], [])

    # Build GT lookup by (category, mechanism, value) — but GT entries reference
    # findings by index in the ORIGINAL run, not by triple. So we need to load
    # the GT-time findings (which we don't have separately). Pragma: GT verdicts
    # are tied to a specific run's finding ordering; for ablation comparison we
    # match by `finding_summary` (a free-text label in the GT entry that names
    # the mechanism enough to disambiguate).
    gt_by_summary_key = {}
    for entry in gt_verdicts:
        summary = (entry.get("finding_summary") or "").lower()
        verdict = entry.get("verdict", "?")
        # Use a coarse key: any non-empty token >=4 chars from the summary
        # gives us a fuzzy-but-deterministic match against finding.value /
        # finding.mechanism. Good enough for the comparison table; flagged
        # cells are spot-checked.
        gt_by_summary_key[summary] = verdict

    matched_gt: set[str] = set()
    tp = fp = fn = tn = 0
    unmatched_findings: list[str] = []

    # Score by best overlap, not first hit. For each finding, count token
    # overlap against every UNCLAIMED GT entry; pick the highest-overlap
    # match (ties go to the first scanned). This stops two findings from
    # claiming the same GT entry when both share a distinctive token (e.g.
    # `coreupdater` appears in both the Run-key and the service GT entries
    # for dfirmadness-001-desktop, but only one finding should match each).
    for f in findings:
        haystack_lc = " ".join(str(x or "").lower() for x in (
            f.get("mechanism", ""), f.get("value", ""), f.get("category", ""),
        ))
        best_key = None
        best_score = 0
        for gt_key in gt_by_summary_key:
            if gt_key in matched_gt:
                continue
            tokens = [t for t in re.split(r"\W+", gt_key) if len(t) >= 5]
            score = sum(1 for t in tokens if t in haystack_lc)
            if score > best_score:
                best_key = gt_key
                best_score = score
        if best_key is None or best_score == 0:
            unmatched_findings.append(f.get("mechanism") or f.get("value", "(unnamed)"))
            continue
        matched_gt.add(best_key)
        verdict = gt_by_summary_key[best_key]
        if verdict == "TP":
            tp += 1
        elif verdict == "FP":
            fp += 1
        elif verdict == "TN":
            tn += 1

    # GT TP entries we never matched = FN
    unmatched_gt: list[str] = []
    for gt_key, verdict in gt_by_summary_key.items():
        if gt_key in matched_gt:
            continue
        if verdict == "TP":
            fn += 1
            unmatched_gt.append(gt_key)
        # Unmatched GT TN/FP entries don't bump counters — they describe
        # what the pipeline correctly omitted/included in the GT-time run.

    # Add explicitly-listed false negatives from GT
    for fn_entry in gt.get("false_negatives", []):
        fn += 1
        unmatched_gt.append(fn_entry.get("summary", "(false negative)"))

    return (tp, fp, fn, tn, unmatched_findings, unmatched_gt)


# ---- main scoring ----------------------------------------------------------


def score_run(run_dir: Path, case_dir: Path, gt: dict | None) -> CellScore:
    row = _read_ablation_row(run_dir)
    case_id = case_dir.name

    findings_doc = _read_findings(run_dir)
    findings = (findings_doc or {}).get("findings", []) if findings_doc else []

    cell = CellScore(
        row=row,
        case_id=case_id,
        run_id=run_dir.name,
        has_gt=gt is not None,
        n_findings=len(findings),
        n_high_confidence=sum(1 for f in findings if f.get("confidence") == "high"),
        terminal=_read_terminal(run_dir),
        n_quarantine=_count_quarantine(run_dir),
    )

    if gt is not None and findings:
        tp, fp, fn, tn, unm_f, unm_gt = _match_findings_to_gt(findings, gt)
        cell.tp, cell.fp, cell.fn, cell.tn = tp, fp, fn, tn
        cell.unmatched_findings = unm_f
        cell.unmatched_gt = unm_gt
        if (tp + fp) > 0:
            cell.precision = tp / (tp + fp)
        if (tp + fn) > 0:
            cell.recall = tp / (tp + fn)
    elif gt is not None and not findings:
        # GT exists but no findings — could be a true NOT_FOUND run.
        sc = gt.get("scorecard", {})
        cell.tp = sc.get("TP", 0)
        cell.fp = sc.get("FP", 0)
        cell.fn = sc.get("FN", 0)
        cell.tn = sc.get("TN", 0)

    return cell


def _latest_run_per_row(runs: list[Path]) -> dict[int, Path]:
    """For each ablation row, return the MOST RECENT run folder (highest run_id)."""
    by_row: dict[int, Path] = {}
    for run in runs:
        row = _read_ablation_row(run)
        if row not in by_row or run.name > by_row[row].name:
            by_row[row] = run
    return by_row


def aggregate() -> tuple[dict[tuple[int, str], CellScore], list[str]]:
    """Walk runs root, return (cells_by_row_and_case, ordered_case_ids)."""
    cells: dict[tuple[int, str], CellScore] = {}
    case_ids: list[str] = []

    if not RUNS_ROOT.exists():
        print(f"[score_ablation] runs root not found: {RUNS_ROOT}", file=sys.stderr)
        return cells, case_ids

    for case_dir in sorted(RUNS_ROOT.iterdir()):
        if not case_dir.is_dir():
            continue
        runs = _list_runs(case_dir)
        if not runs:
            continue
        case_ids.append(case_dir.name)
        gt = _read_gt(case_dir)
        latest_per_row = _latest_run_per_row(runs)
        for row in ROWS_TO_REPORT:
            if row in latest_per_row:
                cells[(row, case_dir.name)] = score_run(latest_per_row[row], case_dir, gt)
            else:
                cells[(row, case_dir.name)] = CellScore(
                    row=row, case_id=case_dir.name, is_empty=True,
                )

    return cells, case_ids


# ---- output ----------------------------------------------------------------


def cell_to_str(cell: CellScore) -> str:
    if cell.is_empty:
        return "TODO"
    if cell.has_gt:
        if cell.precision is not None and cell.recall is not None:
            base = f"P={cell.precision:.2f} R={cell.recall:.2f}"
        elif cell.tp == 0 and cell.fp == 0 and cell.fn == 0:
            base = f"TN={cell.tn}" if cell.tn else "no findings"
        else:
            base = f"TP={cell.tp} FP={cell.fp} FN={cell.fn}"
        if cell.unmatched_findings or cell.unmatched_gt:
            base += " ⚠"
        return base
    # Non-GT case
    parts = [f"{cell.n_findings}f"]
    if cell.n_quarantine:
        parts.append(f"{cell.n_quarantine}q")
    parts.append(cell.terminal[:4])
    return " ".join(parts)


def render_markdown(cells: dict, case_ids: list[str]) -> str:
    lines = [
        "# Slice 6 ablation comparison table",
        "",
        "Generated by `experiments/slice-2-notebook/score_ablation.py`. Cells:",
        "",
        "- GT cases: `P=0.00 R=0.00` (precision/recall) or `TP=N FP=N FN=N` when not both defined. `⚠` flags mismatched findings/GT entries needing human spot-check.",
        "- Non-GT cases: `Nf` (findings count), `Nq` (injection-quarantine events), terminal abbreviation (SUCC / HUMA / QUAR).",
        "- `TODO` = no run yet for that row × case.",
        "",
        "Row 1 (Slice 2.5 baseline) is intentionally not auto-computed — fill in",
        "from PLAN.md historical numbers.",
        "",
    ]
    header = "| Row | Configuration | " + " | ".join(case_ids) + " |"
    sep = "|---|---|" + "|".join("---" for _ in case_ids) + "|"
    lines.append(header)
    lines.append(sep)

    row_labels = {
        2: "dual-channel only (no cap-tokens)",
        3: "full Slice 5 (current production)",
        4: "full minus `classification` field",
    }
    for row in ROWS_TO_REPORT:
        cells_for_row = [cell_to_str(cells.get((row, c), CellScore(row=row, case_id=c, is_empty=True))) for c in case_ids]
        lines.append(f"| {row} | {row_labels[row]} | " + " | ".join(cells_for_row) + " |")

    # Per-cell mismatch warnings
    warnings = []
    for (row, case), cell in sorted(cells.items()):
        if cell.unmatched_findings:
            warnings.append(f"- Row {row} / `{case}`: unmatched findings (no GT entry): {cell.unmatched_findings}")
        if cell.unmatched_gt:
            warnings.append(f"- Row {row} / `{case}`: unmatched GT entries (no finding): {cell.unmatched_gt}")
    if warnings:
        lines.append("")
        lines.append("## Spot-check warnings")
        lines.append("")
        lines.extend(warnings)

    lines.append("")
    return "\n".join(lines)


def render_json(cells: dict, case_ids: list[str]) -> str:
    out = {"case_ids": case_ids, "cells": []}
    for (row, case), cell in sorted(cells.items()):
        out["cells"].append({
            "row": row,
            "case_id": case,
            "run_id": cell.run_id,
            "has_gt": cell.has_gt,
            "is_empty": cell.is_empty,
            "n_findings": cell.n_findings,
            "n_high_confidence": cell.n_high_confidence,
            "terminal": cell.terminal,
            "n_quarantine": cell.n_quarantine,
            "tp": cell.tp,
            "fp": cell.fp,
            "fn": cell.fn,
            "tn": cell.tn,
            "precision": cell.precision,
            "recall": cell.recall,
            "unmatched_findings": cell.unmatched_findings,
            "unmatched_gt": cell.unmatched_gt,
        })
    return json.dumps(out, indent=2, sort_keys=False)


def main() -> int:
    cells, case_ids = aggregate()
    if not case_ids:
        print("[score_ablation] no runs found; nothing to do.", file=sys.stderr)
        return 1

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    md_path = OUTPUT_DIR / "ablation-table.md"
    json_path = OUTPUT_DIR / "ablation-table.json"
    md_path.write_text(render_markdown(cells, case_ids), encoding="utf-8")
    json_path.write_text(render_json(cells, case_ids), encoding="utf-8")

    print(f"[score_ablation] wrote {md_path}")
    print(f"[score_ablation] wrote {json_path}")
    print(f"[score_ablation] {len(cells)} cells across {len(case_ids)} cases.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
