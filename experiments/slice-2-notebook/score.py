"""Slice 2.5 scorer: findings.json + ground_truth.json → precision / recall / hallucinations.

Run from the project root:

    uv run --project experiments/slice-2-notebook score.py            # all cases
    uv run --project experiments/slice-2-notebook score.py --case srl-2018-wkstn-05
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

RUNS_DIR = Path(__file__).parent / "out" / "runs"


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def score_case(case_dir: Path) -> dict:
    findings = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    ground_truth = json.loads((case_dir / "ground_truth.json").read_text(encoding="utf-8"))
    raw_by_tcid = {e["tool_call_id"]: e for e in load_jsonl(case_dir / "raw_results.jsonl")}

    verdicts_by_index = {v["finding_index"]: v for v in ground_truth["agent_findings_verdicts"]}

    tp = fp = unclear = 0
    verdict_rows = []
    for idx, finding in enumerate(findings["findings"]):
        v = verdicts_by_index.get(idx)
        verdict = v["verdict"] if v else "MISSING"
        verdict_rows.append({
            "index": idx,
            "summary": v["finding_summary"] if v else finding.get("mechanism", "?"),
            "verdict": verdict,
        })
        if verdict == "TP":
            tp += 1
        elif verdict == "FP":
            fp += 1
        elif verdict == "UNCLEAR":
            unclear += 1

    fn = len(ground_truth.get("false_negatives") or [])

    hallucinations = []
    for idx, finding in enumerate(findings["findings"]):
        for ev_i, ev in enumerate(finding.get("evidence", [])):
            tcid = ev.get("tool_call_id")
            excerpt = ev.get("output_excerpt", "")
            if tcid not in raw_by_tcid:
                hallucinations.append({
                    "finding_index": idx,
                    "evidence_index": ev_i,
                    "reason": "tool_call_id not in raw_results.jsonl",
                    "tool_call_id": tcid,
                })
                continue
            haystack = raw_by_tcid[tcid].get("stdout_excerpt", "")
            if excerpt and excerpt not in haystack:
                hallucinations.append({
                    "finding_index": idx,
                    "evidence_index": ev_i,
                    "reason": "output_excerpt not found in cited stdout_excerpt",
                    "tool_call_id": tcid,
                })

    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else None

    return {
        "case_id": ground_truth["case_id"],
        "counts": {"TP": tp, "FP": fp, "FN": fn, "UNCLEAR": unclear},
        "precision": precision,
        "recall": recall,
        "hallucination_count": len(hallucinations),
        "hallucinations": hallucinations,
        "verdicts": verdict_rows,
    }


def fmt(val: float | None) -> str:
    return f"{val:.2f}" if val is not None else "  — "


def print_scorecard(card: dict) -> None:
    c = card["counts"]
    print(f"\n=== {card['case_id']} ===")
    for row in card["verdicts"]:
        print(f"  [{row['verdict']:<7}] finding {row['index']}: {row['summary']}")
    print(f"  TP={c['TP']}  FP={c['FP']}  FN={c['FN']}  UNCLEAR={c['UNCLEAR']}")
    print(f"  Precision={fmt(card['precision'])}  Recall={fmt(card['recall'])}  Hallucinations={card['hallucination_count']}")
    if card["hallucinations"]:
        for h in card["hallucinations"]:
            print(f"    ! finding {h['finding_index']} evidence[{h['evidence_index']}]: {h['reason']}")


def print_summary(cards: list[dict]) -> None:
    totals = {"TP": 0, "FP": 0, "FN": 0, "UNCLEAR": 0}
    halluc = 0
    for card in cards:
        for k, v in card["counts"].items():
            totals[k] += v
        halluc += card["hallucination_count"]
    precision = totals["TP"] / (totals["TP"] + totals["FP"]) if (totals["TP"] + totals["FP"]) > 0 else None
    recall = totals["TP"] / (totals["TP"] + totals["FN"]) if (totals["TP"] + totals["FN"]) > 0 else None
    print(f"\n=== combined (n={len(cards)}) ===")
    print(f"  TP={totals['TP']}  FP={totals['FP']}  FN={totals['FN']}  UNCLEAR={totals['UNCLEAR']}")
    print(f"  Precision={fmt(precision)}  Recall={fmt(recall)}  Hallucinations={halluc}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", help="case_id (directory name under out/runs/). Omit to score all cases.")
    ap.add_argument("--no-write", action="store_true", help="skip writing scorecard.json files")
    args = ap.parse_args()

    if args.case:
        case_dirs = [RUNS_DIR / args.case]
    else:
        case_dirs = sorted(d for d in RUNS_DIR.iterdir() if d.is_dir() and (d / "ground_truth.json").exists())

    cards = []
    for case_dir in case_dirs:
        if not (case_dir / "ground_truth.json").exists():
            print(f"skip {case_dir.name}: no ground_truth.json")
            continue
        card = score_case(case_dir)
        cards.append(card)
        print_scorecard(card)
        if not args.no_write:
            (case_dir / "scorecard.json").write_text(json.dumps(card, indent=2), encoding="utf-8")

    if len(cards) > 1:
        print_summary(cards)


if __name__ == "__main__":
    main()
