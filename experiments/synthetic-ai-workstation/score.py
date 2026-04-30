#!/usr/bin/env python3
"""Score a daily synthetic-workstation pipeline run.

Reads the pipeline's `findings.json` output and the day's manifest, decides
per-artifact PASS / MISS based on whether any finding cites or describes
the planted artifact's location, and writes both a JSON score blob and a
human-readable Markdown report.

The scoring uses location-based matching (paths, registry keys, service
names) rather than free-text matching, because path and key strings are
the most stable identifiers across LLM phrasing variations.

Usage:
    python3 score.py \
        --manifest manifest_v1.json \
        --findings /opt/find-evil/working/.../findings.json \
        --evidence /opt/find-evil/working/.../execute_evidence.jsonl \
        --baseline-detected perfmon_masquerading,tbbd05_named_pipe_beacon \
        --out-json score_2026-04-28.json \
        --out-md REPORT.md

Exit codes:
    0  always (scoring never fails the run; the loop already failed-fast
       earlier if the pipeline crashed)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


def info(msg: str):
    print(f"[SCORE] {msg}", flush=True)


def _flatten(obj: Any, _out: list[str] | None = None) -> list[str]:
    """Flatten any structured object to its string-valued leaves so we can
    do conservative substring matches."""
    if _out is None:
        _out = []
    if isinstance(obj, str):
        _out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _flatten(v, _out)
    elif isinstance(obj, list):
        for item in obj:
            _flatten(item, _out)
    elif obj is not None:
        _out.append(str(obj))
    return _out


# 2026-04-30: matcher rewritten to fix over-counting bug.
# Old behavior: any locator substring match counted as detection. With
# locators like value_data="1" (wdigest UseLogonCredential), this matched
# anything containing the digit "1". On run-002, medusa_wdigest_credential_cache
# was incorrectly marked PASS using the matching_excerpt of the unrelated
# medusa_run_key_persistence finding.
# New behavior: each type names ONE discriminating field that must appear in
# the finding (e.g. value_name for run_keys, service_name for services).
# Locators below the minimum length are rejected (catches "1", "2", "Run",
# etc. that would false-match).
_MIN_LOCATOR_LEN = 4


def _artifact_match_locator(artifact: dict) -> str | None:
    """Return the single discriminating string for this artifact. The finding
    blob MUST contain this exact substring to count as detection. Per-type:
        registry_run_key      -> value_name (unique under HKLM Run)
        registry_service      -> service_name
        registry_binary_value -> value_name (unique under key_path)
        scheduled_task_xml    -> task_install_path
        file_drop             -> file_path (also checked with \\ separators)
    Returns None if the artifact has no usable discriminator (manifest gap).
    """
    t = artifact.get("type")
    if t == "registry_run_key":
        return artifact.get("value_name") or None
    if t == "registry_service":
        return artifact.get("service_name") or None
    if t == "registry_binary_value":
        return artifact.get("value_name") or None
    if t == "scheduled_task_xml":
        return artifact.get("task_install_path") or None
    if t == "file_drop":
        return artifact.get("file_path") or None
    return None


def find_artifact_in_findings(artifact: dict, findings_text: list[str]) -> tuple[bool, str | None]:
    """Return (detected, matching_finding_excerpt).

    A finding counts as detection only if it contains the artifact's
    discriminating locator (per type). Locators shorter than _MIN_LOCATOR_LEN
    are rejected to prevent false matches on tokens like "1", "Run", etc.
    file_drop additionally tries the backslash-escaped form for Windows paths.
    """
    locator = _artifact_match_locator(artifact)
    if not locator or len(locator) < _MIN_LOCATOR_LEN:
        return False, None
    needles = [locator.lower()]
    if artifact.get("type") == "file_drop":
        # Manifest paths use /; findings come in as json.dumps() output, which
        # escapes Windows backslashes into \\. Try both raw and JSON-escaped
        # backslash forms so a forward-slash manifest path catches the
        # finding's escaped backslash path.
        bs_path = ("\\" + locator.replace("/", "\\")).lower()
        needles.append(bs_path)
        needles.append(bs_path.replace("\\", "\\\\"))
        # 2026-04-30 fix: web-shell findings sometimes include only the
        # leaf filename + parent dir context (e.g. "portal_login.php (in
        # wwwroot)") rather than the full path. Add the basename as a
        # fallback needle when it is long enough to be discriminating.
        # iranapi_ics_phishing_webshell at run-004 surfaced as a real
        # web_shell finding but scored MISS because the matcher only
        # checked the full path.
        norm = locator.replace("\\", "/")
        basename = norm.rsplit("/", 1)[-1] if "/" in norm else norm
        if len(basename) >= _MIN_LOCATOR_LEN and basename.lower() not in needles:
            needles.append(basename.lower())
    for finding_blob in findings_text:
        blob_lc = finding_blob.lower()
        if any(n in blob_lc for n in needles):
            return True, finding_blob[:200]
    return False, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--findings", required=True, help="findings.json from pipeline run")
    ap.add_argument("--evidence", required=False, help="execute_evidence.jsonl (optional, for FP context)")
    ap.add_argument("--baseline-detected", default="", help="comma-separated baseline ids the pipeline DID find")
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-md", required=True)
    args = ap.parse_args()

    manifest = json.loads(Path(args.manifest).read_text())
    findings_obj = json.loads(Path(args.findings).read_text()) if Path(args.findings).exists() else {}

    # Flatten the findings object for substring matching
    findings_list = findings_obj if isinstance(findings_obj, list) else findings_obj.get("findings", [])
    findings_blobs = [json.dumps(f) for f in findings_list]
    info(f"loaded {len(findings_blobs)} findings from pipeline")

    # Regression: which baseline ids did the pipeline re-detect?
    detected_baselines = set([b.strip() for b in args.baseline_detected.split(",") if b.strip()])
    expected_baselines = manifest["base"].get("expected_baseline_findings", [])
    regression_pass = []
    regression_fail = []
    for entry in expected_baselines:
        bid = entry["id"]
        if bid in detected_baselines:
            regression_pass.append(bid)
        else:
            regression_fail.append(bid)

    # Extension: per-artifact PASS / MISS / EXPECTED-MISS
    rows = []
    extension_pass = 0
    extension_miss = 0
    expected_miss_pass = 0  # acknowledged-gap artifacts that the pipeline correctly did not detect
    expected_miss_unexpected_hit = 0  # acknowledged-gap artifacts the pipeline DID detect (bonus)
    for category in manifest["categories"]:
        for art in category["artifacts"]:
            detected, excerpt = find_artifact_in_findings(art, findings_blobs)
            expected = art.get("expected_detection")
            if expected == "expected_miss_documented_gap":
                # We expect this NOT to be detected; if it is, that's a positive surprise
                if detected:
                    expected_miss_unexpected_hit += 1
                    status = "BONUS"
                else:
                    expected_miss_pass += 1
                    status = "AS-EXPECTED-MISS"
            else:
                if detected:
                    extension_pass += 1
                    status = "PASS"
                else:
                    extension_miss += 1
                    status = "MISS"
            rows.append({
                "id": art["id"],
                "category": category["name"],
                "type": art["type"],
                "expected_detection": expected,
                "status": status,
                "detected": detected,
                "matching_excerpt": excerpt,
                "rationale": art.get("rationale", ""),
            })

    # Score blob
    score = {
        "manifest_id": manifest["manifest_id"],
        "regression": {
            "expected": [e["id"] for e in expected_baselines],
            "detected": list(detected_baselines),
            "pass": regression_pass,
            "fail": regression_fail,
        },
        "extension": {
            "total": extension_pass + extension_miss,
            "pass": extension_pass,
            "miss": extension_miss,
            "expected_miss_pass": expected_miss_pass,
            "expected_miss_unexpected_hit": expected_miss_unexpected_hit,
        },
        "per_artifact": rows,
    }
    Path(args.out_json).write_text(json.dumps(score, indent=2))
    info(f"score JSON written: {args.out_json}")

    # Build the report
    md = []
    md.append(f"# Daily synthetic-workstation run, {manifest['manifest_id']}")
    md.append("")
    md.append("## Regression on base-wkstn-05 originals")
    if regression_fail:
        md.append(f"REGRESSION: **FAIL** ({len(regression_pass)}/{len(expected_baselines)})")
        for fid in regression_fail:
            md.append(f"  - missed: `{fid}`")
        md.append("")
        md.append("**This is a build or pipeline regression. Investigate before trusting today's extension scores.**")
    else:
        md.append(f"REGRESSION: **PASS** ({len(regression_pass)}/{len(expected_baselines)})")
        for pid in regression_pass:
            md.append(f"  - re-detected: `{pid}`")
    md.append("")

    md.append("## Extension by category")
    by_cat: dict[str, list[dict]] = {}
    for r in rows:
        by_cat.setdefault(r["category"], []).append(r)
    for cat, cat_rows in by_cat.items():
        cat_pass = sum(1 for r in cat_rows if r["status"] == "PASS")
        cat_total = sum(1 for r in cat_rows if r["status"] in ("PASS", "MISS"))
        md.append(f"- **{cat}**: {cat_pass}/{cat_total}")
        for r in cat_rows:
            md.append(f"  - [{r['status']}] `{r['id']}` ({r['type']})")
            if r["status"] == "MISS":
                md.append(f"    - rationale: {r['rationale']}")
    md.append("")

    if expected_miss_pass + expected_miss_unexpected_hit > 0:
        md.append("## Acknowledged gaps")
        md.append(f"- as expected (correctly NOT detected): {expected_miss_pass}")
        md.append(f"- bonus (detected anyway by another signal): {expected_miss_unexpected_hit}")
        md.append("")

    md.append("## What is new in today's manifest")
    md.append(f"- intel_window_days: {manifest.get('intel_window_days', 'n/a')}")
    md.append(f"- intel_sources ({len(manifest.get('intel_sources', []))}):")
    for src in manifest.get("intel_sources", [])[:10]:
        md.append(f"  - {src}")
    md.append("")

    Path(args.out_md).write_text("\n".join(md) + "\n")
    info(f"report written: {args.out_md}")

    info(f"summary: regression {len(regression_pass)}/{len(expected_baselines)} | "
         f"extension {extension_pass}/{extension_pass + extension_miss} | "
         f"acknowledged-gaps as-expected {expected_miss_pass}, bonus {expected_miss_unexpected_hit}")


if __name__ == "__main__":
    main()
