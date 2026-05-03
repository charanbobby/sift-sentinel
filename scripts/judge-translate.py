#!/usr/bin/env python3
"""scripts/judge-translate.py

Translate a free-form judge scenario into a schema-valid manifest_v1.json
suitable for the synthetic-workstation builder. Promoted from the
experiments/slice-2-notebook/_judge_probe/ probe on 2026-05-02.

Reads a scenario from stdin (or --scenario-file). Calls Sonnet 4.6 via
OpenRouter. Validates output against manifest_schema.json and the supported
plant-type list. Overrides manifest_id with today's date plus a -judge-<id>
suffix because the LLM emits training-time dates that we cannot trust.

Usage:
    cat scenario.txt | OPENROUTER_API_KEY=... \
        scripts/judge-translate.py --job-id abc123 -o out/manifest.json

    scripts/judge-translate.py --scenario-file scenario.txt --job-id abc123

    # Offline validation of an existing manifest. No API call, no spend.
    scripts/judge-translate.py --validate-only -i existing_manifest.json --job-id check
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "experiments" / "synthetic-ai-workstation" / "manifest_schema.json"
EXAMPLE_PATH = REPO_ROOT / "experiments" / "synthetic-ai-workstation" / "manifest_v1.json"
CATALOG_PATH = REPO_ROOT / "docs" / "judges" / "supported-techniques.md"

MODEL = "anthropic/claude-sonnet-4-6"

SUPPORTED_PLANT_TYPES = {
    "file_drop",
    "scheduled_task_xml",
    "registry_run_key",
    "registry_service",
    "registry_binary_value",
}

# manifest_schema.json restricts manifest_id to a single optional alphanumeric
# suffix (no internal dashes), so the job_id we splice in must also be a
# single alphanumeric run. The "judge" identity travels via the job directory
# (out/judge-jobs/<job-id>/), not the manifest_id itself.
MANIFEST_ID_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(-[a-z0-9]+)?$")
JOB_ID_RE = re.compile(r"^[a-z0-9]+$")

SYSTEM_PROMPT_TEMPLATE = """You are a forensics scenario translator. A user describes an attack scenario in plain English. Your job: emit a JSON manifest that the synthetic-workstation builder can plant on a Windows NTFS image.

Output ONLY the JSON manifest. No prose, no code fences, no commentary. The manifest must validate against the schema below.

You must:
- Use only artifact types that the builder supports: file_drop, scheduled_task_xml, registry_run_key, registry_service, registry_binary_value.
- Pick a category from the enum: ai_attacker, ransomware_persistence, supply_chain, exploited_cves_in_wild, lolbin_abuse, apt_specific_ttp.
- Set expected_detection per artifact: attacker_persistence, attacker_persistence_ai_assisted, requires_disambiguation, tradecraft_signal, or expected_miss_documented_gap.
- Use example.invalid domains for any C2 references.
- Use ALLCAPS_PLACEHOLDER tokens for credentials.
- Each artifact id must match ^[a-z0-9_]+$.
- Include manifest_id (any YYYY-MM-DD value; the wrapper will overwrite it), and a base block pointing at base-wkstn-05 by default.

Reject scenarios that imply memory-only artifacts or domain-controller compromise; emit a manifest with a single artifact of type expected_miss_documented_gap explaining the rejection.

SCHEMA:
%(schema)s

REFERENCE EXAMPLE (a real working manifest, abridged):
%(example)s

CAPABILITY CATALOG:
%(catalog)s
"""


def inject_manifest_id(manifest: dict, today: str, job_id: str) -> dict:
    """Override manifest_id with today's date plus a judge suffix.

    The LLM emits manifest_id from training time (we have observed
    "2025-01-30-judge"). For job tracking we want today's date and an
    operator-supplied job id. Returns the manifest unchanged except for
    manifest_id; the caller may pass the same dict or a copy.

    Raises ValueError if today or job_id are not the right shape.
    """
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", today):
        raise ValueError(f"today must be YYYY-MM-DD, got {today!r}")
    if not JOB_ID_RE.fullmatch(job_id):
        raise ValueError(
            f"job_id must match {JOB_ID_RE.pattern!r}, got {job_id!r}"
        )
    new_id = f"{today}-{job_id}"
    if not MANIFEST_ID_RE.fullmatch(new_id):
        raise ValueError(f"computed manifest_id {new_id!r} fails schema regex")
    manifest["manifest_id"] = new_id
    return manifest


def validate_manifest(manifest: dict, schema: dict) -> list[str]:
    """Run schema + plant-type validation. Return a list of error messages,
    empty if the manifest is acceptable.

    Two-stage check:
    1. jsonschema validation against manifest_schema.json.
    2. Every artifact must use a plant type the builder supports OR be
       marked expected_miss_documented_gap.
    """
    errors: list[str] = []

    try:
        import jsonschema
    except ImportError:
        errors.append("jsonschema not installed; cannot run schema validation (uv pip install jsonschema)")
    else:
        try:
            jsonschema.validate(manifest, schema)
        except jsonschema.ValidationError as e:
            path = "/".join(str(p) for p in e.absolute_path) or "<root>"
            errors.append(f"schema violation at {path}: {e.message}")

    bad: list[tuple[str, str]] = []
    for cat in manifest.get("categories", []) or []:
        for art in cat.get("artifacts", []) or []:
            t = art.get("type")
            if t not in SUPPORTED_PLANT_TYPES and art.get("expected_detection") != "expected_miss_documented_gap":
                bad.append((art.get("id", "<no-id>"), t or "<no-type>"))
    if bad:
        errors.append(
            f"unsupported plant types (not in builder DISPATCH): {bad}"
        )

    return errors


def _abridge_example(example_full: dict) -> dict:
    """Trim the reference manifest to a prompt-safe size."""
    return {
        "manifest_id": example_full["manifest_id"],
        "intel_window_days": example_full.get("intel_window_days"),
        "intel_sources": example_full.get("intel_sources", [])[:2],
        "base": example_full["base"],
        "categories": [
            {
                "name": c["name"],
                "rationale": c["rationale"][:200],
                "artifacts": c["artifacts"][:2],
            }
            for c in example_full["categories"][:1]
        ],
    }


def build_system_prompt(schema_text: str, catalog_text: str, example_text: str) -> str:
    return SYSTEM_PROMPT_TEMPLATE % {
        "schema": schema_text,
        "example": example_text,
        "catalog": catalog_text,
    }


def call_sonnet(api_key: str, messages: list[dict]) -> tuple[str, dict]:
    """Make the OpenRouter call. Returns (content_text, usage_dict)."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from llm_cost import cost_pre, cost_post

    cost_pre("judge-translate", MODEL, messages)

    body = {
        "model": MODEL,
        "messages": messages,
        "temperature": 0,
        "usage": {"include": True},
    }
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/charanbobby/find-evil",
            "X-Title": "find-evil judge translator",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        out = json.loads(resp.read())

    usage = out.get("usage", {}) or {}
    cost_post("judge-translate", MODEL, usage)

    content = out["choices"][0]["message"]["content"].strip()
    if content.startswith("```"):
        content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    return content, usage


def translate(scenario: str, api_key: str) -> dict:
    """End-to-end: scenario string -> parsed manifest dict (raw, pre-injection)."""
    schema_text = SCHEMA_PATH.read_text(encoding="utf-8")
    catalog_text = CATALOG_PATH.read_text(encoding="utf-8")
    example_full = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
    example_text = json.dumps(_abridge_example(example_full), indent=2)

    system_prompt = build_system_prompt(schema_text, catalog_text, example_text)
    print(f"[judge-translate] system prompt size: {len(system_prompt):,} chars (~{len(system_prompt)//4:,} tokens)", file=sys.stderr)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Scenario:\n{scenario.strip()}\n\nProduce the manifest JSON now."},
    ]

    content, _usage = call_sonnet(api_key, messages)
    return json.loads(content)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Translate a judge scenario into a manifest.")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--scenario-file", type=Path, help="Read scenario from this file. Default: stdin.")
    src.add_argument("-i", "--input-manifest", type=Path, help="Skip the LLM call; validate this existing manifest. Implies --validate-only.")
    p.add_argument("-o", "--output", type=Path, help="Write manifest JSON here. Default: stdout.")
    p.add_argument("--job-id", required=True, help="Job id (lowercase + dashes/digits) used in manifest_id suffix.")
    p.add_argument("--today", default=None, help="Override today's date (YYYY-MM-DD). Default: UTC today.")
    p.add_argument("--validate-only", action="store_true", help="Do not call the LLM; validate existing input only. Requires -i.")
    args = p.parse_args(argv)

    if args.input_manifest and not args.validate_only:
        args.validate_only = True

    today = args.today or _dt.datetime.utcnow().strftime("%Y-%m-%d")

    if args.validate_only:
        if not args.input_manifest:
            print("--validate-only requires -i / --input-manifest", file=sys.stderr)
            return 2
        manifest = json.loads(args.input_manifest.read_text(encoding="utf-8"))
    else:
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            print("OPENROUTER_API_KEY not set", file=sys.stderr)
            return 2
        if args.scenario_file:
            scenario = args.scenario_file.read_text(encoding="utf-8")
        else:
            scenario = sys.stdin.read()
        if not scenario.strip():
            print("scenario is empty", file=sys.stderr)
            return 2
        manifest = translate(scenario, api_key)

    inject_manifest_id(manifest, today, args.job_id)

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = validate_manifest(manifest, schema)
    if errors:
        print("[judge-translate] validation FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        # Still emit the manifest so the operator can inspect it
        sink = args.output.open("w", encoding="utf-8") if args.output else sys.stdout
        json.dump(manifest, sink, indent=2)
        if args.output:
            sink.close()
        return 1

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"[judge-translate] OK: wrote {args.output}", file=sys.stderr)
    else:
        json.dump(manifest, sys.stdout, indent=2)
        sys.stdout.write("\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
