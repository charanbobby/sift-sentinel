"""Probe model candidates for the PLAN phase.

Runs the *current* C6 production PLAN prompt against N candidate models via
OpenRouter. For each candidate, runs TWO calls:

    call #1 → cache write (system block marked `cache_control: ephemeral`)
    call #2 → cache hit  (should surface non-zero `cached_tokens`)

For each call, captures: usage (prompt / completion / cached), cost, latency,
the raw response. For the first call, parses to `ToolPlan` and runs the three
structural invariants (regripper→icat, no inode=0 literal, placeholder syntax).

Scope: one-shot screening tool, NOT cross-validation. Real cross-val = Slice 4.
Budget: self-limits to $BUDGET_CAP_USD across all calls; stops on breach.

Output:
    stdout   — comparison table
    out/model_probe.json — full results + per-call metrics + raw outputs

DRIFT WARNING: this file duplicates `AVAILABLE_TOOLS`, the schemas, and
`PLAN_SYSTEM_PROMPT` from slice2.ipynb C2 + C6. When the C6 prompt changes,
update this file too. Manually in sync beats exec'ing notebook cells for this
throwaway eval tool.

Run:
    docker exec -w /workspace find-evil-notebook uv run python probe_plan_models.py
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Literal, Optional

from openai import OpenAI
from pydantic import BaseModel

# ======================================================================
# CONFIG — edit in-place to add / remove candidates or raise the cap
# ======================================================================

CANDIDATES = [
    "anthropic/claude-sonnet-4.6",   # baseline = current production
    "anthropic/claude-haiku-4.5",    # cheapest Anthropic option
    "z-ai/glm-5.1",                  # Arena Code #4, ~25% of Sonnet cost
]

# cache_control is Anthropic-specific syntax; OpenRouter passes it through.
# Verified 2026-04-19: all three candidates accept the block without erroring,
# and cached_tokens fires on the second call. Any candidate NOT in this set will
# have cache_control stripped to avoid spurious errors.
CANDIDATES_SUPPORT_CACHE_CONTROL = {
    "anthropic/claude-sonnet-4.6",
    "anthropic/claude-haiku-4.5",
    "z-ai/glm-5.1",
}

BUDGET_CAP_USD = 0.50
CASE_ID   = "srl-2018-wkstn-05"
E01_PATH  = "/mnt/hackathon/base-wkstn-05-cdrive.E01"

# ======================================================================
# SCHEMAS — duplicated from slice2.ipynb C2 (keep in sync)
# ======================================================================

Confidence = Literal["low", "medium", "high"]

class PlannedStep(BaseModel):
    step_id: int
    tool: Literal["fsstat_e01", "fls_list", "icat_extract", "regripper_run"]
    args: dict
    purpose: str
    depends_on: list[int]
    confidence: Confidence

class ToolPlan(BaseModel):
    question: str
    steps: list[PlannedStep]
    expected_findings_range: tuple[int, int]

# ======================================================================
# PROMPT — duplicated from slice2.ipynb C6 (keep in sync)
# ======================================================================

AVAILABLE_TOOLS = {
    "fsstat_e01": {
        "description": "Run `fsstat` on an E01 image. Returns filesystem metadata (type, block size, MFT offset for NTFS).",
        "args": {"e01_path": "absolute path to the E01 under /mnt/hackathon/"},
    },
    "fls_list": {
        "description": "Run `fls` — list directory entries (includes deleted). Use iteratively to locate hive file inodes inside Windows/System32/config/ and user profile folders.",
        "args": {
            "e01_path": "absolute path to the E01",
            "parent_inode": "int OR placeholder OR null; null lists the root",
            "recurse": "bool; True walks the whole subtree (expensive — only use on small subtrees like Users/<name>/)",
        },
    },
    "icat_extract": {
        "description": "Extract a file's bytes by inode out of the E01 into <case>/analysis/extracted/<dest_filename>. Use before regripper_run to stage registry hive bytes.",
        "args": {
            "e01_path": "absolute path to the E01",
            "inode": "int OR placeholder (must come from a prior fls_list step via a binding)",
            "dest_filename": "plain filename (no path separators), e.g. 'SOFTWARE', 'SYSTEM', 'NTUSER-administrator.DAT'",
        },
    },
    "regripper_run": {
        "description": "Run a named RegRipper plugin against a hive previously extracted by icat_extract. The server rejects any hive_path not under <case>/analysis/extracted/, so every regripper_run MUST have an icat_extract upstream in depends_on.",
        "args": {
            "hive_path": f"absolute path; must be exactly /home/sansforensics/cases/{CASE_ID}/analysis/extracted/<dest_filename> where <dest_filename> matches the upstream icat_extract step",
            "plugin": "plugin name from the allowlist below",
        },
        "plugin_allowlist": {
            "run":          "hive: Software or NTUSER.DAT — Run / RunOnce keys (most common persistence)",
            "runonceex":    "hive: Software — RunOnceEx keys",
            "services":     "hive: System — CurrentControlSet\\Services (SYSTEM-privilege persistence)",
            "schedagent":   "hive: Software — scheduled-task tracking",
            "appinitdlls":  "hive: Software — AppInit_DLLs (DLL injection into every GUI process)",
            "imagefile":    "hive: Software — Image File Execution Options / debuggers (IFEO)",
            "winlogon_tln": "hive: Software — Winlogon Userinit / Shell / Notify",
        },
    },
}

TOOL_PLAN_SCHEMA = json.dumps(ToolPlan.model_json_schema(), indent=2)
TOOLS_SPEC       = json.dumps(AVAILABLE_TOOLS, indent=2)

PLAN_SYSTEM_PROMPT = f"""You design a tool-call plan to answer a forensic question, using ONLY the 4 tools
available below. You are NOT executing anything — only producing a plan that a human
will review before any tool runs.

Return a single JSON object matching exactly this schema (no prose, no markdown fences):

{TOOL_PLAN_SCHEMA}

Case constants (use these LITERAL values — do NOT invent paths):
- case_id:        {CASE_ID}
- e01_path:       {E01_PATH}
- extracted_dir:  /home/sansforensics/cases/{CASE_ID}/analysis/extracted

Available tools:
{TOOLS_SPEC}

Argument templating (READ THIS BEFORE WRITING ANY STEP):
- Inodes are not known at planning time — they come from upstream `fls_list` output.
  DO NOT guess. DO NOT write `"inode": 0` or any made-up number. Write a placeholder:
      "{{step:N.EXTRACTOR(PARAM)}}"
  The executor substitutes it before calling the tool. Step N MUST appear in the same
  step's `depends_on`.
- Available extractor (only one):
      inode_by_name(FILENAME)   # FILENAME is a basename, case-insensitive
          e.g. "inode": "{{step:5.inode_by_name(SOFTWARE)}}"

Filesystem navigation (use placeholders; do NOT emit duplicate fls_list calls):
- To drill from root to /Windows/System32/config, chain fls_list calls via parent_inode:
      step 2: fls_list(parent_inode=null, recurse=false)                                    # list root
      step 3: fls_list(parent_inode="{{step:2.inode_by_name(Windows)}}",  recurse=false)    # list /Windows
      step 4: fls_list(parent_inode="{{step:3.inode_by_name(System32)}}", recurse=false)    # list /Windows/System32
      step 5: fls_list(parent_inode="{{step:4.inode_by_name(config)}}",   recurse=false)    # list .../config
      step 6: icat_extract(inode="{{step:5.inode_by_name(SOFTWARE)}}", dest_filename="SOFTWARE")
      step 7: icat_extract(inode="{{step:5.inode_by_name(SYSTEM)}}",   dest_filename="SYSTEM")
- If two steps would have identical (parent_inode, recurse) args, collapse them into
  ONE step — downstream steps can reference the same fls_list output.

Hard rules:
- To inspect a registry hive you MUST first call `icat_extract` on it, then call
  `regripper_run` with `hive_path` = /home/sansforensics/cases/{CASE_ID}/analysis/extracted/<dest_filename>
  where <dest_filename> matches the upstream icat_extract step. Every `regripper_run`
  step MUST list the corresponding `icat_extract` step_id in `depends_on`.
- `regripper_run.plugin` MUST be one of the allowlisted plugin names above. Do NOT
  invent plugin names. Pick the plugin whose expected hive matches the hive you extracted.
- For per-user persistence (Run keys in NTUSER.DAT), plan one icat_extract per user's
  NTUSER.DAT — use dest_filename like 'NTUSER-<username>.DAT' to keep them distinct.
  User profile directories live under /Users (Windows 10+) or /Documents and Settings (XP).

Soft rules:
- Score `confidence` for each step INDEPENDENTLY. Do not default to "high". Rate each
  step based on how directly its output contributes to answering the question (an
  `fsstat_e01` is usually "high" for confirming layout; an `fls_list` navigation step
  is "medium" because its value is discovering inodes, not producing findings).
- Set `expected_findings_range` based on typical compromised Windows hosts (usually 1-5
  persistence mechanisms). Emit as a 2-element JSON array, e.g. [1, 5].
- Every step MUST have a non-empty `purpose` (one sentence).
- Dependencies: if step N needs output from step M, set depends_on=[M]. Otherwise [].
"""

# ======================================================================
# VALIDATOR — duplicated from slice2.ipynb C6 (keep in sync)
# ======================================================================

PLACEHOLDER_RE  = re.compile(r"^\{step:(\d+)\.(\w+)\(([^)]*)\)\}$")
KNOWN_EXTRACTORS = {"inode_by_name"}

def validate_plan(tp: ToolPlan) -> dict:
    violations: list[str] = []
    steps_by_id = {s.step_id: s for s in tp.steps}
    for s in tp.steps:
        if s.tool == "regripper_run":
            upstreams = [steps_by_id.get(d) for d in s.depends_on]
            if not any(u and u.tool == "icat_extract" for u in upstreams):
                violations.append(f"step {s.step_id}: regripper_run has no icat_extract in depends_on")
        if s.tool == "icat_extract" and s.args.get("inode") == 0:
            violations.append(f"step {s.step_id}: icat_extract inode=0 literal disallowed")
        for k, v in s.args.items():
            if not isinstance(v, str):
                continue
            stripped = v.strip()
            if not stripped.startswith("{step:"):
                continue
            m = PLACEHOLDER_RE.match(stripped)
            if not m:
                violations.append(f"step {s.step_id}: malformed placeholder in args.{k}: {v!r}")
                continue
            ref, ext, param = int(m.group(1)), m.group(2), m.group(3)
            if ref not in s.depends_on:
                violations.append(f"step {s.step_id}: args.{k} references step {ref} not in depends_on={s.depends_on}")
            if ext not in KNOWN_EXTRACTORS:
                violations.append(f"step {s.step_id}: unknown extractor {ext!r} in args.{k}")
            if not param.strip():
                violations.append(f"step {s.step_id}: empty extractor param in args.{k}")
    return {
        "n_dep":         sum(1 for v in violations if "has no icat_extract" in v),
        "n_inode0":      sum(1 for v in violations if "inode=0" in v),
        "n_placeholder": sum(1 for v in violations if ("placeholder" in v or "extractor" in v or "empty extractor" in v)),
        "total":         len(violations),
        "violations":    violations,
    }

# ======================================================================
# HELPERS
# ======================================================================

def parse_json_response(raw: str, model_cls):
    """Strip optional ```json fences, then Pydantic-validate."""
    s = (raw or "").strip()
    if s.startswith("```"):
        s = re.sub(r"^```(?:json|JSON)?\s*", "", s)
        s = re.sub(r"\s*```\s*$", "", s)
    return model_cls.model_validate_json(s)

def build_messages(system_prompt: str, user_input: str, *, with_cache: bool) -> list[dict]:
    """Same message shape as C6, toggling cache_control on the system block."""
    if with_cache:
        system_content = [{
            "type": "text",
            "text": system_prompt,
            "cache_control": {"type": "ephemeral"},
        }]
    else:
        system_content = system_prompt
    return [
        {"role": "system", "content": system_content},
        {"role": "user",   "content": user_input},
    ]

def call_one(client: OpenAI, model: str, messages: list[dict]) -> dict:
    """One OpenRouter call. Returns a result dict (never raises — errors captured)."""
    t0 = time.monotonic()
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            response_format={"type": "json_object"},
        )
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "latency_ms": int((time.monotonic() - t0) * 1000)}
    latency_ms = int((time.monotonic() - t0) * 1000)
    u = resp.usage.model_dump() if resp.usage else {}
    ptd = (u.get("prompt_tokens_details") or {})
    return {
        "ok": True,
        "content": resp.choices[0].message.content,
        "finish_reason": resp.choices[0].finish_reason,
        "prompt_tokens":     u.get("prompt_tokens"),
        "completion_tokens": u.get("completion_tokens"),
        "cached_tokens":     ptd.get("cached_tokens"),
        "cache_write_tokens": ptd.get("cache_write_tokens"),
        "cost":   u.get("cost", 0.0),
        "latency_ms": latency_ms,
    }

# ======================================================================
# MAIN
# ======================================================================

def main() -> int:
    # Load the latest EXTRACT output — candidates.json from the live C5 run.
    cands_path = Path("out/candidates.json")
    if not cands_path.exists():
        print(f"ERROR: {cands_path} not found. Run C5 EXTRACT in the notebook first.")
        return 2
    cands = json.loads(cands_path.read_text(encoding="utf-8"))
    # Flat user_input matches what C6 sends (candidates as a list, not nested).
    user_input = json.dumps({
        "question":   cands["question"],
        "candidates": cands["candidates"],
    }, indent=2)

    client = OpenAI(
        api_key=os.environ["OPENROUTER_API_KEY"],
        base_url="https://openrouter.ai/api/v1",
    )

    per_model: list[dict] = []
    total_spend = 0.0

    for model in CANDIDATES:
        print(f"\n=== {model} ===")
        use_cache = model in CANDIDATES_SUPPORT_CACHE_CONTROL
        if not use_cache:
            print(f"  (cache_control stripped — model not in allowlist)")

        messages = build_messages(PLAN_SYSTEM_PROMPT, user_input, with_cache=use_cache)

        # --- Call 1 (cache WRITE if supported) ---
        if total_spend >= BUDGET_CAP_USD:
            per_model.append({"model": model, "skipped": "budget_cap", "before_spend": total_spend})
            print(f"  SKIP — budget cap hit (${total_spend:.4f} ≥ ${BUDGET_CAP_USD})")
            continue
        c1 = call_one(client, model, messages)
        total_spend += c1.get("cost", 0.0)
        if not c1["ok"]:
            per_model.append({"model": model, "call1": c1, "call2": None, "parse": None, "invariants": None})
            print(f"  call1 ERROR: {c1['error']}")
            continue

        # Parse + validate call 1's output
        try:
            tp = parse_json_response(c1["content"], ToolPlan)
            inv = validate_plan(tp)
            parse = {
                "ok": True,
                "n_steps": len(tp.steps),
                "n_icat": sum(1 for s in tp.steps if s.tool == "icat_extract"),
                "n_rip":  sum(1 for s in tp.steps if s.tool == "regripper_run"),
            }
        except Exception as e:
            tp = None
            inv = None
            parse = {"ok": False, "err": f"{type(e).__name__}: {e}"}

        # --- Call 2 (cache HIT if call 1 wrote) ---
        if total_spend >= BUDGET_CAP_USD:
            c2 = {"ok": False, "skipped": "budget_cap"}
        else:
            c2 = call_one(client, model, messages)
            total_spend += c2.get("cost", 0.0)

        per_model.append({
            "model": model,
            "used_cache_control": use_cache,
            "call1": c1,
            "call2": c2,
            "parse": parse,
            "invariants": inv,
        })

        # Inline status
        if parse["ok"]:
            inv_str = f"inv OK" if inv["total"] == 0 else f"inv FAIL ({inv['total']} viol: dep={inv['n_dep']} inode0={inv['n_inode0']} ph={inv['n_placeholder']})"
            print(f"  call1: steps={parse['n_steps']:>2}  icat={parse['n_icat']}  rip={parse['n_rip']}  {inv_str}  ${c1['cost']:.4f}  {c1['latency_ms']}ms")
        else:
            print(f"  call1: PARSE FAIL — {parse['err']}  ${c1['cost']:.4f}")
        if c2.get("ok"):
            hit = c2["cached_tokens"] or 0
            print(f"  call2: cached_tokens={hit}  ${c2['cost']:.4f}  {c2['latency_ms']}ms")
        elif c2.get("skipped"):
            print(f"  call2: SKIP — budget")
        else:
            print(f"  call2: ERROR {c2.get('error','?')}")

    # ----- Final table -----
    print("\n" + "=" * 110)
    hdr = f"{'model':<40} {'steps':>5} {'inv':>5} {'1st $':>8} {'2nd $':>8} {'cache%':>7} {'total $':>8} {'1st lat':>7}"
    print(hdr)
    print("-" * 110)
    for r in per_model:
        if "skipped" in r:
            print(f"{r['model']:<40} {'-':>5} {'-':>5} {'-':>8} {'-':>8} {'-':>7} {'SKIP':>8} {'-':>7}")
            continue
        c1, c2, p, inv = r["call1"], r["call2"], r["parse"], r["invariants"]
        steps   = p["n_steps"] if p and p.get("ok") else "-"
        inv_s   = "OK" if (inv and inv["total"] == 0) else (f"F{inv['total']}" if inv else "PARSE")
        cost1   = f"${c1['cost']:.4f}"
        cost2   = f"${c2['cost']:.4f}" if c2.get("ok") else "-"
        cache_r = ""
        if c2.get("ok") and c2.get("cached_tokens"):
            total_in = (c2.get("prompt_tokens") or 0) + (c2.get("cached_tokens") or 0)
            cache_r = f"{(c2['cached_tokens'] / max(total_in, 1)) * 100:.0f}%" if total_in else "-"
        else:
            cache_r = "-"
        total   = f"${(c1['cost'] + (c2.get('cost',0) if c2.get('ok') else 0)):.4f}"
        latency = f"{c1['latency_ms']/1000:.1f}s"
        print(f"{r['model']:<40} {str(steps):>5} {inv_s:>5} {cost1:>8} {cost2:>8} {cache_r:>7} {total:>8} {latency:>7}")

    print(f"\ntotal spend: ${total_spend:.4f}  (cap: ${BUDGET_CAP_USD})")

    # ----- Persist full results -----
    out = Path("out/model_probe.json")
    out.write_text(json.dumps({
        "candidates": CANDIDATES,
        "budget_cap_usd": BUDGET_CAP_USD,
        "total_spend_usd": total_spend,
        "results": per_model,
    }, indent=2, default=str), encoding="utf-8")
    print(f"full results → {out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
