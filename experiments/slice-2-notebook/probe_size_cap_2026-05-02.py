"""Probe: bundle size cap + per-host budget ceiling in pipeline.nodes.

Added 2026-05-02 ahead of the 13-host standalone memory sweep. Verifies:
  1. _cap_bundle_size hard-trims oversized bundles below 600KB and caps known
     list fields (connections, processes) and long string fields.
  2. _cap_bundle_size is a no-op (returns the same object) for under-soft input.
  3. _llm_cost_post accumulates `usage.cost` and raises BudgetExceeded when
     RUN_COST_LIMIT_USD is crossed.
  4. RUN_COST_LIMIT_USD=0 disables the budget check.

Run inside sift-sentinel:
  docker cp experiments/slice-2-notebook/probe_size_cap_2026-05-02.py \\
      sift-sentinel:/workspace/probe_size_cap_2026-05-02.py
  docker exec sift-sentinel /workspace/.venv/bin/python \\
      /workspace/probe_size_cap_2026-05-02.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, "/workspace")
from pipeline import nodes as N


class _FakeUsage:
    def __init__(self, cost: float, prompt_tokens: int = 1000,
                 completion_tokens: int = 500):
        self.cost = cost
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.cost_details = {}


def make_oversized_bundle() -> dict:
    big = "X" * 50_000
    conn_template = {
        "pid": 0, "foreign_address": "1.2.3.4:80",
        "state": "CLOSE_WAIT", "owner": "x",
    }
    return {
        "question": "test",
        "case_id": "probe",
        "_canary": "",
        "steps": [
            {
                "step_id": "1",
                "tool_call_id": "tc-1",
                "tool": "volatility_run",
                "purpose": big,
                "expected_paths_covered": [big] * 3,
                "tool_execution_status": "ok",
                "_untrusted_begin": "BEGIN",
                "structured_fields": {
                    "plugin_name": "netscan",
                    "connections": [
                        {**conn_template, "pid": i,
                         "foreign_address": f"1.2.3.{i % 255}:80"}
                        for i in range(5000)
                    ],
                    "raw_blob": big,
                },
                "_untrusted_end": "END",
            },
            {
                "step_id": "2",
                "tool_call_id": "tc-2",
                "tool": "volatility_run",
                "purpose": "small",
                "expected_paths_covered": [],
                "tool_execution_status": "ok",
                "_untrusted_begin": "BEGIN",
                "structured_fields": {
                    "plugin_name": "pslist",
                    "processes": [
                        {"pid": i, "name": f"proc{i}.exe", "ppid": 4}
                        for i in range(800)
                    ],
                },
                "_untrusted_end": "END",
            },
        ],
    }


def main() -> int:
    failures: list[str] = []

    print("=== bundle cap ===")
    big = make_oversized_bundle()
    orig_size = N._bundle_size_bytes(big)
    print(f"  orig size={orig_size:,}")
    if orig_size <= N._BUNDLE_HARD_CAP_BYTES:
        failures.append(f"test bundle not large enough: {orig_size}")

    trimmed = N._cap_bundle_size(big)
    new_size = N._bundle_size_bytes(trimmed)
    print(f"  trimmed size={new_size:,}")
    if new_size > N._BUNDLE_HARD_CAP_BYTES:
        failures.append(f"trim did not bring bundle under cap: {new_size}")
    conns = trimmed["steps"][0]["structured_fields"]["connections"]
    if len(conns) != 200:
        failures.append(f"connections cap broken: {len(conns)}")
    procs = trimmed["steps"][1]["structured_fields"]["processes"]
    if len(procs) != 300:
        failures.append(f"processes cap broken: {len(procs)}")
    purpose = trimmed["steps"][0]["purpose"]
    if not (isinstance(purpose, str) and purpose.endswith("...[truncated]")):
        failures.append("purpose was not truncated")
    raw_blob = trimmed["steps"][0]["structured_fields"]["raw_blob"]
    if not (isinstance(raw_blob, str) and raw_blob.endswith("...[truncated]")):
        failures.append("raw_blob was not truncated")

    print("\n=== under-soft no-op ===")
    small = {"question": "q", "case_id": "c", "_canary": "",
             "steps": [{"step_id": "1", "structured_fields": {"a": "b"}}]}
    out = N._cap_bundle_size(small)
    if out is not small:
        failures.append("under-soft should be passthrough (same object)")

    print("\n=== per-host budget via _llm_cost_post ===")
    N._reset_run_cost()
    os.environ["RUN_COST_LIMIT_USD"] = "1.00"
    try:
        N._llm_cost_post("plan", "test-model", _FakeUsage(0.40))
        N._llm_cost_post("interpret", "test-model", _FakeUsage(0.40))
    except N.BudgetExceeded as e:
        failures.append(f"budget triggered too early: {e}")
    try:
        N._llm_cost_post("interpret_retry", "test-model", _FakeUsage(0.50))
    except N.BudgetExceeded as e:
        print(f"  expected raise: {e}")
    else:
        failures.append("budget did not trigger on third call")

    print("\n=== budget disable (RUN_COST_LIMIT_USD=0) ===")
    N._reset_run_cost()
    os.environ["RUN_COST_LIMIT_USD"] = "0"
    try:
        N._llm_cost_post("plan", "test-model", _FakeUsage(100.0))
    except N.BudgetExceeded as e:
        failures.append(f"limit=0 should disable but raised: {e}")
    else:
        print(f"  no raise (expected, limit disabled)")

    print("\n=== budget invalid env falls back to 1.50 ===")
    os.environ["RUN_COST_LIMIT_USD"] = "not-a-number"
    if abs(N._budget_limit_usd() - 1.50) > 0.001:
        failures.append("invalid env should fall back to 1.50")
    else:
        print("  fallback ok")

    print("\n=== summary ===")
    if failures:
        print(f"FAILURES: {len(failures)}")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("ALL PROBES OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
