"""Probe: prompt builders for all three channel modes.

Strategy: byte-equality regression check.
  Phase 1 (--snapshot, run pre-refactor): capture current outputs for the two
    working modes (disk-only, dual) into gold files.
  Phase 2 (--check, run after each refactor edit): re-run the builders and
    assert the outputs match gold byte-for-byte. Plus assert that memory-only
    mode now produces a sensible prompt (no disk-rules sections).

This protects the legacy paths from regression while the refactor is under way.

Run inside sift-sentinel:
    docker exec sift-sentinel /workspace/.venv/bin/python \\
        /workspace/probe_memory_only_prompts_2026-05-02.py --snapshot
    # ... edit nodes.py ...
    docker exec sift-sentinel /workspace/.venv/bin/python \\
        /workspace/probe_memory_only_prompts_2026-05-02.py --check
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, "/workspace")
from pipeline import nodes as N

CASE_ID = "srl-2018-base-wkstn-05-dual"
DISK_PATH = "/mnt/hackathon/base-wkstn-05-cdrive.E01"
MEM_PATH = "/tmp/base-wkstn-05-memory.img"
MEM_PROFILE = "Win7SP1x64"
HOST_TYPE = "workstation"
HOST_DESC = "Generic Win10 workstation"

GOLD_DIR = Path("/tmp/probe_memory_only_gold")

GOLDS = {
    "plan_disk_only":   lambda: N._plan_system_prompt(CASE_ID, DISK_PATH, None, None),
    "plan_dual":        lambda: N._plan_system_prompt(CASE_ID, DISK_PATH, MEM_PATH, MEM_PROFILE),
    "extract_disk_only": lambda: N._build_extract_prompt(HOST_TYPE, HOST_DESC, has_memory=False),
    "extract_dual":      lambda: N._build_extract_prompt(HOST_TYPE, HOST_DESC, has_memory=True),
}


def snapshot() -> int:
    GOLD_DIR.mkdir(parents=True, exist_ok=True)
    for name, fn in GOLDS.items():
        out = fn()
        path = GOLD_DIR / f"{name}.txt"
        path.write_text(out, encoding="utf-8")
        print(f"  [snap] {path} ({len(out):,} chars)")
    print(f"\nSNAPSHOT WRITTEN to {GOLD_DIR}")
    return 0


def _diff_first_lines(a: str, b: str, n: int = 5) -> str:
    """Return the first n line-level differences (1-based line numbers)."""
    al = a.splitlines()
    bl = b.splitlines()
    out: list[str] = []
    for i, (la, lb) in enumerate(zip(al, bl), 1):
        if la != lb:
            out.append(f"  line {i} A: {la[:120]!r}")
            out.append(f"  line {i} B: {lb[:120]!r}")
            if len(out) // 2 >= n:
                break
    if len(al) != len(bl):
        out.append(f"  (line counts differ: A={len(al)} B={len(bl)})")
    return "\n".join(out)


def check() -> int:
    failures: list[str] = []

    print("=== regression check (gold byte-equality) ===")
    for name, fn in GOLDS.items():
        gold_path = GOLD_DIR / f"{name}.txt"
        if not gold_path.exists():
            print(f"  [SKIP] no gold for {name} (run --snapshot first)")
            failures.append(f"missing gold {name}")
            continue
        gold = gold_path.read_text(encoding="utf-8")
        actual = fn()
        if actual == gold:
            print(f"  [OK ] {name} byte-equal to gold")
        else:
            print(f"  [FAIL] {name} REGRESSED")
            print(_diff_first_lines(gold, actual))
            failures.append(f"regression {name}")

    print("\n=== memory-only mode (NEW) ===")
    # PLAN memory-only must build, omit the disk-only rule sections, keep the schema + memory rules.
    try:
        plan_mo = N._plan_system_prompt(CASE_ID, None, MEM_PATH, MEM_PROFILE)
    except Exception as e:
        print(f"  [FAIL] memory-only PLAN crashed: {type(e).__name__}: {e}")
        failures.append("memory-only PLAN crash")
        plan_mo = None

    if plan_mo is not None:
        # MUST contain
        for s in ["volatility_run", "pslist", "memory_image", "memory_profile",
                  "Memory-evidence rules", "Soft rules"]:
            ok = s in plan_mo
            print(f"  [{'OK ' if ok else 'FAIL'}] memory-only PLAN contains {s!r}")
            if not ok:
                failures.append(f"memory-only PLAN missing {s!r}")
        # MUST NOT contain (disk-rules sections)
        for s in ["Argument templating", "Filesystem navigation",
                  "icat_extract", "regripper_run", "fls_list",
                  "/Windows/System32/config"]:
            ok = s not in plan_mo
            print(f"  [{'OK ' if ok else 'FAIL'}] memory-only PLAN omits {s!r}")
            if not ok:
                failures.append(f"memory-only PLAN should omit {s!r}")
        # e01_path constant should not appear (no disk path to template)
        ok = "e01_path:" not in plan_mo
        print(f"  [{'OK ' if ok else 'FAIL'}] memory-only PLAN omits 'e01_path:' constant")
        if not ok:
            failures.append("memory-only PLAN should omit e01_path constant")

    # EXTRACT memory-only must build via has_disk=False, omit universal-Windows-persistence section
    try:
        extract_mo = N._build_extract_prompt(HOST_TYPE, HOST_DESC, has_memory=True, has_disk=False)
    except TypeError as e:
        print(f"  [FAIL] _build_extract_prompt missing has_disk param: {e}")
        failures.append("_build_extract_prompt missing has_disk param")
        extract_mo = None
    except Exception as e:
        print(f"  [FAIL] memory-only EXTRACT crashed: {type(e).__name__}: {e}")
        failures.append("memory-only EXTRACT crash")
        extract_mo = None

    if extract_mo is not None:
        # MUST contain memory artifact_types so the LLM knows what to emit;
        # MEMORY-ONLY CASE header tells it disk artifact_types are forbidden.
        for s in ["MEMORY-ONLY CASE", "process_anomaly",
                  "network_connection", "injected_region"]:
            ok = s in extract_mo
            print(f"  [{'OK ' if ok else 'FAIL'}] memory-only EXTRACT contains {s!r}")
            if not ok:
                failures.append(f"memory-only EXTRACT missing {s!r}")
        # MUST NOT contain (disk persistence sections)
        for s in ["Universal Windows persistence locations",
                  "File-drop staging locations",
                  "Web-shell drop locations",
                  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"]:
            ok = s not in extract_mo
            print(f"  [{'OK ' if ok else 'FAIL'}] memory-only EXTRACT omits {s!r}")
            if not ok:
                failures.append(f"memory-only EXTRACT should omit {s!r}")

    print("\n=== memory-only role guidance ===")
    role_cases = [
        ("domain_controller", "Windows Domain Controller", "lsass.exe", "Kerberos"),
        ("mail_server", "Microsoft Exchange mail server", "EdgeTransport.exe", "ProxyShell"),
        ("sharepoint_server", "SharePoint server", "OWSTimer.exe", "ToolShell"),
        ("av_server", "AV / EDR management server", "vendor management", "dll_load_anomaly"),
        ("rdp_gateway", "RDP / Remote Desktop server", "TermService", "sticky-keys"),
    ]
    for host_type, _desc, must_a, must_b in role_cases:
        try:
            text = N._build_extract_prompt(host_type, "test desc", has_memory=True, has_disk=False)
        except Exception as e:
            print(f"  [FAIL] memory-only EXTRACT crashed for {host_type}: {e}")
            failures.append(f"role {host_type} crashed")
            continue
        for token in (must_a, must_b):
            ok = token in text
            print(f"  [{'OK ' if ok else 'FAIL'}] {host_type} contains {token!r}")
            if not ok:
                failures.append(f"role {host_type} missing {token!r}")
        # Disk-paths must NOT appear in any memory-only role guidance
        for forbidden in ("HKLM\\SOFTWARE", "HKCU\\SOFTWARE", "/Windows/System32/config", "icat_extract", "regripper_run"):
            ok = forbidden not in text
            print(f"  [{'OK ' if ok else 'FAIL'}] {host_type} omits {forbidden!r}")
            if not ok:
                failures.append(f"role {host_type} should omit {forbidden!r}")

    print("\n=== _host_type_of dispatches new roles ===")
    for cid, want in [
        ("srl-2018-base-av-memonly", "av_server"),
        ("srl-2018-base-sp-memonly", "sharepoint_server"),
    ]:
        got, _ = N._host_type_of(cid)
        ok = got == want
        print(f"  [{'OK ' if ok else 'FAIL'}] {cid} -> {got!r} (want {want!r})")
        if not ok:
            failures.append(f"_host_type_of({cid!r}) returned {got!r}, want {want!r}")

    print("\n=== neither channel (must raise) ===")
    try:
        N._plan_system_prompt(CASE_ID, None, None, None)
        print("  [FAIL] PLAN did not raise on (no disk, no memory)")
        failures.append("PLAN missing neither-channel guard")
    except ValueError:
        print("  [OK ] PLAN raised ValueError on (no disk, no memory)")

    print("\n=== summary ===")
    if failures:
        print(f"FAILURES: {len(failures)}")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--snapshot", action="store_true")
    p.add_argument("--check", action="store_true")
    args = p.parse_args()
    if args.snapshot and args.check:
        print("pick one of --snapshot / --check", file=sys.stderr)
        return 2
    if args.snapshot:
        return snapshot()
    if args.check:
        return check()
    print("usage: --snapshot or --check", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
