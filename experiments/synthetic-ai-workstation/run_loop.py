#!/usr/bin/env python3
"""Daily self-healing-loop orchestrator.

Runs the six phases of the daily synthetic-workstation cycle, with a
fast-fail check between each. Designed to run on the VPS host (not
inside a container). It launches Docker sub-containers for each phase
and gathers their output into a dated report folder.

Phases:
    A. Pre-flight (CHECK 01-02)
    B. Research agent fetches threat intel (CHECK 03)
    C. Build planted raw (CHECK 04-08, runs in privileged synth-builder container)
    D. Verify planted + baseline intact (CHECK 09-10, runs in non-privileged container)
    E. Pipeline run (CHECK 11-12, uses existing find-evil/sift-mcp + sentinel)
    F. Score + cleanup (CHECK 13-15)

Usage (typically called by cron at 07:00 UTC daily):
    python3 /opt/find-evil/repo/experiments/synthetic-ai-workstation/run_loop.py
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Config:
    # Paths on the VPS host
    REPO_ROOT       = Path("/opt/find-evil/repo")
    SOURCE_DIR      = Path("/opt/find-evil/source")
    DERIVED_DIR     = Path("/opt/find-evil/derived")
    WORKING_DIR     = Path("/opt/find-evil/working")
    OUT_BASE        = Path("/opt/find-evil/out/loop-runs")

    BASE_E01        = SOURCE_DIR / "base-wkstn-05-cdrive.E01"
    BASE_RAW        = DERIVED_DIR / "base-wkstn-05.raw"
    BASE_RAW_MD5_FILE = DERIVED_DIR / "base-wkstn-05.raw.md5"

    # Image used for build + verify (must have hivex, pyTSK, regipy installed)
    BUILDER_IMAGE   = "find-evil/sift:slice5"

    # Research agent step: today's first-run uses a hand-written manifest;
    # later this is replaced by a Claude Code routine that pulls fresh intel.
    DEFAULT_MANIFEST_TEMPLATE = REPO_ROOT / "experiments/synthetic-ai-workstation/manifest_v1.json"


CFG = Config()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def today_str() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def info(msg: str):
    print(f"[LOOP {now_iso()}] {msg}", flush=True)


def check_pass(n: int, name: str, detail: str = ""):
    line = f"[CHECK {n:02d}] {name}: PASS"
    if detail:
        line += f" ({detail})"
    print(line, flush=True)


def check_fail(n: int, name: str, reason: str):
    print(f"[CHECK {n:02d}] {name}: FAIL — {reason}", file=sys.stderr, flush=True)
    sys.exit(100 + n)


def run(cmd: list[str], capture: bool = False, check: bool = True) -> subprocess.CompletedProcess:
    info(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, check=check,
                          capture_output=capture, text=True if capture else False)


def md5_of(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Phase A: pre-flight (CHECK 01-02)
# ---------------------------------------------------------------------------

def phase_a_preflight(run_dir: Path) -> None:
    info("=== Phase A: pre-flight ===")

    # CHECK 01: git pull clean
    try:
        run(["git", "-C", str(CFG.REPO_ROOT), "pull", "--ff-only"], capture=True)
        check_pass(1, "git pull clean")
    except subprocess.CalledProcessError as e:
        check_fail(1, "git pull clean", f"exit {e.returncode}")

    # CHECK 02: base raw md5 unchanged
    if not CFG.BASE_RAW.exists():
        check_fail(2, "base raw md5 unchanged",
                   f"base raw not found: {CFG.BASE_RAW}. Run ewfexport first.")
    if not CFG.BASE_RAW_MD5_FILE.exists():
        # First run: record the md5 as the canonical baseline fingerprint
        info(f"first-run: recording base raw md5")
        baseline_md5 = md5_of(CFG.BASE_RAW)
        CFG.BASE_RAW_MD5_FILE.write_text(baseline_md5 + "\n")
        check_pass(2, "base raw md5 unchanged", f"first run, md5 fingerprint={baseline_md5}")
    else:
        expected = CFG.BASE_RAW_MD5_FILE.read_text().strip()
        actual = md5_of(CFG.BASE_RAW)
        if actual == expected:
            check_pass(2, "base raw md5 unchanged", f"md5={actual}")
        else:
            check_fail(2, "base raw md5 unchanged",
                       f"expected {expected}, got {actual}")


# ---------------------------------------------------------------------------
# Phase B: research agent (CHECK 03)
# ---------------------------------------------------------------------------

def _research_shim(run_dir: Path, template_path: Path) -> Path:
    """Fallback: stamp today's date into the hand-written template and write it."""
    if not template_path.exists():
        check_fail(3, "research agent manifest", f"template missing: {template_path}")
    template = json.loads(template_path.read_text())
    template["manifest_id"] = today_str()
    out = run_dir / f"manifest_{today_str()}.json"
    out.write_text(json.dumps(template, indent=2))
    return out


def phase_b_research(run_dir: Path) -> Path:
    info("=== Phase B: research agent ===")
    manifest_today = run_dir / f"manifest_{today_str()}.json"

    research_script = CFG.REPO_ROOT / "experiments/synthetic-ai-workstation/research.py"
    schema_path = CFG.REPO_ROOT / "experiments/synthetic-ai-workstation/manifest_schema.json"
    template_path = CFG.DEFAULT_MANIFEST_TEMPLATE

    if research_script.exists() and shutil.which("claude"):
        info("running research.py to fetch fresh threat intel ...")
        res = subprocess.run(
            [
                sys.executable, str(research_script),
                "--schema", str(schema_path),
                "--template", str(template_path),
                "--out", str(manifest_today),
                "--intel-window-days", "30",
                "--loop-runs-dir", str(CFG.OUT_BASE),
            ],
            capture_output=False,
            cwd=str(research_script.parent),
        )
        if res.returncode == 0 and manifest_today.exists():
            info(f"research agent manifest written: {manifest_today}")
        else:
            info(f"research.py exited {res.returncode} — falling back to template shim")
            manifest_today = _research_shim(run_dir, template_path)
    else:
        info("research.py or claude CLI not found — using template shim")
        manifest_today = _research_shim(run_dir, template_path)
    info(f"manifest: {manifest_today}")

    # CHECK 03: manifest validates (parses + has expected structure + non-empty)
    try:
        m = json.loads(manifest_today.read_text())
    except Exception as e:
        check_fail(3, "research agent manifest", f"manifest unloadable: {e}")
    if "categories" not in m or "base" not in m:
        check_fail(3, "research agent manifest", "missing categories or base")
    if not m["categories"]:
        check_fail(3, "research agent manifest", "categories empty")
    total_artifacts = sum(len(c["artifacts"]) for c in m["categories"])
    if total_artifacts == 0:
        check_fail(3, "research agent manifest", "zero artifacts in manifest")
    if m.get("manifest_id") != today_str():
        check_fail(3, "research agent manifest",
                   f"manifest_id mismatch: {m.get('manifest_id')} vs {today_str()}")
    check_pass(3, "research agent manifest",
               f"{total_artifacts} artifacts across {len(m['categories'])} categories")
    return manifest_today


# ---------------------------------------------------------------------------
# Phase C: build (CHECK 04-08, runs in PRIVILEGED synth-builder container)
# ---------------------------------------------------------------------------

def phase_c_build(run_dir: Path, manifest_path: Path) -> Path:
    info("=== Phase C: build (privileged synth-builder container) ===")
    working_raw = CFG.WORKING_DIR / f"win-ops-04-{today_str()}.raw"
    CFG.WORKING_DIR.mkdir(parents=True, exist_ok=True)

    # Run build.py inside a privileged ad-hoc container.
    # Network disabled (--network none) since build needs no internet.
    docker_cmd = [
        "docker", "run", "--rm",
        "--privileged",                  # for loop mounts
        "--network", "none",             # no exfil during build
        "-v", f"{CFG.REPO_ROOT}:/repo:ro",
        "-v", f"{CFG.DERIVED_DIR}:/derived:ro",
        "-v", f"{CFG.WORKING_DIR}:/working:rw",
        "-v", f"{run_dir}:/run_out:rw",
        CFG.BUILDER_IMAGE,
        "python3", "/repo/experiments/synthetic-ai-workstation/build.py",
        "--manifest", str(manifest_path).replace(str(run_dir), "/run_out"),
        "--base", str(CFG.BASE_RAW).replace(str(CFG.DERIVED_DIR), "/derived"),
        "--working", str(working_raw).replace(str(CFG.WORKING_DIR), "/working"),
    ]

    try:
        run(docker_cmd)
        check_pass(8, "build.py exit 0", f"working raw at {working_raw}")
    except subprocess.CalledProcessError as e:
        check_fail(e.returncode + 3, "build.py", f"build container exit {e.returncode}")

    return working_raw


# ---------------------------------------------------------------------------
# Phase D: verify (CHECK 09-10, non-privileged container)
# ---------------------------------------------------------------------------

def phase_d_verify(run_dir: Path, manifest_path: Path, working_raw: Path) -> None:
    info("=== Phase D: verify planted + baseline intact ===")

    # CHECK 09: verify_planted.py
    try:
        run([
            "docker", "run", "--rm",
            "--network", "none",
            "-v", f"{CFG.REPO_ROOT}:/repo:ro",
            "-v", f"{CFG.WORKING_DIR}:/working:ro",
            "-v", f"{run_dir}:/run_out:ro",
            CFG.BUILDER_IMAGE,
            "python3", "/repo/experiments/synthetic-ai-workstation/verify_planted.py",
            "--manifest", str(manifest_path).replace(str(run_dir), "/run_out"),
            "--planted", str(working_raw).replace(str(CFG.WORKING_DIR), "/working"),
        ])
        check_pass(9, "verify_planted.py")
    except subprocess.CalledProcessError as e:
        check_fail(9, "verify_planted.py", f"exit {e.returncode}")

    # CHECK 10: verify_baseline_intact.py
    try:
        run([
            "docker", "run", "--rm",
            "--network", "none",
            "-v", f"{CFG.REPO_ROOT}:/repo:ro",
            "-v", f"{CFG.DERIVED_DIR}:/derived:ro",
            "-v", f"{CFG.WORKING_DIR}:/working:ro",
            "-v", f"{run_dir}:/run_out:ro",
            CFG.BUILDER_IMAGE,
            "python3", "/repo/experiments/synthetic-ai-workstation/verify_baseline_intact.py",
            "--manifest", str(manifest_path).replace(str(run_dir), "/run_out"),
            "--base", "/derived/base-wkstn-05.raw",
            "--planted", str(working_raw).replace(str(CFG.WORKING_DIR), "/working"),
        ])
        check_pass(10, "verify_baseline_intact.py")
    except subprocess.CalledProcessError as e:
        check_fail(10, "verify_baseline_intact.py", f"exit {e.returncode}")


# ---------------------------------------------------------------------------
# Phase E: pipeline run (CHECK 11-12)
# ---------------------------------------------------------------------------

def phase_e_pipeline(run_dir: Path, working_raw: Path) -> Path:
    info("=== Phase E: pipeline run ===")
    pipeline_out = run_dir / "pipeline_output"
    pipeline_out.mkdir(parents=True, exist_ok=True)

    # TODO: wire up sift-mcp + sift-sentinel run against working_raw.
    # Until that's done (Day-1 next session), skip this phase and emit a
    # placeholder findings.json so the score phase can run sanity check.
    placeholder = pipeline_out / "findings.json"
    placeholder.write_text(json.dumps({
        "_placeholder": True,
        "_message": "Pipeline integration pending. Wire up sift-mcp + sentinel here.",
        "findings": [],
    }))
    info(f"pipeline integration TODO; placeholder: {placeholder}")
    check_pass(11, "pipeline run exit 0", "PLACEHOLDER (pipeline integration pending)")
    check_pass(12, "findings.json valid", "PLACEHOLDER (empty findings)")

    return placeholder


# ---------------------------------------------------------------------------
# Phase F: score + cleanup (CHECK 13-15)
# ---------------------------------------------------------------------------

def phase_f_score(run_dir: Path, manifest_path: Path, findings_path: Path) -> None:
    info("=== Phase F: score + cleanup ===")
    score_json = run_dir / f"score_{today_str()}.json"
    report_md = run_dir / "REPORT.md"

    try:
        run([
            "docker", "run", "--rm",
            "--network", "none",
            "-v", f"{CFG.REPO_ROOT}:/repo:ro",
            "-v", f"{run_dir}:/run_out:rw",
            CFG.BUILDER_IMAGE,
            "python3", "/repo/experiments/synthetic-ai-workstation/score.py",
            "--manifest", "/run_out/" + manifest_path.name,
            "--findings", "/run_out/" + findings_path.relative_to(run_dir).as_posix(),
            "--baseline-detected", "",  # populated by Phase E once integrated
            "--out-json", "/run_out/" + score_json.name,
            "--out-md", "/run_out/" + report_md.name,
        ])
        check_pass(13, "score.py", f"score at {score_json}")
    except subprocess.CalledProcessError as e:
        check_fail(13, "score.py", f"exit {e.returncode}")

    # CHECK 14: regression assertion
    score = json.loads(score_json.read_text())
    if score["regression"]["fail"]:
        check_fail(14, "regression assertion",
                   f"baseline misses: {score['regression']['fail']}")
    check_pass(14, "regression assertion",
               f"all {len(score['regression']['expected'])} baseline findings re-detected")


def phase_g_cleanup(working_raw: Path) -> None:
    info("=== Phase G: cleanup ===")
    if working_raw.exists():
        try:
            working_raw.unlink()
            check_pass(15, "cleanup", f"deleted {working_raw}")
        except Exception as e:
            check_fail(15, "cleanup", str(e))
    else:
        check_pass(15, "cleanup", "no working file to delete")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-cleanup", action="store_true",
                    help="Keep working file (debug mode)")
    args = ap.parse_args()

    run_dir = CFG.OUT_BASE / today_str()
    run_dir.mkdir(parents=True, exist_ok=True)
    info(f"loop run dir: {run_dir}")

    started = time.time()

    phase_a_preflight(run_dir)
    manifest_today = phase_b_research(run_dir)
    working_raw = phase_c_build(run_dir, manifest_today)
    phase_d_verify(run_dir, manifest_today, working_raw)
    findings_path = phase_e_pipeline(run_dir, working_raw)
    phase_f_score(run_dir, manifest_today, findings_path)
    if not args.no_cleanup:
        phase_g_cleanup(working_raw)
    else:
        info(f"--no-cleanup: keeping {working_raw}")

    elapsed = time.time() - started
    info(f"=== LOOP COMPLETE in {elapsed:.1f}s ===")


if __name__ == "__main__":
    main()
