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
    STATE_DIR       = Path("/opt/find-evil/state")
    LOCK_FILE       = STATE_DIR / "active_run.json"

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
# Run lock: serialize concurrent loop invocations.
# ---------------------------------------------------------------------------
# 2026-04-30: written so two invocations of run_loop.py (e.g. cron + manual,
# or two terminals) cannot collide on the 49 GB working volume. Also lays
# the groundwork for the Stage-4 judge-plant-and-test UI which will share
# this lock space (judge runs queue behind / preempt the daily loop).
#
# Lock format: JSON file at CFG.LOCK_FILE recording {pid, owner, started_iso,
# phase, last_heartbeat_iso}. Stale detection: if pid does not exist OR
# heartbeat is older than 60 minutes, the lock is broken and silently overridden.

import os as _os


def _pid_alive(pid: int) -> bool:
    """True if `pid` is a running process. Linux-only (signal 0 syscall)."""
    if pid <= 0:
        return False
    try:
        _os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but is owned by another UID; still alive for our purposes.
        return True
    return True


def acquire_lock(owner: str = "daily-cron") -> None:
    """Acquire the shared run lock. Halts via check_fail(99, ...) if another
    run is in flight. Stale locks (dead pid or 60+ min heartbeat) are overridden."""
    CFG.STATE_DIR.mkdir(parents=True, exist_ok=True)
    if CFG.LOCK_FILE.exists():
        try:
            existing = json.loads(CFG.LOCK_FILE.read_text())
        except Exception:
            existing = {}
        their_pid = int(existing.get("pid", 0))
        their_owner = existing.get("owner", "?")
        their_start = existing.get("started_iso", "?")
        their_hb = existing.get("last_heartbeat_iso", "?")
        # Stale check
        is_dead = not _pid_alive(their_pid)
        is_old_hb = False
        try:
            hb = datetime.datetime.fromisoformat(their_hb.replace("Z", "+00:00"))
            age_s = (datetime.datetime.now(datetime.timezone.utc) - hb).total_seconds()
            is_old_hb = age_s > 60 * 60  # 60 minutes
        except Exception:
            is_old_hb = True  # unparseable heartbeat = stale
        if is_dead or is_old_hb:
            info(f"override stale lock: pid={their_pid} owner={their_owner} dead={is_dead} old_hb={is_old_hb}")
        else:
            check_fail(99, "acquire run lock",
                       f"another run active: pid={their_pid} owner={their_owner} "
                       f"started={their_start} last_heartbeat={their_hb}")
    _write_lock(owner=owner, phase="acquired")
    info(f"run lock acquired: pid={_os.getpid()} owner={owner} file={CFG.LOCK_FILE}")


def heartbeat_lock(phase: str) -> None:
    """Update phase + last_heartbeat in the lock file. Silent on missing file."""
    if not CFG.LOCK_FILE.exists():
        return
    try:
        existing = json.loads(CFG.LOCK_FILE.read_text())
    except Exception:
        return
    _write_lock(
        owner=existing.get("owner", "?"),
        phase=phase,
        started_iso=existing.get("started_iso"),
    )


def release_lock() -> None:
    """Remove the lock file. Idempotent; safe to call from finally even
    when acquire failed."""
    try:
        if CFG.LOCK_FILE.exists():
            CFG.LOCK_FILE.unlink()
            info(f"run lock released: {CFG.LOCK_FILE}")
    except Exception as e:
        info(f"could not release lock {CFG.LOCK_FILE}: {e}")


def _write_lock(*, owner: str, phase: str, started_iso: str | None = None) -> None:
    payload = {
        "pid": _os.getpid(),
        "owner": owner,
        "started_iso": started_iso or now_iso(),
        "phase": phase,
        "last_heartbeat_iso": now_iso(),
    }
    CFG.LOCK_FILE.write_text(json.dumps(payload, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Phase A: pre-flight (CHECK 01-02)
# ---------------------------------------------------------------------------

def phase_a_preflight(run_dir: Path) -> None:
    info("=== Phase A: pre-flight ===")

    # CHECK 01: repo current. If REPO_ROOT is a git checkout, fast-forward pull;
    # if it is rsync-deployed (no .git), soft-pass with a note. The VPS at
    # /opt/find-evil/repo/ is rsync-deployed (no git remote), so the prior
    # hard-fail-on-git-pull behavior was wrong for that environment.
    if (CFG.REPO_ROOT / ".git").exists():
        try:
            run(["git", "-C", str(CFG.REPO_ROOT), "pull", "--ff-only"], capture=True)
            check_pass(1, "repo current", "git fast-forward")
        except subprocess.CalledProcessError as e:
            check_fail(1, "repo current", f"git pull exit {e.returncode}")
    else:
        check_pass(1, "repo current", "rsync-deployed; skipping git pull")

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

    # CHECK 02b: clean stale working raws. The /working/ volume is 49 GB on
    # this VPS and each working raw is ~30 GB sparse + grow-on-write. Phase G
    # always cleans up the run's own working file, but if a prior run halts
    # before Phase G (Critic escalation, container crash, manual stop) the
    # working file stays on disk and the next run hits "No space left on
    # device" during cp --sparse=always. Defensive sweep: delete any *.raw in
    # /working/ older than 6 hours OR that does not match today's filename.
    # Runs in a tiny privileged container so we can remove root-owned files
    # produced by previous build containers without needing host sudo.
    info("CHECK 02b: scanning /working/ for stale raw files")
    try:
        # Match the synth-builder naming pattern only; ignore any other .raw
        # files a user may have parked in /working/. -mmin +5 catches a partial
        # from a hung run minutes ago AND any older files. The fresh working
        # raw for THIS loop run will not exist yet (build is Phase C).
        cleanup_cmd = (
            "find /working -maxdepth 1 -name 'win-ops-04-*.raw' "
            "-mmin +5 -print -delete"
        )
        res = run(
            ["docker", "run", "--rm", "--network", "none",
             "-v", f"{CFG.WORKING_DIR}:/working:rw",
             CFG.BUILDER_IMAGE,
             "sh", "-c", cleanup_cmd],
            capture=True,
        )
        deleted = [ln for ln in (res.stdout or "").splitlines() if ln.strip()]
        if deleted:
            check_pass(102, "stale working raws cleaned",
                       f"deleted {len(deleted)} file(s): {[Path(p).name for p in deleted]}")
        else:
            check_pass(102, "stale working raws cleaned", "no stale files")
    except subprocess.CalledProcessError as e:
        # Soft-pass: if cleanup fails the loop still runs; Phase C will catch
        # the genuine no-space failure with a clearer error.
        info(f"CHECK 02b: cleanup container exit {e.returncode} (soft-pass; Phase C will catch real failures)")


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
    info("=== Phase E: pipeline run (sift-sentinel) ===")
    pipeline_out = run_dir / "pipeline_output"
    pipeline_out.mkdir(parents=True, exist_ok=True)

    case_id = f"synthetic-{today_str()}"
    # sift-mcp sees the working dir at /mnt/working (docker-compose.vps.yaml mount)
    container_image_path = f"/mnt/working/{working_raw.name}"

    # CHECK 11: run pipeline inside the live sift-sentinel container
    try:
        run([
            "docker", "exec", "sift-sentinel",
            "bash", "-c",
            f"cd /workspace && uv run python run_case.py --case {case_id} --e01 {container_image_path}",
        ])
    except subprocess.CalledProcessError as e:
        check_fail(11, "pipeline run", f"docker exec exit {e.returncode}")

    # run_case.py writes findings to /workspace/out/runs/{case_id}/{run_id}/05_interpret_findings.json
    # /workspace inside the container maps to:
    #   /opt/find-evil/repo/experiments/slice-2-notebook  (via docker-compose.vps.yaml)
    workspace_host = CFG.REPO_ROOT / "experiments/slice-2-notebook"
    case_dir = workspace_host / "out" / "runs" / case_id
    latest_txt = case_dir / "latest.txt"
    if not latest_txt.exists():
        check_fail(11, "pipeline run", f"latest.txt not found at {latest_txt} — run_case.py may have crashed")
    run_id = latest_txt.read_text().strip()
    check_pass(11, "pipeline run exit 0", f"case={case_id} run_id={run_id}")

    # CHECK 12: findings file is present and valid JSON
    findings_src = case_dir / run_id / "05_interpret_findings.json"
    if not findings_src.exists():
        check_fail(12, "findings.json valid", f"05_interpret_findings.json not found at {findings_src}")

    findings_dst = pipeline_out / "findings.json"
    shutil.copy2(str(findings_src), str(findings_dst))
    try:
        f = json.loads(findings_dst.read_text())
    except Exception as e:
        check_fail(12, "findings.json valid", f"invalid JSON: {e}")

    n = len(f.get("findings", []))
    check_pass(12, "findings.json valid", f"{n} findings, run_dir={case_dir / run_id}")

    return findings_dst


# ---------------------------------------------------------------------------
# Phase F: score + cleanup (CHECK 13-15)
# ---------------------------------------------------------------------------

def derive_baseline_detected(manifest_path: Path, findings_path: Path) -> list[str]:
    """Scan findings.json for any expected baseline finding from the manifest.

    Each baseline finding has an `id` like 'perfmon_masquerading' or
    'tbbd05_named_pipe_beacon'. The first underscore-component (length >= 4) is
    the discriminator (e.g. 'perfmon', 'tbbd05'); a baseline counts as
    detected if that token appears anywhere in the findings JSON.

    Using only the first component avoids over-matching on generic words like
    'masquerading' or 'beacon' that other findings may also use.

    Returns the list of detected baseline ids, in manifest order.
    """
    try:
        manifest = json.loads(manifest_path.read_text())
        findings_obj = json.loads(findings_path.read_text())
    except Exception as e:
        info(f"derive_baseline_detected: read error {e}; returning []")
        return []

    findings_list = (
        findings_obj if isinstance(findings_obj, list)
        else findings_obj.get("findings", [])
    )
    blob = json.dumps(findings_list).lower()

    detected: list[str] = []
    for entry in manifest.get("base", {}).get("expected_baseline_findings", []):
        bid = entry.get("id", "")
        # First underscore-part with length >= 4 is the discriminator.
        keyword = next(
            (p.lower() for p in bid.split("_") if len(p) >= 4),
            None,
        )
        if keyword and keyword in blob:
            detected.append(bid)
    return detected


def phase_f_score(run_dir: Path, manifest_path: Path, findings_path: Path) -> None:
    info("=== Phase F: score + cleanup ===")
    score_json = run_dir / f"score_{today_str()}.json"
    report_md = run_dir / "REPORT.md"

    detected_baselines = derive_baseline_detected(manifest_path, findings_path)
    info(f"baseline detection scan: {detected_baselines or 'none'}")

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
            "--baseline-detected", ",".join(detected_baselines),
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


def phase_g_cleanup(working_raw: Path | None = None) -> None:
    """Always-fire cleanup. Removes the run's own working raw if known, AND
    sweeps /working/ for any orphan win-ops-04-*.raw left by an aborted run.

    Called from a finally block so it runs even when an earlier phase
    raised SystemExit via check_fail. The sweep uses a privileged-equivalent
    docker container so it can delete root-owned files produced by the
    privileged builder without host sudo.
    """
    info("=== Phase G: cleanup ===")
    # Step 1: remove the run's own working raw if we know its path.
    if working_raw is not None and working_raw.exists():
        try:
            working_raw.unlink()
            info(f"removed run's working raw: {working_raw}")
        except Exception as e:
            info(f"could not unlink {working_raw}: {e} (will rely on sweep)")
    # Step 2: defensive sweep of /working/ for any orphan win-ops-04-*.raw.
    # Catches: files left by a hung build, files we could not unlink in step 1
    # (root-owned), partial files from a crashed run.
    try:
        cleanup_cmd = (
            "find /working -maxdepth 1 -name 'win-ops-04-*.raw' "
            "-print -delete"
        )
        res = run(
            ["docker", "run", "--rm", "--network", "none",
             "-v", f"{CFG.WORKING_DIR}:/working:rw",
             CFG.BUILDER_IMAGE,
             "sh", "-c", cleanup_cmd],
            capture=True,
        )
        deleted = [ln for ln in (res.stdout or "").splitlines() if ln.strip()]
        if deleted:
            check_pass(15, "cleanup",
                       f"sweep removed {len(deleted)} working raw(s): "
                       f"{[Path(p).name for p in deleted]}")
        else:
            check_pass(15, "cleanup", "no working raws on disk")
    except subprocess.CalledProcessError as e:
        # Soft-pass: sweep failure is logged but does not change overall loop status.
        info(f"cleanup sweep container exit {e.returncode} (soft-pass)")
        check_pass(15, "cleanup", f"sweep exit {e.returncode} (soft-pass)")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-cleanup", action="store_true",
                    help="Keep working file (debug mode)")
    ap.add_argument("--owner", default="daily-cron",
                    help="Lock owner identifier (e.g. daily-cron, judge-<id>). Used for the activity feed.")
    args = ap.parse_args()

    run_dir = CFG.OUT_BASE / today_str()
    run_dir.mkdir(parents=True, exist_ok=True)
    info(f"loop run dir: {run_dir}")

    started = time.time()
    working_raw: Path | None = None
    lock_acquired = False

    try:
        # Acquire the shared run lock BEFORE any expensive work. If another
        # run is in flight (cron + manual collision, or two terminals),
        # acquire_lock calls check_fail(99, ...) which exits cleanly without
        # touching disk.
        acquire_lock(owner=args.owner)
        lock_acquired = True

        heartbeat_lock("phase_a")
        phase_a_preflight(run_dir)
        heartbeat_lock("phase_b")
        manifest_today = phase_b_research(run_dir)
        heartbeat_lock("phase_c")
        working_raw = phase_c_build(run_dir, manifest_today)
        heartbeat_lock("phase_d")
        phase_d_verify(run_dir, manifest_today, working_raw)
        heartbeat_lock("phase_e")
        findings_path = phase_e_pipeline(run_dir, working_raw)
        heartbeat_lock("phase_f")
        phase_f_score(run_dir, manifest_today, findings_path)

        elapsed = time.time() - started
        info(f"=== LOOP COMPLETE in {elapsed:.1f}s ===")
    finally:
        # ALWAYS run cleanup. The synth-builder's working raw is ~30 GB and the
        # /working/ volume on VPS is 49 GB; one orphan blocks the next run. The
        # finally block fires on success, on check_fail SystemExit, and on
        # KeyboardInterrupt. --no-cleanup is debug-only and skips Phase G.
        if args.no_cleanup:
            info(f"--no-cleanup: keeping {working_raw} (debug mode)")
        else:
            phase_g_cleanup(working_raw)
        # Release the lock LAST so concurrent runs see Phase G finish before
        # they unblock. Skipped if acquire failed (which means the lock was
        # held by someone else; we must NOT remove it).
        if lock_acquired:
            release_lock()


if __name__ == "__main__":
    main()
