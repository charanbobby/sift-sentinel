#!/usr/bin/env python3
"""Synthetic workstation builder.

Reads a manifest (JSON) and a base raw NTFS image. Plants the manifest's
artifacts on a copy of the base raw, writes the planted raw to the working
path. Designed to run inside a privileged find-evil/sift container where
ntfs-3g, losetup, hivex (Python bindings), and the rest of SIFT are
available.

Usage:
    python3 build.py --manifest manifest_v1.json \
                     --base /opt/find-evil/derived/base-wkstn-05.raw \
                     --working /opt/find-evil/working/win-ops-04-2026-04-28.raw

Exit codes (per the 15-check fast-fail protocol):
    0  build successful, every artifact planted, baseline preserved
    1  manifest validation failed
    2  base raw missing or copy failed
    3  mount failed
    4  artifact planting failed
    5  unmount failed
    6  cleanup failed
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# hive-writing dependency. Imported lazily so file-only manifests can run
# without it.
def _import_hivex():
    try:
        import hivex
        return hivex
    except ImportError:
        fail(4, "python3-hivex not available. Install via apt: libhivex-dev hivex python3-hivex")


def fail(code: int, msg: str):
    print(f"[BUILD FAIL {code}] {msg}", file=sys.stderr)
    sys.exit(code)


def info(msg: str):
    print(f"[BUILD] {msg}", flush=True)


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    info(f"run: {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, check=True, **kw)


# ---------------------------------------------------------------------------
# Stage 1: copy base -> working (sparse-aware)
# ---------------------------------------------------------------------------

def cp_sparse(src: Path, dst: Path):
    if dst.exists():
        info(f"removing existing working file: {dst}")
        dst.unlink()
    dst.parent.mkdir(parents=True, exist_ok=True)
    run(["cp", "--sparse=always", str(src), str(dst)])
    info(f"copied {src} -> {dst} ({dst.stat().st_size} bytes)")


# ---------------------------------------------------------------------------
# Stage 2: mount the working raw
# ---------------------------------------------------------------------------

def mount_raw(raw_path: Path, partition_index: int) -> tuple[str, Path]:
    """losetup the raw with -P (scan partitions). Mount the chosen partition
    read-write via ntfs-3g. Falls back to mounting the loop device directly
    when the raw is a single-partition image with no MBR/GPT.
    Returns (loop_device, mount_dir)."""
    res = run(["losetup", "--show", "-Pf", str(raw_path)])
    loop_dev = res.stdout.strip()
    info(f"loop device: {loop_dev}")
    part_dev = f"{loop_dev}p{partition_index}"
    if Path(part_dev).exists():
        info(f"partition device: {part_dev}")
    else:
        # Single-partition raw (no MBR/GPT). Mount the loop device directly.
        info(f"no partition table on raw; mounting loop device directly: {loop_dev}")
        part_dev = loop_dev
    mount_dir = Path(tempfile.mkdtemp(prefix="synth-mount-"))
    run(["mount", "-t", "ntfs-3g", "-o", "rw", part_dev, str(mount_dir)])
    info(f"mounted at {mount_dir}")
    return loop_dev, mount_dir


def umount_raw(loop_dev: str, mount_dir: Path):
    try:
        run(["sync"])
        run(["umount", str(mount_dir)])
    except Exception as e:
        info(f"warning during umount: {e}")
    try:
        run(["losetup", "-d", loop_dev])
    except Exception as e:
        info(f"warning during losetup -d: {e}")
    if mount_dir.exists():
        shutil.rmtree(mount_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Artifact planters (one per type)
# ---------------------------------------------------------------------------

def plant_file(mount_dir: Path, artifact: dict):
    rel = artifact["file_path"]
    target = mount_dir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    if "file_content_text" in artifact:
        target.write_text(artifact["file_content_text"])
    elif "file_content_b64" in artifact:
        target.write_bytes(base64.b64decode(artifact["file_content_b64"]))
    else:
        fail(4, f"file_drop {artifact['id']} has no content field")
    info(f"  planted file ({len(target.read_bytes())} bytes): {rel}")


def plant_scheduled_task(mount_dir: Path, artifact: dict):
    # task_install_path uses Windows backslashes, e.g. "Microsoft\\RebuildSearchIndex".
    # Convert to POSIX so each path component becomes a real directory.
    sub_path = artifact["task_install_path"].replace("\\", "/")
    rel = Path("Windows/System32/Tasks") / sub_path
    target = mount_dir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    # Windows Task XML on disk is UTF-16-LE with BOM.
    xml_text = artifact["task_xml"]
    target.write_bytes(b"\xff\xfe" + xml_text.encode("utf-16-le"))
    info(f"  planted scheduled task: {rel}")


def _hive_path(mount_dir: Path, hive_name: str) -> Path:
    candidates = [
        mount_dir / "Windows/System32/config" / hive_name,
        mount_dir / "Windows/System32/config" / hive_name.upper(),
    ]
    for c in candidates:
        if c.exists():
            return c
    fail(4, f"hive not found at any of: {candidates}")


def _hivex_create_or_find_path(h, root_node: int, key_path: str) -> int:
    """Walk/create the hive path under root_node. Returns the leaf node id.
    key_path uses single backslash, e.g. 'Microsoft\\Windows\\CurrentVersion\\Run'.
    hivex returns 0 OR None when a child is missing depending on Python binding
    version, so we treat both as 'not present' and create."""
    if not root_node:
        raise RuntimeError(f"invalid root_node: {root_node!r}")
    node = root_node
    for component in key_path.split("\\"):
        if not component:
            continue
        child = h.node_get_child(node, component)
        if not child:  # 0 or None == not present
            child = h.node_add_child(node, component)
            if not child:
                raise RuntimeError(f"node_add_child returned {child!r} for '{component}' under node {node}")
        node = child
    return node


def plant_registry_run_key(hive_path: Path, artifact: dict):
    hivex = _import_hivex()
    info(f"  opening hive read-write: {hive_path}")
    h = hivex.Hivex(str(hive_path), write=1)
    try:
        root = h.root()
        node = _hivex_create_or_find_path(h, root, artifact["key_path"])
        # set_value with REG_SZ (type 1)
        h.node_set_value(node, {
            "key": artifact["value_name"],
            "t": 1,
            "value": (artifact["value_data"] + "\0").encode("utf-16-le"),
        })
        h.commit(None)
        info(f"  planted Run key {artifact['key_path']}\\{artifact['value_name']}")
    finally:
        del h


def plant_registry_service(hive_path: Path, artifact: dict):
    hivex = _import_hivex()
    h = hivex.Hivex(str(hive_path), write=1)
    try:
        root = h.root()
        if not root:
            raise RuntimeError(f"hivex root() returned {root!r}")
        # Services live at CurrentControlSet\Services\<service_name>.
        # SYSTEM hive root has ControlSet001 etc; CurrentControlSet is a symlink
        # set in Select. For our planting, write under ControlSet001\Services
        # (matches what RegRipper services plugin queries).
        services_path = "ControlSet001\\Services"
        services_node = _hivex_create_or_find_path(h, root, services_path)
        if not services_node:
            raise RuntimeError(f"could not navigate to {services_path}")
        svc = h.node_get_child(services_node, artifact["service_name"])
        if not svc:  # 0 or None
            svc = h.node_add_child(services_node, artifact["service_name"])
            if not svc:
                raise RuntimeError(f"node_add_child failed for {artifact['service_name']}")
        # ImagePath (REG_EXPAND_SZ = 2)
        if artifact.get("service_image_path"):
            h.node_set_value(svc, {
                "key": "ImagePath", "t": 2,
                "value": (artifact["service_image_path"] + "\0").encode("utf-16-le"),
            })
        # DisplayName (REG_SZ)
        if artifact.get("service_display_name"):
            h.node_set_value(svc, {
                "key": "DisplayName", "t": 1,
                "value": (artifact["service_display_name"] + "\0").encode("utf-16-le"),
            })
        # Description (REG_SZ)
        if artifact.get("service_description"):
            h.node_set_value(svc, {
                "key": "Description", "t": 1,
                "value": (artifact["service_description"] + "\0").encode("utf-16-le"),
            })
        # Start (REG_DWORD = 4)
        start = artifact.get("service_start_type", 2)
        h.node_set_value(svc, {
            "key": "Start", "t": 4,
            "value": int(start).to_bytes(4, "little"),
        })
        # Type (REG_DWORD), default 0x10 = Win32OwnProcess
        h.node_set_value(svc, {
            "key": "Type", "t": 4,
            "value": (0x10).to_bytes(4, "little"),
        })
        h.commit(None)
        info(f"  planted service: {artifact['service_name']}")
    finally:
        del h


def plant_registry_binary(hive_path: Path, artifact: dict):
    hivex = _import_hivex()
    h = hivex.Hivex(str(hive_path), write=1)
    try:
        root = h.root()
        node = _hivex_create_or_find_path(h, root, artifact["key_path"])
        if "value_binary_b64" not in artifact:
            fail(4, f"registry_binary_value {artifact['id']} missing value_binary_b64")
        h.node_set_value(node, {
            "key": artifact["value_name"],
            "t": 3,  # REG_BINARY
            "value": base64.b64decode(artifact["value_binary_b64"]),
        })
        h.commit(None)
        info(f"  planted binary value: {artifact['key_path']}\\{artifact['value_name']}")
    finally:
        del h


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

DISPATCH = {
    "file_drop": lambda mount_dir, art: plant_file(mount_dir, art),
    "scheduled_task_xml": lambda mount_dir, art: plant_scheduled_task(mount_dir, art),
    "registry_run_key": lambda mount_dir, art: plant_registry_run_key(
        _hive_path(mount_dir, art["hive"]), art),
    "registry_service": lambda mount_dir, art: plant_registry_service(
        _hive_path(mount_dir, art["hive"]), art),
    "registry_binary_value": lambda mount_dir, art: plant_registry_binary(
        _hive_path(mount_dir, art["hive"]), art),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--base", required=True, help="Path to base raw image.")
    ap.add_argument("--working", required=True, help="Where to write the planted raw.")
    args = ap.parse_args()

    info(f"manifest: {args.manifest}")
    info(f"base: {args.base}")
    info(f"working: {args.working}")

    # Step 0: validate manifest can be loaded
    try:
        manifest = json.loads(Path(args.manifest).read_text())
    except Exception as e:
        fail(1, f"manifest not loadable as JSON: {e}")
    if "categories" not in manifest or "base" not in manifest:
        fail(1, "manifest missing required keys (categories, base)")

    base_raw = Path(args.base)
    working_raw = Path(args.working)
    if not base_raw.exists():
        fail(2, f"base raw not found: {base_raw}")

    # Step 1: copy base -> working (sparse)
    cp_sparse(base_raw, working_raw)

    # Step 2: mount
    partition_index = manifest["base"].get("windows_partition_index", 1)
    try:
        loop_dev, mount_dir = mount_raw(working_raw, partition_index)
    except subprocess.CalledProcessError as e:
        fail(3, f"mount failed: {e.stderr}")

    planted_count = 0
    failed_artifacts = []
    try:
        # Step 3: plant artifacts
        for category in manifest["categories"]:
            info(f"category: {category['name']} ({len(category['artifacts'])} artifacts)")
            for art in category["artifacts"]:
                t = art["type"]
                if t not in DISPATCH:
                    failed_artifacts.append((art["id"], f"unknown type: {t}"))
                    continue
                try:
                    DISPATCH[t](mount_dir, art)
                    planted_count += 1
                except SystemExit:
                    raise
                except Exception as e:
                    failed_artifacts.append((art["id"], str(e)))
                    info(f"  ERROR planting {art['id']}: {e}")
    finally:
        # Step 4: always unmount
        umount_raw(loop_dev, mount_dir)

    # Final report
    total = sum(len(c["artifacts"]) for c in manifest["categories"])
    info(f"planted {planted_count}/{total} artifacts")
    if failed_artifacts:
        info("failed artifacts:")
        for aid, err in failed_artifacts:
            info(f"  - {aid}: {err}")
        fail(4, f"{len(failed_artifacts)} artifact(s) failed to plant")

    # Compute working raw md5 for the daily report
    info("computing working raw md5 ...")
    h = hashlib.md5()
    with working_raw.open("rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    info(f"working raw md5: {h.hexdigest()}")

    info(f"BUILD OK: {working_raw}")


if __name__ == "__main__":
    main()
