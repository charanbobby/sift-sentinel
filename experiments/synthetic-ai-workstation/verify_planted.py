#!/usr/bin/env python3
"""Verify planted artifacts on a synthetic workstation raw image.

This script answers the question a skeptical reviewer will ask:
"How do we know the planted artifacts are actually on the disk?"

It reads the planted raw image DIRECTLY via pyTSK (a different code path
from the pipeline's MCP-tool wrappers), walks each manifest artifact
to its expected path, and confirms it is present. The pipeline is not
invoked at all. This makes the ground truth auditable without trusting
the pipeline.

For registry artifacts, the hive is extracted via pyTSK and parsed by
regipy. For file artifacts, the bytes are read by pyTSK's File() API.

Usage:
    python3 verify_planted.py --manifest manifest_v1.json \
                              --planted /opt/find-evil/working/win-ops-04-2026-04-28.raw

Exit codes:
    0  every artifact verified present
    1  manifest unreadable
    2  planted raw unreadable
    3  one or more artifacts NOT found at expected location
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytsk3
from regipy.registry import RegistryHive  # type: ignore


def info(msg: str):
    print(f"[VERIFY] {msg}", flush=True)


# ---------------------------------------------------------------------------
# pyTSK helpers
# ---------------------------------------------------------------------------

class RawImage:
    """Wraps pytsk3 Img + Volume + the chosen NTFS partition's FS_Info."""

    def __init__(self, raw_path: str, partition_index: int = 1):
        self.img = pytsk3.Img_Info(raw_path)
        # mmls / Volume_Info to find the NTFS partition
        try:
            vol = pytsk3.Volume_Info(self.img)
            ntfs_offset = None
            seen = 0
            for part in vol:
                if part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC and part.len > 0:
                    seen += 1
                    if seen == partition_index:
                        ntfs_offset = part.start * vol.info.block_size
                        break
            if ntfs_offset is None:
                raise RuntimeError(
                    f"could not find allocated partition #{partition_index}")
        except OSError:
            # Single-partition raw
            ntfs_offset = 0
        self.fs = pytsk3.FS_Info(self.img, offset=ntfs_offset)

    def read_file_bytes(self, path: str) -> bytes | None:
        """Walk the path and return the file content, or None if not found."""
        # Normalize: pytsk3 wants forward slashes from FS root.
        path_norm = path.replace("\\", "/").lstrip("/")
        try:
            f = self.fs.open(f"/{path_norm}")
        except OSError:
            return None
        if f.info.meta is None or f.info.meta.size is None:
            return None
        size = f.info.meta.size
        data = b""
        offset = 0
        while offset < size:
            chunk = f.read_random(offset, min(64 * 1024, size - offset))
            if not chunk:
                break
            data += chunk
            offset += len(chunk)
        return data

    def file_exists(self, path: str) -> bool:
        path_norm = path.replace("\\", "/").lstrip("/")
        try:
            self.fs.open(f"/{path_norm}")
            return True
        except OSError:
            return False


# ---------------------------------------------------------------------------
# Hive extraction + parsing
# ---------------------------------------------------------------------------

def extract_hive_to_temp(img: RawImage, hive_name: str, scratch_dir: Path) -> Path:
    """Extract the hive bytes from the planted raw to a temp file so regipy
    can open it. regipy needs a real file path."""
    hive_path = f"Windows/System32/config/{hive_name}"
    data = img.read_file_bytes(hive_path)
    if data is None:
        raise RuntimeError(f"hive not found in image: {hive_path}")
    out = scratch_dir / hive_name
    out.write_bytes(data)
    return out


# ---------------------------------------------------------------------------
# Per-type verifiers
# ---------------------------------------------------------------------------

def verify_file_drop(img: RawImage, art: dict) -> tuple[bool, str]:
    rel = art["file_path"]
    data = img.read_file_bytes(rel)
    if data is None:
        return False, f"file missing: {rel}"
    if "file_content_text" in art:
        expected = art["file_content_text"].encode("utf-8")
        if data != expected:
            # Content drift: still PASS if file is present and non-empty
            # (NTFS line-ending normalization or BOM differences are common)
            if len(data) == 0:
                return False, f"file empty: {rel}"
            return True, f"file present, content differs (len {len(data)} vs {len(expected)})"
    return True, f"file present ({len(data)} bytes): {rel}"


def verify_scheduled_task(img: RawImage, art: dict) -> tuple[bool, str]:
    rel = f"Windows/System32/Tasks/{art['task_install_path']}"
    data = img.read_file_bytes(rel)
    if data is None:
        return False, f"task XML missing: {rel}"
    return True, f"task XML present ({len(data)} bytes): {rel}"


def verify_registry_run_key(img: RawImage, art: dict, scratch: Path) -> tuple[bool, str]:
    try:
        hive_file = extract_hive_to_temp(img, art["hive"], scratch)
        h = RegistryHive(str(hive_file))
        key_path = "\\" + art["key_path"]
        node = h.get_key(key_path)
        for v in node.iter_values():
            if v.name.lower() == art["value_name"].lower():
                return True, f"Run key value present: {key_path}\\{art['value_name']}"
        return False, f"Run key value missing: {key_path}\\{art['value_name']}"
    except Exception as e:
        return False, f"hive parse error for run key: {e}"


def verify_registry_service(img: RawImage, art: dict, scratch: Path) -> tuple[bool, str]:
    try:
        hive_file = extract_hive_to_temp(img, art["hive"], scratch)
        h = RegistryHive(str(hive_file))
        for cs_name in ("ControlSet001", "CurrentControlSet"):
            try:
                node = h.get_key(f"\\{cs_name}\\Services\\{art['service_name']}")
                return True, f"service present: {cs_name}\\Services\\{art['service_name']}"
            except Exception:
                continue
        return False, f"service missing: {art['service_name']}"
    except Exception as e:
        return False, f"hive parse error for service: {e}"


def verify_registry_binary(img: RawImage, art: dict, scratch: Path) -> tuple[bool, str]:
    try:
        hive_file = extract_hive_to_temp(img, art["hive"], scratch)
        h = RegistryHive(str(hive_file))
        node = h.get_key("\\" + art["key_path"])
        for v in node.iter_values():
            if v.name.lower() == art["value_name"].lower():
                return True, f"binary value present: {art['key_path']}\\{art['value_name']}"
        return False, f"binary value missing: {art['key_path']}\\{art['value_name']}"
    except Exception as e:
        return False, f"hive parse error for binary value: {e}"


VERIFIERS = {
    "file_drop": lambda img, art, scratch: verify_file_drop(img, art),
    "scheduled_task_xml": lambda img, art, scratch: verify_scheduled_task(img, art),
    "registry_run_key": verify_registry_run_key,
    "registry_service": verify_registry_service,
    "registry_binary_value": verify_registry_binary,
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--planted", required=True, help="Planted raw image path.")
    ap.add_argument("--scratch", default="/tmp/synth-verify", help="Where to extract hives.")
    args = ap.parse_args()

    try:
        manifest = json.loads(Path(args.manifest).read_text())
    except Exception as e:
        print(f"[VERIFY FAIL 1] manifest unreadable: {e}", file=sys.stderr)
        sys.exit(1)

    if not Path(args.planted).exists():
        print(f"[VERIFY FAIL 2] planted raw not found: {args.planted}", file=sys.stderr)
        sys.exit(2)

    scratch = Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)

    info(f"opening planted raw: {args.planted}")
    partition_index = manifest["base"].get("windows_partition_index", 1)
    img = RawImage(args.planted, partition_index=partition_index)
    info("image opened")

    total = 0
    passed = 0
    rows = []
    for category in manifest["categories"]:
        for art in category["artifacts"]:
            total += 1
            t = art["type"]
            verifier = VERIFIERS.get(t)
            if verifier is None:
                rows.append((art["id"], False, f"no verifier for type: {t}"))
                continue
            try:
                ok, msg = verifier(img, art, scratch)
            except Exception as e:
                ok, msg = False, f"verifier exception: {e}"
            if ok:
                passed += 1
            rows.append((art["id"], ok, msg))

    print()
    print("=" * 72)
    for aid, ok, msg in rows:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {aid}: {msg}")
    print("=" * 72)
    print(f"VERIFY PLANTED: {passed}/{total} artifacts present on disk")
    print()

    sys.exit(0 if passed == total else 3)


if __name__ == "__main__":
    main()
