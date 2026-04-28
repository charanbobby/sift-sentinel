#!/usr/bin/env python3
"""Regression assertion: the base wkstn-05 attacker findings must be
byte-identical on the planted raw vs the source base raw.

The synthetic workstation plants new threats ON TOP of a known-positive
disk. Every daily run must re-detect the originals (PerfMon + tbbd05),
otherwise the pipeline regressed. This script proves the originals are
still on disk untouched, BEFORE the pipeline runs. It is a structural
gate, not a behavioral one.

For each baseline entry in the manifest, the script extracts the relevant
hive from BOTH raws and compares the targeted value bytes. If any planted
key write accidentally collided with a baseline key, the comparison fails.

Usage:
    python3 verify_baseline_intact.py \
        --manifest manifest_v1.json \
        --base /opt/find-evil/derived/base-wkstn-05.raw \
        --planted /opt/find-evil/working/win-ops-04-2026-04-28.raw

Exit codes:
    0  baseline entries unchanged
    1  manifest/inputs unreadable
    2  one or more baseline entries differ between base and planted
    3  baseline entry NOT FOUND on either disk (data quality issue)
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

import pytsk3
from regipy.registry import RegistryHive  # type: ignore


# Baseline targets known on base-wkstn-05 (per
# experiments/slice-2-notebook/out/runs/srl-2018-wkstn-05/ground_truth.json).
# Keyed on baseline_id matching manifest.base.expected_baseline_findings[].id.
BASELINE_TARGETS = {
    "perfmon_masquerading": {
        "hive": "SYSTEM",
        "service_name": "PerfMon",
        "compare_values": ["ImagePath", "DisplayName", "Start", "Type"],
    },
    "tbbd05_named_pipe_beacon": {
        "hive": "SYSTEM",
        "service_name": "tbbd05",
        "compare_values": ["ImagePath", "DisplayName", "Start", "Type"],
    },
}


def info(msg: str):
    print(f"[REGRESS] {msg}", flush=True)


def extract_hive(raw_path: str, hive_name: str, scratch_dir: Path,
                 partition_index: int = 1) -> Path:
    """Extract a hive from the raw via pyTSK."""
    img_info = pytsk3.Img_Info(raw_path)
    try:
        vol = pytsk3.Volume_Info(img_info)
        ntfs_offset = None
        seen = 0
        for part in vol:
            if part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC and part.len > 0:
                seen += 1
                if seen == partition_index:
                    ntfs_offset = part.start * vol.info.block_size
                    break
    except OSError:
        ntfs_offset = 0
    fs = pytsk3.FS_Info(img_info, offset=ntfs_offset)
    f = fs.open(f"/Windows/System32/config/{hive_name}")
    size = f.info.meta.size
    out = scratch_dir / f"{Path(raw_path).name}_{hive_name}"
    with out.open("wb") as fp:
        offset = 0
        while offset < size:
            chunk = f.read_random(offset, min(64 * 1024, size - offset))
            if not chunk:
                break
            fp.write(chunk)
            offset += len(chunk)
    return out


def get_service_values(hive_path: Path, service_name: str) -> dict[str, bytes] | None:
    """Return a dict of value-name -> raw value bytes for the named service."""
    h = RegistryHive(str(hive_path))
    for cs_name in ("ControlSet001", "CurrentControlSet"):
        try:
            node = h.get_key(f"\\{cs_name}\\Services\\{service_name}")
            out = {}
            for v in node.iter_values():
                # regipy gives us decoded values; for bytes-comparison we
                # serialize back to bytes.
                val = v.value
                if isinstance(val, bytes):
                    out[v.name] = val
                elif isinstance(val, int):
                    out[v.name] = val.to_bytes(8, "little")
                elif isinstance(val, str):
                    out[v.name] = val.encode("utf-16-le")
                else:
                    out[v.name] = repr(val).encode()
            return out
        except Exception:
            continue
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--planted", required=True)
    ap.add_argument("--scratch", default="/tmp/synth-regress")
    args = ap.parse_args()

    try:
        manifest = json.loads(Path(args.manifest).read_text())
    except Exception as e:
        print(f"[REGRESS FAIL 1] manifest unreadable: {e}", file=sys.stderr)
        sys.exit(1)

    for p_arg in [args.base, args.planted]:
        if not Path(p_arg).exists():
            print(f"[REGRESS FAIL 1] missing input: {p_arg}", file=sys.stderr)
            sys.exit(1)

    scratch = Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)

    partition_index = manifest["base"].get("windows_partition_index", 1)

    expected = manifest["base"].get("expected_baseline_findings", [])
    if not expected:
        info("manifest declares zero baseline findings to regress; skipping")
        sys.exit(0)

    fail_count = 0
    not_found = 0
    rows = []

    # Cache hive extractions per (raw, hive_name)
    cache: dict[tuple[str, str], Path] = {}

    def get_hive(raw_path: str, hive_name: str) -> Path:
        key = (raw_path, hive_name)
        if key not in cache:
            cache[key] = extract_hive(raw_path, hive_name, scratch, partition_index)
        return cache[key]

    for entry in expected:
        bid = entry["id"]
        target = BASELINE_TARGETS.get(bid)
        if target is None:
            rows.append((bid, "SKIP", f"no baseline target spec for id: {bid}"))
            continue

        try:
            base_hive = get_hive(args.base, target["hive"])
            planted_hive = get_hive(args.planted, target["hive"])
        except Exception as e:
            rows.append((bid, "ERROR", f"hive extract failed: {e}"))
            fail_count += 1
            continue

        base_vals = get_service_values(base_hive, target["service_name"])
        planted_vals = get_service_values(planted_hive, target["service_name"])

        if base_vals is None:
            rows.append((bid, "FAIL", f"baseline service NOT in base disk: {target['service_name']}"))
            not_found += 1
            continue
        if planted_vals is None:
            rows.append((bid, "FAIL", f"baseline service NOT in planted disk: {target['service_name']}"))
            fail_count += 1
            continue

        # Compare each value-of-interest
        differences = []
        for vname in target["compare_values"]:
            b = base_vals.get(vname)
            p = planted_vals.get(vname)
            if b != p:
                differences.append(f"{vname}: base={b!r} vs planted={p!r}")

        if differences:
            rows.append((bid, "FAIL", "; ".join(differences)))
            fail_count += 1
        else:
            rows.append((bid, "PASS", f"{target['service_name']} byte-identical for {target['compare_values']}"))

    print()
    print("=" * 72)
    for bid, status, msg in rows:
        print(f"  [{status}] {bid}: {msg}")
    print("=" * 72)
    print(f"REGRESS: passed {len([r for r in rows if r[1] == 'PASS'])}/{len(rows)} baseline entries")
    print()

    if not_found:
        sys.exit(3)
    if fail_count:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
