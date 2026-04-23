"""Extract a raw NTFS partition from an E01 forensic image.

Runs inside a PRIVILEGED sift container (needs FUSE for ewfmount).

  docker run --rm -it --privileged --device /dev/fuse \
    -v "D:/Python Applications/Find Evil - Hackathon/HACKATHON-2026:/mnt/hackathon:ro" \
    -v "D:/Python Applications/Find Evil - Hackathon/HACKATHON-2026/derived:/mnt/derived:rw" \
    -v "D:/Python Applications/Find Evil - Hackathon/experiments/slice-2-notebook:/work:ro" \
    find-evil/sift:slice5 \
    python3 /work/preprocess_e01.py --case base-dc

Pipeline per case: ewfmount -> mmls -> pick-largest-NTFS -> dd -> fsstat verify -> sha256.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

HACKATHON_DIR = Path("/mnt/hackathon")
DERIVED_DIR = Path("/mnt/derived")
E01_NAME_PATTERNS = ["{case}-cdrive.E01", "{case}-c-drive.E01"]


@dataclass
class Partition:
    slot: str
    start: int
    end: int
    length: int
    description: str


def parse_mmls(output: str) -> list[Partition]:
    """Parse mmls stdout; skip meta + unallocated rows."""
    parts: list[Partition] = []
    for line in output.splitlines():
        line = line.rstrip()
        if not line or ":" not in line:
            continue
        row_num = line.split(":", 1)[0].strip()
        if not row_num.isdigit():
            continue
        rest = line.split(":", 1)[1].strip()
        fields = rest.split(None, 4)
        if len(fields) < 5:
            continue
        slot, start, end, length, description = fields
        try:
            start_i, end_i, length_i = int(start), int(end), int(length)
        except ValueError:
            continue
        if (
            slot == "-------"
            or "Meta" in description
            or "Primary Table" in description
            or "Unallocated" in description
        ):
            continue
        parts.append(Partition(slot, start_i, end_i, length_i, description))
    return parts


def pick_ntfs(parts: list[Partition]) -> Partition:
    ntfs = [p for p in parts if "NTFS" in p.description]
    if not ntfs:
        raise SystemExit(
            "no NTFS partition found in mmls output; "
            "inspect the stdout above for unexpected table layout"
        )
    return max(ntfs, key=lambda p: p.length)


def find_e01(case: str) -> Path:
    for pat in E01_NAME_PATTERNS:
        p = HACKATHON_DIR / pat.format(case=case)
        if p.exists():
            return p
    raise SystemExit(
        f"no E01 found for case {case!r} in {HACKATHON_DIR}; "
        f"tried: {[pat.format(case=case) for pat in E01_NAME_PATTERNS]}"
    )


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, check=True, text=True, **kw)


def sha256_file(path: Path, chunk: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def preprocess(case: str, force: bool = False) -> int:
    e01 = find_e01(case)
    out = DERIVED_DIR / f"{case}.ntfs.dd"
    if out.exists() and not force:
        raise SystemExit(f"{out} already exists; pass --force to overwrite")

    mount = Path(tempfile.mkdtemp(prefix="ewf_"))
    try:
        run(["ewfmount", str(e01), str(mount)])
        ewf1 = mount / "ewf1"
        if not ewf1.exists():
            raise SystemExit(f"ewfmount succeeded but {ewf1} missing")

        # Detect layout: is ewf1 a full disk (needs mmls+dd to slice) or already a raw NTFS partition?
        probe = subprocess.run(
            ["fsstat", str(ewf1)], text=True, capture_output=True
        )
        if "File System Type: NTFS" in probe.stdout:
            print(f"ewf1 is already a raw NTFS partition (E01 is partition-only); copying whole blob")
            run([
                "dd",
                f"if={ewf1}",
                f"of={out}",
                "bs=4M",
                "status=progress",
                "conv=sparse",
            ])
        else:
            mmls_res = subprocess.run(
                ["mmls", str(ewf1)], text=True, capture_output=True
            )
            if mmls_res.returncode != 0:
                raise SystemExit(
                    f"mmls failed (rc={mmls_res.returncode}) and fsstat did not detect NTFS on ewf1 directly.\n"
                    f"mmls stdout:\n{mmls_res.stdout}\n"
                    f"mmls stderr:\n{mmls_res.stderr}\n"
                    f"fsstat stdout head:\n{probe.stdout[:400]}\n"
                    f"fsstat stderr head:\n{probe.stderr[:400]}"
                )
            print(mmls_res.stdout)
            parts = parse_mmls(mmls_res.stdout)
            ntfs = pick_ntfs(parts)
            print(
                f"picked NTFS partition: start_sector={ntfs.start} "
                f"length_sectors={ntfs.length} ({ntfs.length * 512 / 1e9:.1f} GB)"
            )
            run([
                "dd",
                f"if={ewf1}",
                f"of={out}",
                "bs=512",
                f"skip={ntfs.start}",
                f"count={ntfs.length}",
                "status=progress",
                "conv=sparse",
            ])
    finally:
        subprocess.run(["fusermount", "-u", str(mount)], check=False)
        try:
            mount.rmdir()
        except OSError:
            pass

    fsstat_res = subprocess.run(
        ["fsstat", str(out)], check=True, text=True, capture_output=True
    )
    if "File System Type: NTFS" not in fsstat_res.stdout:
        raise SystemExit(
            f"fsstat did not report NTFS for {out}; output head:\n"
            f"{fsstat_res.stdout[:500]}"
        )

    size = out.stat().st_size
    digest = sha256_file(out)

    print()
    print("=" * 70)
    print("RESULT")
    print("=" * 70)
    print(f"  case:     {case}")
    print(f"  source:   {e01}")
    print(f"  output:   {out}")
    print(f"  size:     {size:,} bytes ({size / 1e9:.2f} GB)")
    print(f"  sha256:   {digest}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--case", required=True, help="case id, e.g. base-dc")
    ap.add_argument("--force", action="store_true", help="overwrite existing .ntfs.dd")
    args = ap.parse_args()
    return preprocess(args.case, force=args.force)


if __name__ == "__main__":
    sys.exit(main())
