"""Fail-fast probe for the wired-in Plan B Extract changes (Slice 6 Step B).

Exercises the patched pipeline.nodes module directly:
  1. _host_type_of returns expected host_type for known case_ids
  2. _build_extract_prompt produces channel-correct prompt strings
  3. The extract_node still imports cleanly (no syntax errors, no missing refs)

Run inside the SIFT container against the same venv the pipeline uses:
    docker exec sift-sentinel uv run python /workspace/probe_extract_b_wired.py
"""
from __future__ import annotations

import sys

sys.path.insert(0, "/workspace")

from pipeline import nodes
from pipeline.nodes import _host_type_of, _build_extract_prompt


# 1. host-type detection
expected = {
    "srl-2018-wkstn-05":   "workstation",
    "srl-2018-base-dc":    "domain_controller",
    "srl-2018-base-file":  "file_server",
    "srl-2018-base-rd-02": "rdp_gateway",
    "srl-2018-dmz-ftp":    "ftp_server",
    "dfirmadness-001-desktop": "workstation",
    "some-unknown-case":   "windows_host",
}
print("=" * 60)
print("1. _host_type_of cases")
print("=" * 60)
for cid, want in expected.items():
    got, desc = _host_type_of(cid)
    ok = "OK " if got == want else "FAIL"
    print(f"  [{ok}] {cid:30s} -> {got} ({desc[:50]})")
    assert got == want, f"Mismatch on {cid}: want {want}, got {got}"

# 2. prompt-builder smoke
print()
print("=" * 60)
print("2. _build_extract_prompt smoke")
print("=" * 60)
for cid, want_ht in expected.items():
    ht, desc = _host_type_of(cid)
    for has_mem in (True, False):
        prompt = _build_extract_prompt(ht, desc, has_mem)
        # mandatory invariants
        assert "HOST TYPE:" in prompt, "missing HOST TYPE header"
        assert ht in prompt, f"host_type {ht} not in prompt body"
        if has_mem:
            assert "disk + memory" in prompt, "should advertise dual channel"
            assert "MEMORY-CHANNEL EVIDENCE" in prompt, "missing memory guidance block"
            assert "process_anomaly" in prompt, "missing process_anomaly type ref"
        else:
            assert "disk only" in prompt, "should advertise disk-only"
            assert "DISK-ONLY CASE" in prompt, "missing disk-only guard block"
            assert "MUST NOT propose memory artifact_types" in prompt, "missing hard rule"
        # host-specific guidance presence (workstation/dc/file/rd/ftp/dmz/mail get extra block)
        if ht == "domain_controller":
            assert "NTDS" in prompt and "KRBTGT".lower() in prompt.lower(), "DC guidance dropped DC-specific paths"
        elif ht == "ftp_server":
            assert "FTPSVC" in prompt or "InetStp" in prompt, "FTP guidance dropped IIS/FTPSVC"
        elif ht == "rdp_gateway":
            assert "TermService" in prompt or "Terminal Server Client" in prompt, "RDP guidance dropped"
        elif ht == "file_server":
            assert "LanmanServer" in prompt, "file-server guidance dropped LanmanServer"
        elif ht == "windows_host":
            # generic falls back to no host_guidance block — universal list still present
            assert "Universal Windows persistence" in prompt, "universal block missing on generic"
        print(f"  [OK ] cid={cid:25s} ht={ht:18s} mem={has_mem}  ({len(prompt)} chars)")

print()
print("=" * 60)
print("3. extract_node import sanity")
print("=" * 60)
assert callable(nodes.extract_node), "extract_node not callable"
assert nodes._EXTRACT_SCHEMA, "_EXTRACT_SCHEMA missing"
assert hasattr(nodes, "_HOST_GUIDANCE"), "_HOST_GUIDANCE missing"
assert hasattr(nodes, "_MEMORY_GUIDANCE"), "_MEMORY_GUIDANCE missing"
assert hasattr(nodes, "_NO_MEMORY_GUIDANCE"), "_NO_MEMORY_GUIDANCE missing"
print("  [OK ] extract_node + new module-level symbols importable")
print()
print("ALL PROBES PASSED")
