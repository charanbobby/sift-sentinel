"""Test pipeline.ledger — integrity ledger MVP (Slice 6 Step 4a).

Covers the hash-chain invariants, LedgerWriter's resume-from-last-entry
behavior, and verify_ledger's tamper detection + partial-chain semantics.
Mirrors the reference probe at `d:/tmp/probe_ledger.py`.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.ledger import (
    LedgerEntry, LedgerWriter, compute_entry_hash, verify_ledger,
)


# ---- compute_entry_hash ----------------------------------------------------


def test_compute_entry_hash_deterministic_under_insertion_order():
    """Canonical JSON must sort keys so two dicts with the same fields in
    different insertion order hash identically."""
    a = {"seq": 0, "case_id": "c", "event_type": "genesis",
         "timestamp_utc": "2026-04-24T12:00:00+00:00", "prev_entry_hash": "",
         "plan_digest": ""}
    b = {"plan_digest": "", "timestamp_utc": "2026-04-24T12:00:00+00:00",
         "event_type": "genesis", "seq": 0, "case_id": "c", "prev_entry_hash": ""}
    assert compute_entry_hash(a) == compute_entry_hash(b)


def test_compute_entry_hash_excludes_entry_hash_field():
    """The field we're computing must not be part of its own input."""
    base = {"seq": 0, "case_id": "c", "event_type": "genesis",
            "timestamp_utc": "t", "prev_entry_hash": "", "plan_digest": ""}
    # Compute the hash, then add it to the dict — re-computing must still return
    # the same value (because entry_hash is excluded from the canonical form).
    h = compute_entry_hash(base)
    with_self = dict(base, entry_hash=h)
    assert compute_entry_hash(with_self) == h


def test_compute_entry_hash_changes_on_any_field_change():
    """Every field contributes — mutating any field changes the hash."""
    base = {"seq": 0, "case_id": "c", "event_type": "genesis",
            "timestamp_utc": "t", "prev_entry_hash": "", "plan_digest": ""}
    h0 = compute_entry_hash(base)
    for field in ("seq", "case_id", "event_type", "timestamp_utc",
                  "prev_entry_hash", "plan_digest"):
        mutated = dict(base)
        mutated[field] = ("X" if field != "seq" else 999)
        assert compute_entry_hash(mutated) != h0, f"mutation of {field!r} did not change hash"


# ---- LedgerWriter ----------------------------------------------------------


def test_writer_genesis_then_events_clean_chain(tmp_path: Path):
    p = tmp_path / "ledger.jsonl"
    with LedgerWriter(p, case_id="case-1") as w:
        g = w.append_genesis(e01_sha256="a" * 64, plan_digest="d" * 64)
        t = w.append(event_type="tool_call_completed", plan_digest="d" * 64,
                     tool_call_id="tc-1", raw_sha256="b" * 64)
        c = w.append(event_type="session_close", plan_digest="d" * 64,
                     findings_count=0)
    # Entries chained
    assert g.seq == 0
    assert g.prev_entry_hash == ""
    assert t.prev_entry_hash == g.entry_hash
    assert c.prev_entry_hash == t.entry_hash
    # File exists + verifies
    ok, n, err = verify_ledger(p)
    assert ok and n == 3, err


def test_writer_resume_appends_to_last_entry(tmp_path: Path):
    p = tmp_path / "ledger.jsonl"
    # Session 1: write two entries
    with LedgerWriter(p, case_id="case-1") as w1:
        g = w1.append_genesis(e01_sha256="a" * 64)
        t = w1.append(event_type="tool_call_completed", tool_call_id="tc-1",
                      raw_sha256="b" * 64)
    # Session 2: open again, append_genesis is idempotent, append new entry
    with LedgerWriter(p, case_id="case-1") as w2:
        assert w2.next_seq == 2
        assert w2.last_entry_hash == t.entry_hash
        g2 = w2.append_genesis()  # idempotent — returns the existing genesis
        assert g2.entry_hash == g.entry_hash
        f = w2.append(event_type="finding_committed", finding_index=0,
                      excerpt_sha256="c" * 64)
    ok, n, err = verify_ledger(p)
    assert ok and n == 3, err
    # Resume gave us entry 2 (seq 2) linked to entry 1
    assert f.seq == 2
    assert f.prev_entry_hash == t.entry_hash


def test_writer_refuses_to_append_to_tampered_tail(tmp_path: Path):
    """If the last-entry hash on disk doesn't match its recomputed hash,
    the resume code must refuse to open — otherwise we'd happily extend
    a chain that's already been tampered with."""
    p = tmp_path / "ledger.jsonl"
    with LedgerWriter(p, case_id="case-1") as w:
        w.append_genesis(e01_sha256="a" * 64)
        w.append(event_type="tool_call_completed", tool_call_id="tc-1",
                 raw_sha256="b" * 64)
    # Tamper with the last line's tool_call_id — leave entry_hash stale
    lines = p.read_text(encoding="utf-8").splitlines()
    last = json.loads(lines[-1])
    last["tool_call_id"] = "tc-ATTACKER"
    lines[-1] = json.dumps(last)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Attempting to resume must raise
    with pytest.raises(ValueError, match="Refusing to append"):
        with LedgerWriter(p, case_id="case-1"):
            pass


def test_writer_outside_context_manager_raises(tmp_path: Path):
    """LedgerWriter is strictly a context manager — calling append outside
    the `with` block is a programming error, raised explicitly."""
    w = LedgerWriter(tmp_path / "ledger.jsonl", case_id="c")
    with pytest.raises(RuntimeError, match="outside context manager"):
        w.append(event_type="genesis")


# ---- verify_ledger --------------------------------------------------------


def test_verify_empty_or_missing_file(tmp_path: Path):
    """Missing file → (True, 0, None). Empty file → same. These are 'no run
    yet' and 'run hadn't started' respectively, not corruption."""
    missing = tmp_path / "does-not-exist.jsonl"
    ok, n, err = verify_ledger(missing)
    assert ok and n == 0 and err is None
    empty = tmp_path / "empty.jsonl"
    empty.touch()
    ok, n, err = verify_ledger(empty)
    assert ok and n == 0 and err is None


def test_verify_clean_five_entry_chain(tmp_path: Path):
    p = tmp_path / "ledger.jsonl"
    with LedgerWriter(p, case_id="c") as w:
        w.append_genesis(e01_sha256="a" * 64)
        w.append(event_type="plan_approved", plan_digest="d" * 64)
        w.append(event_type="tool_call_completed", tool_call_id="tc-1",
                 raw_sha256="b" * 64)
        w.append(event_type="finding_committed", finding_index=0,
                 excerpt_sha256="c" * 64)
        w.append(event_type="critic_decision", finding_index=0,
                 severity="pass")
    ok, n, err = verify_ledger(p)
    assert ok and n == 5 and err is None


def test_verify_tamper_on_middle_entry(tmp_path: Path):
    """Mutate entry 1 (middle of chain) — verifier reports break at that
    point, with entry 0 having verified successfully (so verified=1)."""
    p = tmp_path / "ledger.jsonl"
    with LedgerWriter(p, case_id="c") as w:
        w.append_genesis(e01_sha256="a" * 64)
        w.append(event_type="tool_call_completed", tool_call_id="tc-1",
                 raw_sha256="b" * 64)
        w.append(event_type="session_close")
    lines = p.read_text(encoding="utf-8").splitlines()
    entry1 = json.loads(lines[1])
    entry1["tool_call_id"] = "tc-ATTACKER"  # field mutation without hash recompute
    lines[1] = json.dumps(entry1)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, n, err = verify_ledger(p)
    assert not ok
    assert n == 1, f"expected verified=1 (genesis clean, break at entry 1), got {n}"
    assert "recomputed hash" in err


def test_verify_tamper_on_genesis(tmp_path: Path):
    """Mutating entry 0 → verified=0; whole chain invalidated."""
    p = tmp_path / "ledger.jsonl"
    with LedgerWriter(p, case_id="c") as w:
        w.append_genesis(e01_sha256="a" * 64)
        w.append(event_type="session_close")
    lines = p.read_text(encoding="utf-8").splitlines()
    entry0 = json.loads(lines[0])
    entry0["e01_sha256"] = "f" * 64
    lines[0] = json.dumps(entry0)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, n, err = verify_ledger(p)
    assert not ok and n == 0


def test_verify_accepts_partial_chain_as_prefix(tmp_path: Path):
    """A chain that ends without session_close (e.g. orchestrator crashed
    mid-run) is INCOMPLETE, not CORRUPT. Verifier must accept it and report
    valid-through-entry-N so the reviewer can decide."""
    p = tmp_path / "ledger.jsonl"
    with LedgerWriter(p, case_id="c") as w:
        w.append_genesis(e01_sha256="a" * 64)
        w.append(event_type="tool_call_completed", tool_call_id="tc-1",
                 raw_sha256="b" * 64)
        # No session_close
    ok, n, err = verify_ledger(p)
    assert ok and n == 2 and err is None


def test_verify_malformed_entry_hash_rejected(tmp_path: Path):
    """An entry with a non-hex / wrong-length entry_hash is rejected with
    a clear error rather than crashing."""
    p = tmp_path / "ledger.jsonl"
    with LedgerWriter(p, case_id="c") as w:
        w.append_genesis(e01_sha256="a" * 64)
    # Overwrite entry_hash with junk
    line = p.read_text(encoding="utf-8").splitlines()[0]
    entry = json.loads(line)
    entry["entry_hash"] = "not-a-hash"
    p.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    ok, n, err = verify_ledger(p)
    assert not ok and n == 0
    assert "malformed" in err


def test_verify_non_hex_entry_hash_rejected(tmp_path: Path):
    """entry_hash of correct length 64 but with non-hex chars is rejected."""
    p = tmp_path / "ledger.jsonl"
    with LedgerWriter(p, case_id="c") as w:
        w.append_genesis(e01_sha256="a" * 64)
    line = p.read_text(encoding="utf-8").splitlines()[0]
    entry = json.loads(line)
    entry["entry_hash"] = "Z" * 64  # 64 chars but not hex
    p.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    ok, n, err = verify_ledger(p)
    assert not ok and n == 0
    assert "not hex" in err


# ---- LedgerEntry schema ---------------------------------------------------


def test_entry_schema_accepts_extra_payload_fields():
    """`extra=allow` on the model so Step 4b can wire in fields like
    raw_sha256, finding_index, severity, etc. without schema churn."""
    e = LedgerEntry(
        seq=0, event_type="tool_call_completed",
        timestamp_utc="2026-04-24T12:00:00+00:00",
        case_id="c", plan_digest="", prev_entry_hash="",
        entry_hash="f" * 64,
        # Extras:
        tool_call_id="tc-1", raw_sha256="a" * 64,
    )
    dumped = e.model_dump()
    assert dumped["tool_call_id"] == "tc-1"
    assert dumped["raw_sha256"] == "a" * 64


def test_entry_schema_rejects_wrong_length_entry_hash():
    """Pydantic gate on entry_hash = exactly 64 chars."""
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        LedgerEntry(
            seq=0, event_type="genesis",
            timestamp_utc="t", case_id="c", plan_digest="",
            prev_entry_hash="", entry_hash="short",
        )


def test_entry_schema_json_round_trip():
    p = LedgerEntry(
        seq=0, event_type="genesis",
        timestamp_utc="2026-04-24T12:00:00+00:00",
        case_id="c", plan_digest="", prev_entry_hash="",
        entry_hash="a" * 64,
    )
    js = p.model_dump_json()
    p2 = LedgerEntry.model_validate_json(js)
    assert p == p2
