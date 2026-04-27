"""Append-only integrity ledger — Slice 6 Step 4a primitive (MVP).

Tamper-evident linear hash-chain over pipeline events. Every entry carries a
pointer to its predecessor's hash; mutating any field of any entry breaks
the chain from that point onward, and `verify_ledger` detects it.

Scope (per `memory/project_core_vs_peripheral.md`): this is MVP credibility
scaffolding, not core. Kept minimal on purpose:

  - Linear hash chain (not a Merkle tree, not HMAC-signed).
  - Per-case storage (`out/runs/<case_id>/integrity_ledger.jsonl`), not a
    global Docker-volume ledger. Post-hackathon we can promote the storage
    location; the entry format doesn't change.
  - No live pipeline wiring yet — that's Step 4b. This step ships the
    primitive + tests only.

Exports:
  - `LedgerEntry` — Pydantic shape of one JSONL line.
  - `LedgerEventType` — Literal of the small event alphabet this version emits.
  - `LedgerWriter` — append-only context manager; tracks last entry_hash,
    computes new entry_hash on `append()`.
  - `compute_entry_hash(entry_dict)` — canonical-JSON sha256, entry_hash field
    excluded from the input.
  - `verify_ledger(path)` -> `(valid, entries_verified, error_msg)` — replay
    the JSONL, recompute every entry's hash, confirm predecessor linkage.
    Clean chain → `(True, N, None)`. Tampered chain → `(False, K, err)`
    where K is the count of entries that verified BEFORE the break (so
    "chain valid up to K" semantics). Partial chain (crashed mid-run,
    never closed) verifies fine as a prefix — MVP treats truncation as
    legitimate session termination, not corruption.

Hashing scheme:
  - Canonical JSON: `sort_keys=True, separators=(",",":"), ensure_ascii=False`,
    with the `entry_hash` field removed before serialization.
  - sha256 of UTF-8 bytes → hex. The entry_hash field holds the hex digest.
  - `prev_entry_hash=""` marks the genesis entry.

Design notes worth keeping in mind:
  - No lock file. Concurrent writers to the same ledger file WILL corrupt
    the chain. Only the orchestrator writes, and pipeline runs are
    sequential per case — not a concern under current topology.
  - `timestamp_utc` is an ISO 8601 string, not a datetime. Keeps the
    canonical-bytes path pure and JSON round-tripping lossless.
  - Payload fields beyond the schema minimum are permitted — Pydantic
    `model_config = {"extra": "allow"}` lets Step 4b wire in extra fields
    (raw_sha256, finding_index, etc.) without schema churn.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


LedgerEventType = Literal[
    "genesis",                  # case initialization — anchors chain with e01_sha256
    "plan_approved",            # tool plan finalized + capability token issued
    "tool_call_completed",      # one EvidenceRecord written; raw_sha256 included
    "finding_committed",        # one Finding entered findings.json
    "critic_decision",          # Critic severity decision (pass / retry / escalate)
    "session_close",            # pipeline run ended cleanly
    "human_review_completed",   # human adjudicated a HUMAN_REVIEW/QUARANTINED run; decision doc co-located in 08_human_decision.json
]


# ============================================================================
# Canonical hashing
# ============================================================================

def _canonical_entry_bytes(entry_dict: dict) -> bytes:
    """Order-independent, whitespace-stable JSON serialization for hashing.
    Excludes `entry_hash` from the input (that's what we're computing)."""
    clone = {k: v for k, v in entry_dict.items() if k != "entry_hash"}
    return json.dumps(
        clone, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, default=str,
    ).encode("utf-8")


def compute_entry_hash(entry_dict: dict) -> str:
    """Hex sha256 over the canonical-JSON form of an entry (entry_hash excluded)."""
    return hashlib.sha256(_canonical_entry_bytes(entry_dict)).hexdigest()


# ============================================================================
# Entry schema
# ============================================================================

class LedgerEntry(BaseModel):
    """One line of the ledger JSONL. Minimum fields required; `extra=allow`
    lets Step 4b wire in per-event payload (raw_sha256, finding_index, etc.)
    without schema changes."""
    model_config = ConfigDict(extra="allow")

    seq: int                             # 0-indexed; genesis = 0
    event_type: LedgerEventType
    timestamp_utc: str                   # ISO 8601 — string, not datetime, for hash stability
    case_id: str
    plan_digest: str = ""                # "" on genesis before plan_approved
    prev_entry_hash: str                 # "" on genesis
    entry_hash: str = Field(..., min_length=64, max_length=64)


# ============================================================================
# Writer
# ============================================================================

class LedgerWriter:
    """Append-only writer. Stateful only on the last entry's hash — which
    we read from disk on open so multiple LedgerWriter sessions against the
    same file continue the chain seamlessly.

    Usage:
        with LedgerWriter(path, case_id="foo") as w:
            w.append_genesis(e01_sha256="...")
            w.append(event_type="tool_call_completed", tool_call_id="tc-1", raw_sha256="...")
            w.append(event_type="session_close", findings_count=1)
    """

    def __init__(self, path: str | Path, case_id: str):
        self.path = Path(path)
        self.case_id = case_id
        self._fp = None
        self._last_hash = ""
        self._seq = 0

    def __enter__(self) -> "LedgerWriter":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # If file exists, load last entry to continue the chain.
        if self.path.exists() and self.path.stat().st_size > 0:
            self._resume()
        self._fp = self.path.open("a", encoding="utf-8")
        return self

    def __exit__(self, *exc):
        if self._fp is not None:
            self._fp.close()
            self._fp = None
        return False

    def _resume(self) -> None:
        """Read existing JSONL to pick up last entry_hash + seq."""
        last_line = None
        with self.path.open("r", encoding="utf-8") as fp:
            for line in fp:
                s = line.strip()
                if s:
                    last_line = s
        if last_line is None:
            return
        last = json.loads(last_line)
        # Verify the tail entry's hash matches — if the file was tampered with
        # we want to refuse to append to an already-broken chain.
        recomputed = compute_entry_hash(last)
        if recomputed != last.get("entry_hash", ""):
            raise ValueError(
                f"Refusing to append: last entry in {self.path} has "
                f"entry_hash={last.get('entry_hash')!r} but recomputed={recomputed!r} "
                f"— chain is already broken. Run verify_ledger() to diagnose."
            )
        self._last_hash = last["entry_hash"]
        self._seq = last["seq"] + 1

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def append_genesis(self, *, e01_sha256: str = "", plan_digest: str = "") -> LedgerEntry:
        """Write the genesis entry. Must be called before any other append
        on a fresh ledger file. No-op if the ledger already has entries
        (resume semantics)."""
        if self._seq != 0 or self._last_hash:
            # Already initialized — genesis was written in a prior session.
            # Not an error; idempotent under resume.
            return self._peek_genesis()
        return self.append(
            event_type="genesis", e01_sha256=e01_sha256, plan_digest=plan_digest,
        )

    def _peek_genesis(self) -> LedgerEntry:
        """Read the first line of the file (the genesis entry) and return it.
        Used by append_genesis() when resuming."""
        with self.path.open("r", encoding="utf-8") as fp:
            line = fp.readline()
        return LedgerEntry.model_validate_json(line)

    def append(self, *, event_type: LedgerEventType, **payload) -> LedgerEntry:
        """Compute + write a new entry. Returns the written LedgerEntry."""
        if self._fp is None:
            raise RuntimeError("LedgerWriter used outside context manager")
        entry_dict = {
            "seq": self._seq,
            "event_type": event_type,
            "timestamp_utc": self._now_iso(),
            "case_id": self.case_id,
            "plan_digest": payload.pop("plan_digest", ""),
            "prev_entry_hash": self._last_hash,
            **payload,
        }
        entry_dict["entry_hash"] = compute_entry_hash(entry_dict)
        entry = LedgerEntry.model_validate(entry_dict)
        self._fp.write(entry.model_dump_json() + "\n")
        self._fp.flush()
        self._last_hash = entry.entry_hash
        self._seq += 1
        return entry

    @property
    def next_seq(self) -> int:
        return self._seq

    @property
    def last_entry_hash(self) -> str:
        return self._last_hash


# ============================================================================
# Verifier
# ============================================================================

def verify_ledger(path: str | Path) -> tuple[bool, int, str | None]:
    """Replay the JSONL and confirm the hash chain.

    Returns:
      (True, N, None)          — N entries, chain clean
      (False, K, error_msg)    — break at entry K; entries 0..K-1 verified clean
      (True, 0, None)          — empty / missing file treated as empty chain

    Semantics: partial chains (the writer crashed before session_close) count
    as valid prefix, NOT corruption. If corruption is detected, `K` is the
    count of entries that verified *before* the break — so "chain valid up
    to entry K" is the reviewer's statement.
    """
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return True, 0, None

    prev_hash = ""
    verified = 0
    with p.open("r", encoding="utf-8") as fp:
        for i, line in enumerate(fp):
            s = line.strip()
            if not s:
                continue
            try:
                entry = json.loads(s)
            except json.JSONDecodeError as e:
                return False, verified, f"entry {i}: JSON decode failed: {e}"

            eh = entry.get("entry_hash", "")
            if not isinstance(eh, str) or len(eh) != 64:
                return False, verified, (f"entry {i}: entry_hash malformed "
                                         f"(len={len(eh) if isinstance(eh, str) else 'n/a'})")
            try:
                int(eh, 16)
            except ValueError:
                return False, verified, f"entry {i}: entry_hash={eh!r} not hex"

            if entry.get("prev_entry_hash", None) != prev_hash:
                return False, verified, (
                    f"entry {i}: prev_entry_hash={entry.get('prev_entry_hash')!r} "
                    f"does not match predecessor's entry_hash={prev_hash!r}"
                )

            recomputed = compute_entry_hash(entry)
            if recomputed != eh:
                return False, verified, (
                    f"entry {i}: recomputed hash={recomputed} "
                    f"does not match stored={eh}"
                )

            prev_hash = eh
            verified += 1

    return True, verified, None


__all__ = [
    "LedgerEventType",
    "LedgerEntry",
    "LedgerWriter",
    "compute_entry_hash",
    "verify_ledger",
]
