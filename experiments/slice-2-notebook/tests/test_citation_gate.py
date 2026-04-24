"""Test the citation-gate mechanism (Tier-1 AI-adversary add-on, 2026-04-24).

The R_14 rule itself is NOT yet wired into CRITIC_RULES — activation is
deferred until an end-to-end pipeline run confirms the INTERPRET LLM
cooperates with the `[ev:<tool_call_id>]` citation format specified in
INTERPRET_SYSTEM_PROMPT (Hard Rule 7). Same opt-in-until-verified pattern
the canary tripwire followed.

This file covers:
  - parse_evidence_citations — regex extraction edge cases
  - validate_finding_citations — cross-check against bundle IDs
  - UNCITED_CLAIM in FailureCode + ESCALATE_CODES
"""
from __future__ import annotations

import pytest

from pipeline.critic import (
    CitationCheckResult,
    ESCALATE_CODES,
    parse_evidence_citations,
    validate_finding_citations,
)


# ---- parse_evidence_citations ----------------------------------------------


def test_parse_single_citation():
    assert parse_evidence_citations("See [ev:tc-0] for confirmation.") == ["tc-0"]


def test_parse_multiple_distinct():
    got = parse_evidence_citations("[ev:tc-0] and [ev:tc-2] and finally [ev:tc-5].")
    assert got == ["tc-0", "tc-2", "tc-5"]


def test_parse_duplicates_preserved():
    """Duplicates are intentional — the caller may want to know which
    tool_call_ids were cited multiple times."""
    got = parse_evidence_citations("[ev:tc-1] bla [ev:tc-1] bla [ev:tc-1].")
    assert got == ["tc-1", "tc-1", "tc-1"]


def test_parse_no_citations():
    assert parse_evidence_citations("Ruled out DFIR tools and vendor products.") == []


def test_parse_empty_string():
    assert parse_evidence_citations("") == []


def test_parse_malformed_missing_colon():
    """[ev tc-0] (no colon) should not match — strictness prevents
    ambiguous free text from resolving to a false citation."""
    assert parse_evidence_citations("[ev tc-0]") == []


def test_parse_malformed_space_inside():
    """Internal whitespace after `ev:` should not match."""
    assert parse_evidence_citations("[ev: tc-0]") == []


def test_parse_back_to_back():
    got = parse_evidence_citations("[ev:tc-0][ev:tc-1]")
    assert got == ["tc-0", "tc-1"]


def test_parse_mixed_charset_ids():
    """tool_call_ids can carry underscores, dashes, digits, letters."""
    got = parse_evidence_citations("[ev:tc_abc-123] and [ev:step-42_alt]")
    assert got == ["tc_abc-123", "step-42_alt"]


def test_parse_with_surrounding_punctuation():
    got = parse_evidence_citations(
        "Value X was confirmed ([ev:tc-3]), which rules it out."
    )
    assert got == ["tc-3"]


def test_parse_none_safe():
    """Defensive — `None` should not raise."""
    assert parse_evidence_citations(None) == []  # type: ignore[arg-type]


# ---- validate_finding_citations --------------------------------------------


def test_validate_all_cited_ids_present():
    result = validate_finding_citations(
        "Confirmed via [ev:tc-0] and [ev:tc-1]; ruled out via [ev:tc-2].",
        {"tc-0", "tc-1", "tc-2", "tc-3"},
    )
    assert result.invalid_ids == set()
    assert result.has_citations is True
    assert result.distinct_cited == {"tc-0", "tc-1", "tc-2"}


def test_validate_cited_id_not_in_bundle():
    """Cited tool_call_id that does not exist in this run's bundle is the
    core UNCITED_CLAIM trigger — hallucinated citations fail."""
    result = validate_finding_citations(
        "Confirmed via [ev:tc-0] and [ev:tc-99].",  # tc-99 is invented
        {"tc-0", "tc-1"},
    )
    assert result.invalid_ids == {"tc-99"}
    assert result.has_citations is True  # markers were present; they're just wrong


def test_validate_no_citations():
    """When no citations appear at all, has_citations=False; invalid_ids empty
    (nothing to invalidate). The rule layer decides whether 'no citations'
    is a failure for this finding's classification+confidence."""
    result = validate_finding_citations(
        "Ruled out DFIR tools; path does not match any known vendor product.",
        {"tc-0", "tc-1"},
    )
    assert result.has_citations is False
    assert result.invalid_ids == set()
    assert result.cited_ids == []


def test_validate_empty_bundle_with_citation():
    """Empty available-set means every citation is by definition invalid."""
    result = validate_finding_citations("See [ev:tc-0].", set())
    assert result.invalid_ids == {"tc-0"}
    assert result.has_citations is True


def test_validate_empty_notes():
    result = validate_finding_citations("", {"tc-0"})
    assert result.has_citations is False
    assert result.cited_ids == []
    assert result.invalid_ids == set()


def test_validate_repeated_valid_citations():
    """Repeated citations to the same valid ID — valid, preserved in order."""
    result = validate_finding_citations(
        "[ev:tc-1] and again [ev:tc-1] and once more [ev:tc-1].",
        {"tc-1"},
    )
    assert result.invalid_ids == set()
    assert result.cited_ids == ["tc-1", "tc-1", "tc-1"]
    assert result.distinct_cited == {"tc-1"}


def test_validate_mixed_valid_and_invalid():
    result = validate_finding_citations(
        "Supported by [ev:tc-0] and [ev:tc-1]. Also [ev:tc-missing] and [ev:tc-bogus].",
        {"tc-0", "tc-1", "tc-2"},
    )
    assert result.invalid_ids == {"tc-missing", "tc-bogus"}
    assert result.has_citations is True


def test_validate_result_repr_is_legible():
    """__repr__ is a debugging aid — make sure it includes all the fields
    a human would want to see when a test failure dumps the value."""
    result = validate_finding_citations("[ev:tc-0]", {"tc-1"})
    s = repr(result)
    assert "tc-0" in s
    assert "invalid_ids" in s
    assert "has_citations" in s


# ---- UNCITED_CLAIM registered in ESCALATE_CODES ----------------------------


def test_uncited_claim_in_escalate_codes():
    """The failure code must be in ESCALATE_CODES so when R_14 is activated,
    uncited-claim failures route straight to human_review instead of retry."""
    assert "UNCITED_CLAIM" in ESCALATE_CODES


# ---- CitationCheckResult class sanity --------------------------------------


def test_citation_check_result_slots():
    """Use __slots__ so misspelled attribute accesses raise immediately
    rather than silently succeeding (important for a security mechanism)."""
    r = validate_finding_citations("[ev:tc-0]", {"tc-0"})
    assert isinstance(r, CitationCheckResult)
    with pytest.raises(AttributeError):
        r.not_a_real_field = 1  # type: ignore[attr-defined]
