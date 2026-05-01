"""Unit tests for the placeholder DSL extractors.

Covers _resolve_inode_by_name (existing) and _resolve_nth_file_inode
(2026-05-01 addition for scheduled_tasks_parse multi-step planning).
"""
from __future__ import annotations

import pytest

from pipeline.nodes import (
    _resolve_inode_by_name,
    _resolve_nth_file_inode,
    ResolverError,
)


# Mimics the FlsResult.structured_fields shape used by execute_node
def _fls(*entries) -> dict:
    return {"entries": list(entries)}


def _entry(inode: int, name: str, entry_type: str = "file") -> dict:
    return {"inode": inode, "filename_safe": name, "entry_type": entry_type}


# ---- inode_by_name (existing extractor; smoke tests) ---------------------


def test_inode_by_name_unique_match_returns_inode():
    structured = _fls(_entry(100, "SOFTWARE"), _entry(200, "SYSTEM"))
    assert _resolve_inode_by_name(structured, "SOFTWARE") == 100


def test_inode_by_name_case_insensitive():
    structured = _fls(_entry(100, "SOFTWARE"))
    assert _resolve_inode_by_name(structured, "software") == 100


def test_inode_by_name_no_match_raises():
    structured = _fls(_entry(100, "SOFTWARE"))
    with pytest.raises(ResolverError, match="no match"):
        _resolve_inode_by_name(structured, "DEFAULT")


# ---- nth_file_inode (new extractor for scheduled_tasks_parse) ------------


def test_nth_file_inode_zero_returns_first_file():
    structured = _fls(
        _entry(10, "Microsoft", entry_type="directory"),
        _entry(20, "Sandworm", entry_type="directory"),
        _entry(30, "TorProxy", entry_type="file"),
        _entry(40, "xinference", entry_type="file"),
    )
    assert _resolve_nth_file_inode(structured, "0") == 30


def test_nth_file_inode_one_returns_second_file():
    structured = _fls(
        _entry(30, "TorProxy", entry_type="file"),
        _entry(40, "xinference", entry_type="file"),
        _entry(50, "AdminCheck", entry_type="file"),
    )
    assert _resolve_nth_file_inode(structured, "1") == 40


def test_nth_file_inode_skips_directories():
    """The recurse=true fls_list emits both directories (Microsoft, Sandworm)
    and files (TorProxy). The extractor must filter out directories so N
    indexes only into files."""
    structured = _fls(
        _entry(10, "Microsoft", entry_type="directory"),
        _entry(20, "Windows", entry_type="directory"),
        _entry(30, "task1", entry_type="file"),
    )
    assert _resolve_nth_file_inode(structured, "0") == 30


def test_nth_file_inode_dedupes_same_inode():
    """NTFS lists files twice when both $FILE_NAME and the resident name
    attributes exist (same inode, different names). The extractor dedupes
    by inode so N=0 / N=1 don't both point at the same file."""
    structured = _fls(
        _entry(30, "TorProxy ($FILE_NAME)", entry_type="file"),
        _entry(30, "TorProxy", entry_type="file"),
        _entry(40, "xinference", entry_type="file"),
    )
    assert _resolve_nth_file_inode(structured, "0") == 30
    assert _resolve_nth_file_inode(structured, "1") == 40


def test_nth_file_inode_out_of_range_raises():
    structured = _fls(_entry(30, "task1", entry_type="file"))
    with pytest.raises(ResolverError, match="out of range"):
        _resolve_nth_file_inode(structured, "5")


def test_nth_file_inode_negative_raises():
    structured = _fls(_entry(30, "task1", entry_type="file"))
    with pytest.raises(ResolverError, match="out of range"):
        _resolve_nth_file_inode(structured, "-1")


def test_nth_file_inode_non_int_raises():
    structured = _fls(_entry(30, "task1", entry_type="file"))
    with pytest.raises(ResolverError, match="not an int"):
        _resolve_nth_file_inode(structured, "abc")


def test_nth_file_inode_empty_listing_out_of_range():
    """No files in the listing -> any N is out of range."""
    structured = _fls(_entry(10, "Microsoft", entry_type="directory"))
    with pytest.raises(ResolverError, match="out of range"):
        _resolve_nth_file_inode(structured, "0")
