"""Regression tests for the regripper services-plugin parser.

The parser had a bug (fixed 2026-05-01) where multiple service blocks under
one timestamp collapsed into a single merged entry. The regripper services
plugin emits ONE timestamp at the start of a Services-key group then lists
every service under that group separated only by blank lines.

Run-004 (2026-04-30) showed planted TermService and MaintenanceService
both falling into the same timestamp group as TDPIPE / Themes / Mozilla
and getting overwritten before flush.
"""
from __future__ import annotations

from pipeline.mcp.parsers import parse_regripper


_REGRIPPER_HEADER = """services v.20100927
(System) Lists services that have an ImagePath value.

Hive: /home/sansforensics/cases/test/analysis/extracted/SYSTEM
"""


def test_multi_block_one_timestamp_emits_all_services():
    """The minimal repro of the run-004 bug. Three services share one
    timestamp; the parser must emit all three, not just the last one."""
    text = _REGRIPPER_HEADER + """
ControlSet001\\Services [LastWrite]
Mon Apr 28 12:00:00 2025 Z
  Name      = TDPIPE
  Display   = TDPIPE
  ImagePath = system32\\drivers\\tdpipe.sys
  Type      = Kernel driver
  Start     = Manual
  Group     =

  Name      = TermService
  Display   = Remote Desktop Services
  ImagePath = C:\\ProgramData\\rdp_handler.exe
  Type      = Own_Process
  Start     = Auto Start
  Group     =

  Name      = Themes
  Display   = Themes
  ImagePath = svchost.exe -k netsvcs
  Type      = Share_Process
  Start     = Auto Start
  Group     = ProfSvc_Group
"""
    result, status = parse_regripper(text.encode("utf-8"), "services")
    assert status == "ok"
    names = [e.value_name for e in result.entries]
    assert "TDPIPE" in names, f"TDPIPE missing: {names}"
    assert "TermService" in names, f"TermService missing: {names}"
    assert "Themes" in names, f"Themes missing: {names}"


def test_planted_term_service_image_path_in_packed():
    """Verify the planted ImagePath survives the flush. Direct repro of
    the run-004 case: regripper saw the planted C:\\ProgramData\\rdp_handler.exe
    but the parser used to drop it via the merge-and-overwrite bug."""
    text = _REGRIPPER_HEADER + """
ControlSet001\\Services [LastWrite]
Mon Apr 28 12:00:00 2025 Z
  Name      = TermService
  Display   = Remote Desktop Services
  ImagePath = C:\\ProgramData\\rdp_handler.exe
  Type      = Own_Process
  Start     = Auto Start
  Group     =
"""
    result, status = parse_regripper(text.encode("utf-8"), "services")
    assert status == "ok"
    term = [e for e in result.entries if e.value_name == "TermService"]
    assert len(term) == 1, f"expected 1 TermService entry, got {len(term)}"
    assert "rdp_handler.exe" in term[0].value_data_safe


def test_single_block_with_timestamp_still_works():
    """Smoke test: the existing one-service-per-timestamp case still parses."""
    text = _REGRIPPER_HEADER + """
ControlSet001\\Services [LastWrite]
Mon Apr 28 12:00:00 2025 Z
  Name      = LoneService
  Display   = LoneService
  ImagePath = C:\\Windows\\lone.exe
  Type      = Own_Process
  Start     = Auto Start
  Group     =
"""
    result, status = parse_regripper(text.encode("utf-8"), "services")
    assert status == "ok"
    assert any(e.value_name == "LoneService" for e in result.entries)


def test_two_timestamp_groups_each_with_multiple_blocks():
    """Two timestamp groups, two services in each. All four must survive."""
    text = _REGRIPPER_HEADER + """
Mon Apr 28 12:00:00 2025 Z
  Name      = First
  ImagePath = C:\\a.exe

  Name      = Second
  ImagePath = C:\\b.exe

Tue Apr 29 13:00:00 2025 Z
  Name      = Third
  ImagePath = C:\\c.exe

  Name      = Fourth
  ImagePath = C:\\d.exe
"""
    result, status = parse_regripper(text.encode("utf-8"), "services")
    assert status == "ok"
    names = [e.value_name for e in result.entries]
    for expected in ("First", "Second", "Third", "Fourth"):
        assert expected in names, f"{expected} missing from {names}"
