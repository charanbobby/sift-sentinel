"""Unit tests for score.py matcher.

Run with: python3 -m pytest experiments/synthetic-ai-workstation/test_score.py
or, from this directory: pytest test_score.py

Covers the 2026-04-30 over-matching fix. Pre-fix, any locator substring match
counted as detection, so registry_run_key with value_data="1" matched anything
containing the digit "1" (run-002 false positive on medusa_wdigest_credential_cache).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# score.py lives next to this test file
sys.path.insert(0, str(Path(__file__).parent))
from score import find_artifact_in_findings, _artifact_match_locator


# ---- helpers ---------------------------------------------------------------


def _finding_blob(d: dict) -> str:
    """Findings are dicts; the matcher takes JSON-serialized strings."""
    return json.dumps(d)


# ---- _artifact_match_locator (per-type discriminator selection) -----------


def test_match_locator_run_key_uses_value_name():
    art = {
        "type": "registry_run_key",
        "key_path": "Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "SystemService",
        "value_data": "C:\\ProgramData\\system_svc.exe",
    }
    assert _artifact_match_locator(art) == "SystemService"


def test_match_locator_service_uses_service_name():
    art = {
        "type": "registry_service",
        "service_name": "SimpleHelpRemoteService",
        "service_image_path": "C:\\Program Files\\SimpleHelp\\simmgr.exe",
    }
    assert _artifact_match_locator(art) == "SimpleHelpRemoteService"


def test_match_locator_scheduled_task_uses_install_path():
    art = {
        "type": "scheduled_task_xml",
        "task_install_path": "Microsoft\\Windows\\MSBuildCheck",
    }
    assert _artifact_match_locator(art) == "Microsoft\\Windows\\MSBuildCheck"


def test_match_locator_file_drop_uses_file_path():
    art = {"type": "file_drop", "file_path": "inetpub/wwwroot/shell.aspx"}
    assert _artifact_match_locator(art) == "inetpub/wwwroot/shell.aspx"


def test_match_locator_unknown_type_returns_none():
    art = {"type": "registry_binary_value_v2_speculative"}
    assert _artifact_match_locator(art) is None


# ---- find_artifact_in_findings: regression cases for over-match bug -------


def test_over_match_wdigest_value_data_one_does_not_match_unrelated():
    """Pre-fix bug: medusa_wdigest_credential_cache had value_data='1'.
    Any finding containing the digit '1' was incorrectly marked detected.
    Fix: only the value_name discriminator is checked, and locators below
    _MIN_LOCATOR_LEN are rejected."""
    wdigest = {
        "type": "registry_run_key",
        "key_path": "CurrentControlSet\\Control\\SecurityProviders\\WDigest",
        "value_name": "UseLogonCredential",
        "value_data": "1",
    }
    unrelated_finding = _finding_blob({
        "category": "registry_run_key",
        "value": "C:\\ProgramData\\system_svc.exe",
        "evidence": [{"output_excerpt": "value_name: SystemService"}],
    })
    detected, _ = find_artifact_in_findings(wdigest, [unrelated_finding])
    assert detected is False, "wdigest must not over-match a system_svc finding"


def test_run_key_matches_when_value_name_present():
    art = {
        "type": "registry_run_key",
        "key_path": "Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "SystemService",
        "value_data": "C:\\ProgramData\\system_svc.exe",
    }
    finding = _finding_blob({
        "category": "registry_run_key",
        "evidence": [{"output_excerpt": "value_name: SystemService, value_data: ..."}],
    })
    detected, excerpt = find_artifact_in_findings(art, [finding])
    assert detected is True
    assert excerpt is not None and "SystemService" in excerpt


def test_run_key_misses_when_value_name_absent():
    art = {
        "type": "registry_run_key",
        "key_path": "Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "VeryUniqueArtifactName",
        "value_data": "C:\\Some\\Path",
    }
    # Finding mentions same key_path but different value_name; no match.
    finding = _finding_blob({
        "category": "registry_run_key",
        "evidence": [{"output_excerpt": "Microsoft\\Windows\\CurrentVersion\\Run other entry"}],
    })
    detected, _ = find_artifact_in_findings(art, [finding])
    assert detected is False


def test_short_locator_rejected_below_min_length():
    """value_name='Run' is shorter than 4 chars; matcher must refuse to
    pretend any finding containing 'Run' (most run_key findings) detected
    this artifact."""
    art = {
        "type": "registry_run_key",
        "key_path": "Microsoft\\Windows\\CurrentVersion\\Run",
        "value_name": "Run",
        "value_data": "C:\\evil.exe",
    }
    finding = _finding_blob({"category": "registry_run_key", "value": "anything Run-related"})
    detected, _ = find_artifact_in_findings(art, [finding])
    assert detected is False


# ---- file_drop slash-form bridging ----------------------------------------


def test_file_drop_forward_slash_matches_backslash_finding():
    """Manifest stores file_path with /; findings emit JSON-escaped Windows
    paths with \\. The matcher tries both forms."""
    art = {"type": "file_drop", "file_path": "inetpub/wwwroot/shell.aspx"}
    finding = _finding_blob({
        "value": "C:\\inetpub\\wwwroot\\shell.aspx",
    })
    detected, _ = find_artifact_in_findings(art, [finding])
    assert detected is True


def test_file_drop_misses_unrelated_path():
    art = {"type": "file_drop", "file_path": "inetpub/wwwroot/shell.aspx"}
    finding = _finding_blob({"value": "C:\\Users\\evil\\notes.txt"})
    detected, _ = find_artifact_in_findings(art, [finding])
    assert detected is False


# ---- service matching -----------------------------------------------------


def test_service_matches_on_service_name():
    art = {
        "type": "registry_service",
        "service_name": "SimpleHelpRemoteService",
        "service_image_path": "C:\\Program Files\\SimpleHelp\\simmgr.exe",
    }
    finding = _finding_blob({
        "category": "service",
        "evidence": [{"output_excerpt": "Services\\SimpleHelpRemoteService entry"}],
    })
    detected, _ = find_artifact_in_findings(art, [finding])
    assert detected is True


def test_service_misses_when_service_name_not_in_finding():
    """Run-002: the SimpleHelp service was never extracted by the pipeline,
    so no finding mentioned its service_name. Score must say MISS."""
    art = {
        "type": "registry_service",
        "service_name": "SimpleHelpRemoteService",
    }
    finding = _finding_blob({
        "category": "service",
        "value": "PerfMon masquerade running c:\\windows\\system32\\perfmonsvc64.exe",
    })
    detected, _ = find_artifact_in_findings(art, [finding])
    assert detected is False


# ---- run_loop.derive_baseline_detected ------------------------------------


def _mk_manifest_findings(tmp_path, baselines, findings):
    """Create temp manifest and findings JSON files; return their paths."""
    manifest = {
        "manifest_id": "2026-04-30",
        "base": {
            "case_id": "test",
            "raw_path": "x.raw",
            "expected_baseline_findings": baselines,
        },
        "categories": [],
    }
    m_path = tmp_path / "manifest.json"
    f_path = tmp_path / "findings.json"
    m_path.write_text(json.dumps(manifest))
    f_path.write_text(json.dumps({"findings": findings}))
    return m_path, f_path


def test_derive_baseline_detected_picks_discriminator(tmp_path):
    from run_loop import derive_baseline_detected

    m_path, f_path = _mk_manifest_findings(
        tmp_path,
        baselines=[
            {"id": "perfmon_masquerading", "category": "service", "description": ""},
            {"id": "tbbd05_named_pipe_beacon", "category": "service", "description": ""},
        ],
        findings=[
            {"value": "Service PerfMon runs perfmonsvc64.exe"},
            {"value": "Service tbbd05 echo to named pipe"},
        ],
    )
    assert derive_baseline_detected(m_path, f_path) == [
        "perfmon_masquerading", "tbbd05_named_pipe_beacon",
    ]


def test_derive_baseline_detected_misses_when_discriminator_absent(tmp_path):
    from run_loop import derive_baseline_detected

    m_path, f_path = _mk_manifest_findings(
        tmp_path,
        baselines=[{"id": "perfmon_masquerading", "category": "service", "description": ""}],
        findings=[{"value": "An unrelated finding about masquerading services"}],
    )
    # 'masquerading' is in the finding but it's not the discriminator;
    # 'perfmon' is the discriminator and it's NOT in the finding -> miss.
    assert derive_baseline_detected(m_path, f_path) == []


def test_derive_baseline_detected_handles_missing_files(tmp_path):
    from run_loop import derive_baseline_detected

    # Neither file exists; helper must not crash.
    m_path = tmp_path / "no_manifest.json"
    f_path = tmp_path / "no_findings.json"
    assert derive_baseline_detected(m_path, f_path) == []


# ---- research._file_path_is_windows_safe (path-shape gate) ----------------


def test_path_shape_accepts_inetpub_web_shell():
    from research import _file_path_is_windows_safe
    ok, _ = _file_path_is_windows_safe("inetpub/wwwroot/admin.aspx")
    assert ok is True


def test_path_shape_accepts_program_files_path():
    from research import _file_path_is_windows_safe
    ok, _ = _file_path_is_windows_safe("Program Files/PaperCut MF/server/webapps/ROOT/shell.jsp")
    assert ok is True


def test_path_shape_accepts_users_path_with_drive_letter():
    from research import _file_path_is_windows_safe
    ok, _ = _file_path_is_windows_safe("C:\\Users\\developer\\AppData\\Local\\Temp\\shell.aspx")
    assert ok is True


def test_path_shape_rejects_linux_root_opt():
    """Run-002: cisco_sdwan_exploitation_artifact at 'opt/cisco/sdwan/web/shell.jsp'
    is unbuildable on a Windows NTFS image."""
    from research import _file_path_is_windows_safe
    ok, reason = _file_path_is_windows_safe("opt/cisco/sdwan/web/shell.jsp")
    assert ok is False
    assert "windows root" in reason.lower()


def test_path_shape_rejects_path_traversal():
    """Run-002: screenconnect_auth_bypass_attempt with literal '..\\..\\..\\..\\Windows\\System32\\config\\SAM'
    cannot be planted; build phase resolves the relative segments."""
    from research import _file_path_is_windows_safe
    ok, reason = _file_path_is_windows_safe(
        "Program Files/ConnectWise/ScreenConnect/..\\..\\..\\..\\Windows\\System32\\config\\SAM"
    )
    assert ok is False
    assert "traversal" in reason.lower()


def test_path_shape_rejects_empty_path():
    from research import _file_path_is_windows_safe
    ok, reason = _file_path_is_windows_safe("")
    assert ok is False


def test_path_shape_rejects_etc_passwd_style():
    from research import _file_path_is_windows_safe
    ok, _ = _file_path_is_windows_safe("etc/passwd")
    assert ok is False
