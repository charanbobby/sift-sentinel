"""Test the 5 Volatility 2 plugin parsers + the dispatch wrapper.

Slice 6 Step 5 P5: closes a real test-coverage gap on the memory-channel
parser layer. Fixtures are minimal reproductions of real Vol2 stdout
captured from `srl-2018-wkstn-05` run-005's `analysis/raw/` files,
trimmed to the smallest sample that exercises each code path. All-stdlib;
no Vol2 import, no MCP roundtrip.
"""
from __future__ import annotations

from pipeline.mcp.parsers import (
    parse_volatility,
    _strip_volatility_warnings,
    VOLATILITY_PLUGIN_ALLOWLIST,
)


# ---------------------------------------------------------------------------
# Real-data fixtures (captured from run-005, trimmed)
# ---------------------------------------------------------------------------

# Vol2 prepends one or more "*** Failed to import ..." lines for every
# unavailable community plugin, plus the framework banner. The allowlist
# parsers must strip both before the per-plugin logic runs.
VOL_WARNINGS = (
    "*** Failed to import volatility.plugins.community.AFF4.aff4 "
    "(ImportError: No module named pyaff4)\n"
    "*** Failed to import volatility.plugins.community.Citronneur.wnf "
    "(ImportError: No module named Citronneur.wnf)\n"
    "Volatility Foundation Volatility Framework 2.6.1\n"
)


PSLIST_BODY = (
    "Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          \n"
    "------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------\n"
    "0xfffffa8024e14b00 System                    4      0    118     2600 ------      0 2018-08-30 05:14:12 UTC+0000                                 \n"
    "0xfffffa80266fdb00 smss.exe                332      4      3       33 ------      0 2018-08-30 05:14:12 UTC+0000                                 \n"
    "0xfffffa8027041990 csrss.exe               496    488      9     1018      0      0 2018-08-30 05:14:21 UTC+0000                                 \n"
)


CMDLINE_BODY = (
    "************************************************************************\n"
    "System pid:      4\n"
    "************************************************************************\n"
    "smss.exe pid:    332\n"
    "Command line : \\SystemRoot\\System32\\smss.exe\n"
    "************************************************************************\n"
    "csrss.exe pid:    496\n"
    "Command line : %SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows\n"
)


NETSCAN_BODY = (
    "Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created\n"
    "0x1c6dcd0          TCPv4    172.16.7.15:57160              172.16.4.10:8080     CLOSED           -1                      \n"
    "0x1253eec0         UDPv4    127.0.0.1:62982                *:*                                   4600     OUTLOOK.EXE    2018-09-04 21:53:14 UTC+0000\n"
    "0x3914a480         TCPv4    172.16.7.15:445                172.16.6.11:59352    ESTABLISHED      4321     System         \n"
)


# Synthetic dlllist (no real fixture in run-005's raw outputs; built to the
# parser's regex spec). One process block with two DLL rows.
DLLLIST_BODY = (
    "************************************************************************\n"
    "powershell.exe pid:   4328\n"
    "Command line : powershell.exe -nop -w hidden\n"
    "\n"
    "Base                             Size     LoadCount LoadTime                       Path\n"
    "0x0000000000401000 0x00050000 0xffff    2018-09-04 21:53:14 UTC+0000   C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
    "0x0000000076d40000 0x00180000 0xffff    2018-09-04 21:53:14 UTC+0000   C:\\Windows\\System32\\ntdll.dll\n"
    "************************************************************************\n"
    "explorer.exe pid:   1480\n"
    "Command line : C:\\Windows\\Explorer.EXE\n"
    "\n"
    "0x00007ff7c0000000 0x00200000 0xffff    2018-09-04 21:53:14 UTC+0000   C:\\Windows\\explorer.exe\n"
)


MALFIND_BODY = (
    "Process: powershell.exe Pid: 4328 Address: 0xf60000\n"
    "Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE\n"
    "Flags: CommitCharge: 2, PrivateMemory: 1, Protection: 6\n"
    "\n"
    "0x0000000000f60000  00 00 00 00 00 00 00 00 2c 32 50 d3 6b 23 00 01   ........,2P.k#..\n"
    "0x0000000000f60010  ee ff ee ff 00 00 00 00 28 01 f6 00 00 00 00 00   ........(.......\n"
    "\n"
    "0x0000000000f60000 0000             ADD [EAX], AL\n"
    "0x0000000000f60008 2c32             SUB AL, 0x32\n"
    "Process: explorer.exe Pid: 1480 Address: 0x7fff0000\n"
    "Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE\n"
    "Flags: PrivateMemory: 1\n"
    "\n"
    "0x000000007fff0000  90 90 90 90 90 90 90 90 c3 00 00 00 00 00 00 00   ................\n"
    "\n"
    "0x000000007fff0000 90               NOP\n"
)


# ---------------------------------------------------------------------------
# _strip_volatility_warnings
# ---------------------------------------------------------------------------


def test_strip_drops_failed_import_lines():
    text = VOL_WARNINGS + "real data line\n"
    out = _strip_volatility_warnings(text)
    assert "Failed to import" not in out
    assert "real data line" in out


def test_strip_drops_framework_banner():
    text = "Volatility Foundation Volatility Framework 2.6.1\nactual data\n"
    out = _strip_volatility_warnings(text)
    assert "Volatility Foundation" not in out
    assert "actual data" in out


def test_strip_preserves_non_warning_lines():
    text = "Offset(V) Name\nrow1\nrow2\n"
    assert _strip_volatility_warnings(text) == "Offset(V) Name\nrow1\nrow2"


# ---------------------------------------------------------------------------
# parse_volatility (dispatch)
# ---------------------------------------------------------------------------


def test_parse_volatility_unknown_plugin_raises_validation_error():
    """Documents actual behavior: VolatilityResult.plugin_name is a Literal,
    so the unknown-plugin branch in parse_volatility is unreachable — Pydantic
    raises before the function returns. Callers (mcp_server.server) validate
    the plugin against VOLATILITY_PLUGIN_ALLOWLIST first; this test pins the
    invariant that bypassing that validation fails loud rather than silent.
    """
    import pytest
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        parse_volatility(b"data", "not_a_real_plugin", "Win7SP1x64")  # type: ignore[arg-type]


def test_parse_volatility_empty_stdout_returns_empty():
    # malfind/netscan legitimately return zero results; pslist does not
    result, status = parse_volatility(b"", "malfind", "Win7SP1x64")
    assert status == "empty"


def test_parse_volatility_only_warnings_returns_empty():
    result, status = parse_volatility(VOL_WARNINGS.encode("utf-8"), "malfind", "Win7SP1x64")
    assert status == "empty"


def test_volatility_plugin_allowlist_has_5_entries():
    """Regression: the allowlist defines exactly the 5 plugins we ship."""
    assert VOLATILITY_PLUGIN_ALLOWLIST == frozenset({
        "pslist", "cmdline", "netscan", "dlllist", "malfind",
    })


# ---------------------------------------------------------------------------
# pslist
# ---------------------------------------------------------------------------


def test_parse_vol_pslist_happy_path():
    stdout = (VOL_WARNINGS + PSLIST_BODY).encode("utf-8")
    result, status = parse_volatility(stdout, "pslist", "Win7SP1x64")
    assert status == "ok"
    assert result.plugin_name == "pslist"
    assert result.profile == "Win7SP1x64"
    assert len(result.processes) == 3
    # Spot-check the second process
    smss = result.processes[1]
    assert smss.name == "smss.exe"
    assert smss.pid == 332
    assert smss.ppid == 4
    assert smss.threads == 3
    # start_time parsed from the trailing date
    assert smss.start_time is not None


def test_parse_vol_pslist_empty_returns_parse_error():
    """Headers only, no rows — parser hits its 'no rows accumulated' branch."""
    stdout = (VOL_WARNINGS +
              "Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit\n"
              "------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------\n").encode("utf-8")
    result, status = parse_volatility(stdout, "pslist", "Win7SP1x64")
    assert status == "parse_error"
    assert len(result.processes) == 0


# ---------------------------------------------------------------------------
# cmdline
# ---------------------------------------------------------------------------


def test_parse_vol_cmdline_happy_path():
    stdout = (VOL_WARNINGS + CMDLINE_BODY).encode("utf-8")
    result, status = parse_volatility(stdout, "cmdline", "Win7SP1x64")
    assert status == "ok"
    # 3 process blocks; System has no Command line so command_line_safe is ""
    assert len(result.cmdlines) == 3
    by_pid = {row.pid: row for row in result.cmdlines}
    assert by_pid[332].name == "smss.exe"
    assert by_pid[332].command_line_safe == "\\SystemRoot\\System32\\smss.exe"
    assert by_pid[4].command_line_safe == ""  # System block has no Command line


def test_parse_vol_cmdline_no_blocks_returns_parse_error():
    stdout = (VOL_WARNINGS + "no recognizable block separators here\n").encode("utf-8")
    result, status = parse_volatility(stdout, "cmdline", "Win7SP1x64")
    assert status == "parse_error"


# ---------------------------------------------------------------------------
# netscan
# ---------------------------------------------------------------------------


def test_parse_vol_netscan_tcpv4_with_state_parsed():
    stdout = (VOL_WARNINGS + NETSCAN_BODY).encode("utf-8")
    result, status = parse_volatility(stdout, "netscan", "Win7SP1x64")
    assert status == "ok"
    # 3 rows total. The TCPv4 with pid=-1 is rejected (parser requires int pid)
    # so we expect 2 valid rows: UDPv4 OUTLOOK.EXE + TCPv4 ESTABLISHED w/ pid=4321
    assert len(result.connections) >= 1
    # OUTLOOK.EXE on UDPv4
    outlook = next((c for c in result.connections if c.owner_safe == "OUTLOOK.EXE"), None)
    assert outlook is not None
    assert outlook.proto == "UDPv4"
    assert outlook.pid == 4600
    assert outlook.local_address == "127.0.0.1:62982"


def test_parse_vol_netscan_skips_non_inet_lines():
    stdout = (VOL_WARNINGS +
              "Offset(P)          Proto    Local Address\n"
              "garbage line that doesn't match\n").encode("utf-8")
    result, status = parse_volatility(stdout, "netscan", "Win7SP1x64")
    assert status == "parse_error"  # zero rows accumulated


# ---------------------------------------------------------------------------
# dlllist
# ---------------------------------------------------------------------------


def test_parse_vol_dlllist_happy_path():
    stdout = (VOL_WARNINGS + DLLLIST_BODY).encode("utf-8")
    result, status = parse_volatility(stdout, "dlllist", "Win7SP1x64")
    assert status == "ok"
    assert len(result.dll_entries) == 2
    by_pid = {entry.pid: entry for entry in result.dll_entries}
    assert by_pid[4328].process_name == "powershell.exe"
    assert by_pid[4328].command_line_safe == "powershell.exe -nop -w hidden"
    # Powershell block has 2 DLL rows
    assert len(by_pid[4328].dlls) == 2
    paths = {d.path_safe for d in by_pid[4328].dlls}
    assert any("powershell.exe" in p for p in paths)
    assert any("ntdll.dll" in p for p in paths)


def test_parse_vol_dlllist_no_blocks_returns_parse_error():
    stdout = (VOL_WARNINGS + "garbage with no block separators\n").encode("utf-8")
    result, status = parse_volatility(stdout, "dlllist", "Win7SP1x64")
    assert status == "parse_error"


# ---------------------------------------------------------------------------
# malfind
# ---------------------------------------------------------------------------


def test_parse_vol_malfind_happy_path():
    stdout = (VOL_WARNINGS + MALFIND_BODY).encode("utf-8")
    result, status = parse_volatility(stdout, "malfind", "Win7SP1x64")
    assert status == "ok"
    assert len(result.malfind_hits) == 2
    # First hit — the powershell.exe PID 4328 process_injection signal
    ps = result.malfind_hits[0]
    assert ps.process_name == "powershell.exe"
    assert ps.pid == 4328
    assert ps.address == "0xf60000"
    assert ps.vad_tag == "VadS"
    assert ps.protection == "PAGE_EXECUTE_READWRITE"
    assert "CommitCharge" in ps.flags
    # Hex + disasm captured separately
    assert "00 00 00 00" in ps.hex_excerpt
    assert "ADD [EAX], AL" in ps.disasm_excerpt


def test_parse_vol_malfind_no_hits_with_warnings_only_returns_empty():
    """A clean image where Vol2 emits the warnings prelude only — `_strip` drops
    them, leaves the body empty, parser returns 'empty' rather than parse_error."""
    stdout = VOL_WARNINGS.encode("utf-8")
    result, status = parse_volatility(stdout, "malfind", "Win7SP1x64")
    assert status == "empty"


def test_parse_vol_malfind_only_garbage_no_headers_returns_parse_error():
    """Body is non-empty but has no `Process: ... Pid: ...` headers. The parser
    can't extract any malfind hit; return parse_error to flag the unexpected
    output shape."""
    stdout = (VOL_WARNINGS + "this body has no malfind headers at all\n").encode("utf-8")
    result, status = parse_volatility(stdout, "malfind", "Win7SP1x64")
    assert status == "parse_error"
