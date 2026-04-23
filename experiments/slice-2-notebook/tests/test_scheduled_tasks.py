"""Test pipeline.mcp.parsers.parse_scheduled_tasks.

Minimal XML fixtures (valid / empty / malformed / unicode / missing-fields) per
Step 11 gate. The parser normalizes Windows Task Scheduler XML across UTF-16
LE/BE BOMs + UTF-8 + plain text.
"""
from __future__ import annotations

import pytest

from pipeline.mcp.parsers import parse_scheduled_tasks


# Valid Windows Task Scheduler XML (namespaced). Minimal but complete: has
# RegistrationInfo + Triggers + Actions so the parser extracts all fields.
VALID_TASK_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\\Microsoft\\Windows\\Maintenance\\WinSAT</URI>
    <Author>Microsoft Corporation</Author>
    <Description>Measures system performance.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Settings>
    <Enabled>true</Enabled>
  </Settings>
  <Actions>
    <Exec>
      <Command>C:\\Windows\\System32\\winsat.exe</Command>
      <Arguments>formal</Arguments>
    </Exec>
  </Actions>
</Task>
"""


MALFORMED_XML = b"<Task><not closed properly"

UNICODE_AUTHOR_XML = (
    b"""<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\\Test\\UnicodeAuthor</URI>
    <Author>"""
    + "ラダ Test".encode("utf-8")  # "ラダ Test" — Japanese
    + b"""</Author>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger/>
  </Triggers>
  <Actions>
    <Exec>
      <Command>C:\\Windows\\System32\\cmd.exe</Command>
    </Exec>
  </Actions>
</Task>
"""
)

MINIMAL_TASK_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions>
    <Exec>
      <Command>C:\\minimal.exe</Command>
    </Exec>
  </Actions>
</Task>
"""


# ---- Status codes ----------------------------------------------------------


def test_parse_valid_returns_ok_status():
    result, status = parse_scheduled_tasks(VALID_TASK_XML)
    assert status == "ok"
    assert len(result.tasks) == 1


def test_parse_empty_bytes_returns_empty_status():
    result, status = parse_scheduled_tasks(b"")
    assert status == "empty"
    assert result.tasks == []


def test_parse_malformed_returns_parse_error_status():
    result, status = parse_scheduled_tasks(MALFORMED_XML)
    assert status == "parse_error"
    assert result.tasks == []


# ---- Field extraction ------------------------------------------------------


def test_parse_valid_extracts_task_name_from_uri():
    result, _ = parse_scheduled_tasks(VALID_TASK_XML)
    assert result.tasks[0].task_name == "\\Microsoft\\Windows\\Maintenance\\WinSAT"


def test_parse_valid_extracts_author_and_description():
    result, _ = parse_scheduled_tasks(VALID_TASK_XML)
    task = result.tasks[0]
    assert task.author_safe == "Microsoft Corporation"
    assert task.description_safe == "Measures system performance."


def test_parse_valid_extracts_trigger_type():
    result, _ = parse_scheduled_tasks(VALID_TASK_XML)
    assert result.tasks[0].trigger_type == "LogonTrigger"


def test_parse_valid_extracts_action_command_and_arguments():
    result, _ = parse_scheduled_tasks(VALID_TASK_XML)
    task = result.tasks[0]
    assert task.action_command_safe == "C:\\Windows\\System32\\winsat.exe"
    assert task.action_arguments_safe == "formal"


def test_parse_valid_task_enabled_defaults_true():
    result, _ = parse_scheduled_tasks(VALID_TASK_XML)
    assert result.tasks[0].enabled is True


# ---- Missing / unusual fields ----------------------------------------------


def test_parse_minimal_task_populates_required_fields_with_defaults():
    """A task with only <Actions>/<Exec>/<Command> should still parse — author,
    description, arguments default to ''; trigger_type = 'Unknown'."""
    result, status = parse_scheduled_tasks(MINIMAL_TASK_XML)
    assert status == "ok"
    task = result.tasks[0]
    assert task.author_safe == ""
    assert task.description_safe == ""
    assert task.action_arguments_safe == ""
    assert task.trigger_type == "Unknown"
    assert task.action_command_safe == "C:\\minimal.exe"


# ---- UTF-16 LE with BOM (canonical Windows Task Scheduler encoding) --------


def test_parse_utf16_le_bom_xml_decodes_correctly():
    """Tasks on disk are UTF-16 LE with BOM. Parser must strip the BOM and the
    encoding='UTF-16' header before feeding to ElementTree."""
    utf16_xml = b"\xff\xfe" + VALID_TASK_XML.replace(
        b'encoding="UTF-8"', b'encoding="UTF-16"'
    ).decode("utf-8").encode("utf-16-le")
    result, status = parse_scheduled_tasks(utf16_xml)
    assert status == "ok"
    assert len(result.tasks) == 1
    assert result.tasks[0].task_name == "\\Microsoft\\Windows\\Maintenance\\WinSAT"


# ---- Unicode-bearing fields ------------------------------------------------


def test_parse_unicode_author_preserved_in_safe_field():
    """author_safe is free-text; unicode should round-trip through the parser."""
    result, status = parse_scheduled_tasks(UNICODE_AUTHOR_XML)
    assert status == "ok"
    assert result.tasks[0].author_safe == "ラダ Test"
