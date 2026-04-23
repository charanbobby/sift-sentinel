"""Per-tool stdout parsers — channel B of the dual-channel handler.

Takes raw subprocess bytes from `_run_and_record` and returns a typed Pydantic
model plus a `ToolExecutionStatus` ("ok" / "timeout" / "permission_denied" /
"parse_error" / "empty" / "capability_denied"). The structured model is what
the agent's INTERPRET node sees; raw bytes are persisted only to disk for the
Slice 6 integrity ledger, never to the LLM context.

Parser-status contract:
    ok              — fresh output, parsed shape populated
    empty           — zero bytes from subprocess (tool found nothing)
    parse_error     — non-empty output that didn't match the expected shape
                      (surfaces R_12 Evidence-of-Absence concerns to Critic)
    timeout / permission_denied — set by `_run_and_record` based on exit code,
                      parser still runs but typically returns an empty model
    capability_denied — set by `_enforce_capability` before subprocess runs;
                      parser is NOT called in that path

Free-text scanning: each parser exposes `free_text_fields(result)` returning
a list of `(field_path, text)` pairs for the injection scanner to consume.
Each parser owns its shape's scan surface — the server doesn't introspect.

Expected-paths-covered: each parser contributes a list of canonical paths it
actually examined. Used by R_06 Negative-Result-Metadata ("did we look?") —
without it a NOT_FOUND finding has no way to prove it wasn't laziness. For
RegRipper this is the per-plugin registry-key list (baked into this module);
for fls it's the directory enumerated; for fsstat it's the filesystem root.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from pipeline.schemas import (
    FlsEntry, FlsResult,
    FsstatResult,
    IcatResult,
    RegripperEntry, RegripperResult,
    ScheduledTaskEntry, ScheduledTasksResult,
)


# --- shared helpers -------------------------------------------------------

_NON_PRINTABLE = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]")


def _safe_filename(raw: str) -> str:
    """Sanitize a filename for channel-B exposure. Replaces non-printables
    (the adversarial-bytes class) with a literal sentinel so the LLM sees
    SOMETHING but not controlled bytes that could smuggle role markers or
    terminator sequences. Inode + size are preserved separately so PLAN can
    still chain a downstream icat call by inode."""
    return _NON_PRINTABLE.sub("<NON_PRINTABLE>", raw)


def _epoch_to_dt(s: str) -> datetime | None:
    try:
        ts = int(s)
    except (ValueError, TypeError):
        return None
    if ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


# --- fsstat ---------------------------------------------------------------

_FSSTAT_FS_TYPE = re.compile(r"^File System Type:\s*(.+)$", re.MULTILINE)
_FSSTAT_SERIAL = re.compile(r"^Volume Serial Number:\s*([0-9A-Fa-f]+)\s*$", re.MULTILINE)
_FSSTAT_MFT = re.compile(r"^First Cluster of MFT:\s*(\d+)\s*$", re.MULTILINE)
_FSSTAT_CLUSTER = re.compile(r"^Cluster Size:\s*(\d+)\s*$", re.MULTILINE)
# install_time for R_13 — fsstat doesn't surface it directly; we keep the hook
# but leave it None for NTFS. Extfs would have "Last Written at:" etc.


def parse_fsstat(stdout: bytes) -> tuple[FsstatResult, str]:
    if not stdout:
        return FsstatResult(fs_type="unknown", block_size=0), "empty"
    text = stdout.decode("utf-8", errors="replace")
    fs_match = _FSSTAT_FS_TYPE.search(text)
    if not fs_match:
        return FsstatResult(fs_type="unknown", block_size=0), "parse_error"

    cluster = _FSSTAT_CLUSTER.search(text)
    mft = _FSSTAT_MFT.search(text)
    serial = _FSSTAT_SERIAL.search(text)

    return FsstatResult(
        fs_type=fs_match.group(1).strip(),
        block_size=int(cluster.group(1)) if cluster else 0,
        mft_offset=int(mft.group(1)) if mft else None,
        volume_serial=serial.group(1) if serial else None,
        partition_count=1,
        install_time=None,
    ), "ok"


def fsstat_free_text_fields(r: FsstatResult) -> list[tuple[str, str]]:
    # fs_type / volume_serial are tightly structured; no free-text surface.
    return []


# --- fls (mactime bodyfile) ----------------------------------------------
#
# Format:  MD5|path|inode|mode_str|UID|GID|size|atime|mtime|ctime|crtime
#
# MD5 is 0 for fls -m (no hashing). `inode` can be NTFS-style
# meta-attrtype-attrid (e.g. "21562-48-2"); we take the meta_addr
# (first integer). mode_str[0] indicates file type: 'd'=dir, 'r'=file,
# 'l'=symlink, others → "other".

_FLS_TYPE_MAP = {"d": "directory", "r": "file", "l": "symlink"}


def parse_fls(stdout: bytes) -> tuple[FlsResult, str]:
    if not stdout:
        return FlsResult(entries=[]), "empty"
    text = stdout.decode("utf-8", errors="replace")
    entries: list[FlsEntry] = []
    parse_errors = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) != 11:
            parse_errors += 1
            continue
        try:
            path = parts[1]
            inode_str = parts[2]
            # Meta_addr is the first integer in inode_str
            inode_match = re.match(r"(\d+)", inode_str)
            if not inode_match:
                parse_errors += 1
                continue
            inode = int(inode_match.group(1))
            mode_str = parts[3]
            type_char = mode_str[0] if mode_str else "-"
            entry_type = _FLS_TYPE_MAP.get(type_char, "other")
            size = int(parts[6]) if parts[6].isdigit() else 0
            atime = _epoch_to_dt(parts[7])
            mtime = _epoch_to_dt(parts[8])
            ctime = _epoch_to_dt(parts[9])
            crtime = _epoch_to_dt(parts[10])
            # Basename; path may end with "($FILE_NAME)" NTFS attribute marker —
            # keep it visible, it's an inode-type signal PLAN may care about.
            basename = path.rsplit("/", 1)[-1] if "/" in path else path
            filename_safe = _safe_filename(basename)
            entries.append(FlsEntry(
                inode=inode, entry_type=entry_type, size=size,
                mtime=mtime, atime=atime, ctime=ctime, crtime=crtime,
                filename_safe=filename_safe,
            ))
        except (ValueError, IndexError):
            parse_errors += 1
            continue

    if not entries and parse_errors:
        return FlsResult(entries=[]), "parse_error"
    return FlsResult(entries=entries), "ok"


def fls_free_text_fields(r: FlsResult) -> list[tuple[str, str]]:
    return [(f"entries[{i}].filename_safe", e.filename_safe)
            for i, e in enumerate(r.entries)]


# --- icat (binary extraction; metadata only) -----------------------------
#
# icat writes the bytes to a dest file via `stdout_target` in _run_and_record.
# The parser receives (bytes_written, sha256, dest_path) — not stdout. There
# is no text to parse, only a small metadata envelope to report to the LLM.


def parse_icat(
    *, bytes_written: int, sha256: str, dest_path: str, magic_peek: bytes,
) -> tuple[IcatResult, str]:
    if bytes_written == 0:
        return IcatResult(
            dest_path=dest_path, bytes_written=0, sha256=sha256,
            magic_bytes="",
        ), "empty"
    magic_hex = magic_peek[:16].hex()
    return IcatResult(
        dest_path=dest_path, bytes_written=bytes_written,
        sha256=sha256, magic_bytes=magic_hex,
    ), "ok"


def icat_free_text_fields(r: IcatResult) -> list[tuple[str, str]]:
    # dest_path is server-controlled; magic_bytes is hex. No free-text scan surface.
    return []


# --- regripper per-plugin dispatch ---------------------------------------
#
# rip.pl outputs a "Launching <plugin>" banner + the plugin's body. Bodies
# vary: most persistence plugins emit key-path lines + indented value lines
# with either " - " or " : " between name and data; a "LastWrite Time" line
# per key. This parser tolerates both separators and attaches the most recent
# LastWrite to each entry under that key.

_RIP_HIVE_FROM_HEADER = re.compile(r"\((Software|System|NTUSER\.DAT)[^)]*\)", re.IGNORECASE)
_RIP_LASTWRITE = re.compile(r"^LastWrite Time\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})Z?\s*$")
_RIP_INDENTED_VAL = re.compile(r"^\s+([^\s].*?)\s+[-:]\s+(.*)$")
_RIP_KEY_PATH = re.compile(r"^([A-Z][A-Za-z0-9_]*\\[^\s].*)$")  # starts with capital + contains \


def _rip_parse_lastwrite(s: str) -> datetime | None:
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_regripper(stdout: bytes, plugin: str) -> tuple[RegripperResult, str]:
    if not stdout:
        return RegripperResult(plugin_name=plugin, hive_type="unknown", entries=[]), "empty"
    text = stdout.decode("utf-8", errors="replace")

    hive_match = _RIP_HIVE_FROM_HEADER.search(text)
    hive_type = hive_match.group(1) if hive_match else "unknown"

    entries: list[RegripperEntry] = []
    current_key: str | None = None
    current_lastwrite: datetime | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        # LastWrite marker for the most-recent key
        lw = _RIP_LASTWRITE.match(line)
        if lw:
            current_lastwrite = _rip_parse_lastwrite(lw.group(1))
            continue
        # Key path (unindented, contains backslash)
        if not line.startswith(" ") and _RIP_KEY_PATH.match(line):
            # Skip "X has no subkeys." / "X has no values." / "X not found." noise
            if " has no " in line or " not found." in line:
                current_key = None
                continue
            current_key = line.strip()
            continue
        # Indented name-value pair
        val = _RIP_INDENTED_VAL.match(raw_line)
        if val and current_key:
            name = val.group(1).strip()
            data = val.group(2).strip()
            entries.append(RegripperEntry(
                key_path=current_key,
                value_name=_safe_filename(name),
                value_type="unknown",  # rip.pl doesn't emit REG_SZ / REG_DWORD markers in most plugins
                value_data_safe=_safe_filename(data),
                last_write=current_lastwrite,
            ))

    # Some plugins emit data without values — e.g. `services` plugin enumerates
    # entire keys with sub-values. A non-empty stdout that produced zero entries
    # is a "parse_error" signal ONLY when the plugin is one we expected to yield
    # structured output. For now: non-empty → at least one entry OR parse_error.
    if not entries:
        # Did the plugin finish cleanly with nothing to report? Regripper's
        # idiom for that is "<key> has no values" or "... not found." — if we
        # saw key mentions at all, it's a legitimate empty-result, not parse_error.
        if re.search(r"has no (values|subkeys)|not found", text):
            return RegripperResult(plugin_name=plugin, hive_type=hive_type, entries=[]), "ok"
        return RegripperResult(plugin_name=plugin, hive_type=hive_type, entries=[]), "parse_error"

    return RegripperResult(plugin_name=plugin, hive_type=hive_type, entries=entries), "ok"


# --- RegRipper per-plugin expected-paths-covered -------------------------
# Canonical registry paths each plugin examines. Feeds R_06
# Negative-Result-Metadata: a NOT_FOUND@high finding about persistence can
# ONLY be credible if it covers all the paths an attacker might have used.
# Paths use single-backslash form (what RegRipper emits) — NOT the double-
# backslash form used in Python string literals elsewhere.

REGRIPPER_EXPECTED_PATHS: dict[str, list[str]] = {
    "run": [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ],
    "runonceex": [
        r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    ],
    "services": [
        r"System\CurrentControlSet\Services",
    ],
    "schedagent": [
        r"Software\Microsoft\SchedulingAgent",
    ],
    "appinitdlls": [
        r"Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
        r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
    ],
    "imagefile": [
        r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    ],
    "winlogon_tln": [
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ],
}


def regripper_expected_paths(plugin: str) -> list[str]:
    return list(REGRIPPER_EXPECTED_PATHS.get(plugin, []))


def regripper_free_text_fields(r: RegripperResult) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for i, e in enumerate(r.entries):
        # key_path is structurally constrained but could still carry smuggled
        # unicode — scan it. value_name + value_data_safe are the main surfaces.
        out.append((f"entries[{i}].key_path", e.key_path))
        out.append((f"entries[{i}].value_name", e.value_name))
        out.append((f"entries[{i}].value_data_safe", e.value_data_safe))
    return out


# --- scheduled_tasks_parse (5th MCP tool, Step 4a deferred to here) ------
#
# Windows Task XML schema is ~xsd:
#   /Task
#     /RegistrationInfo
#       /Author, /Description
#     /Triggers
#       /LogonTrigger, /TimeTrigger, /BootTrigger, ...
#     /Actions
#       /Exec
#         /Command, /Arguments

_TASK_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


def _task_text(el: ET.Element | None, tag: str) -> str:
    if el is None:
        return ""
    found = el.find(f"{_TASK_NS}{tag}")
    if found is None:
        found = el.find(tag)
    return (found.text or "").strip() if found is not None else ""


def _trigger_type(triggers: ET.Element | None) -> str:
    if triggers is None:
        return "Unknown"
    for child in triggers:
        # Namespaced tag like "{...}LogonTrigger"; keep just the local name
        tag = child.tag.split("}", 1)[-1]
        if tag.endswith("Trigger"):
            return tag
    return "Unknown"


def parse_scheduled_tasks(xml_bytes: bytes) -> tuple[ScheduledTasksResult, str]:
    if not xml_bytes:
        return ScheduledTasksResult(tasks=[]), "empty"
    try:
        # Windows Task XML on disk is UTF-16 LE with a BOM; ET enforces the
        # declared-encoding vs actual-bytes match, so we decode to str first
        # and strip the `<?xml ... encoding="UTF-16"?>` header before parsing.
        if xml_bytes[:2] == b"\xff\xfe":
            text = xml_bytes.decode("utf-16-le", errors="replace")
        elif xml_bytes[:2] == b"\xfe\xff":
            text = xml_bytes.decode("utf-16-be", errors="replace")
        elif xml_bytes[:3] == b"\xef\xbb\xbf":
            text = xml_bytes[3:].decode("utf-8", errors="replace")
        else:
            text = xml_bytes.decode("utf-8", errors="replace")
        text = re.sub(r"^\s*<\?xml[^?]*\?>\s*", "", text, count=1)
        root = ET.fromstring(text)
    except (ET.ParseError, UnicodeDecodeError):
        return ScheduledTasksResult(tasks=[]), "parse_error"

    tasks: list[ScheduledTaskEntry] = []
    # A single file holds one <Task>; we still iterate to tolerate multi-task
    # XML files if a derivative tool produces them.
    for task_el in [root] if root.tag.endswith("Task") else root.iter(f"{_TASK_NS}Task"):
        reg_info = task_el.find(f"{_TASK_NS}RegistrationInfo")
        triggers = task_el.find(f"{_TASK_NS}Triggers")
        actions = task_el.find(f"{_TASK_NS}Actions")
        settings = task_el.find(f"{_TASK_NS}Settings")
        exec_el = actions.find(f"{_TASK_NS}Exec") if actions is not None else None

        # task_name: prefer <URI>, else <TaskName>
        task_name = _task_text(reg_info, "URI") or _task_text(reg_info, "TaskName") or "<unknown>"

        enabled_s = _task_text(settings, "Enabled")
        enabled = enabled_s.lower() != "false" if enabled_s else True

        tasks.append(ScheduledTaskEntry(
            task_name=_safe_filename(task_name),
            author_safe=_safe_filename(_task_text(reg_info, "Author")),
            description_safe=_safe_filename(_task_text(reg_info, "Description")),
            trigger_type=_trigger_type(triggers),
            action_command_safe=_safe_filename(_task_text(exec_el, "Command")),
            action_arguments_safe=_safe_filename(_task_text(exec_el, "Arguments")),
            enabled=enabled,
        ))

    if not tasks:
        return ScheduledTasksResult(tasks=[]), "parse_error"
    return ScheduledTasksResult(tasks=tasks), "ok"


def scheduled_tasks_free_text_fields(r: ScheduledTasksResult) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for i, t in enumerate(r.tasks):
        for fname in ("task_name", "author_safe", "description_safe",
                      "action_command_safe", "action_arguments_safe"):
            val = getattr(t, fname, "")
            if val:
                out.append((f"tasks[{i}].{fname}", val))
    return out


__all__ = [
    "parse_fsstat", "fsstat_free_text_fields",
    "parse_fls", "fls_free_text_fields",
    "parse_icat", "icat_free_text_fields",
    "parse_regripper", "regripper_free_text_fields",
    "regripper_expected_paths", "REGRIPPER_EXPECTED_PATHS",
    "parse_scheduled_tasks", "scheduled_tasks_free_text_fields",
]
