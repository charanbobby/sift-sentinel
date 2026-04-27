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
    VolatilityCmdlineEntry, VolatilityDll, VolatilityDllEntry,
    VolatilityMalfindEntry, VolatilityNetworkEntry, VolatilityProcessEntry,
    VolatilityResult,
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
    # 2026-04-27: empty stdout is parse_error, not empty. fsstat always prints
    # filesystem metadata on success (FS Type, Cluster Size, MFT location).
    # Silent stdout means the tool crashed or could not read the image.
    # Same pattern as the regripper fix — see docs/submission/known-limitations.md.
    if not stdout:
        return FsstatResult(fs_type="unknown", block_size=0), "parse_error"
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
# fall into two shapes:
#
#   (a) Generic key-value (most plugins: run, runonceex, imagefile,
#       appinitdlls, winlogon_tln, schedagent, ntuser-scoped Run):
#           Software\Microsoft\Windows\CurrentVersion\Run
#           LastWrite Time 2018-05-11 19:17:16Z
#             VMware User Process - "C:\Program Files\VMware\..."
#             AppInit_DLLs : {blank}
#             OldName      = 37L4247E29-32
#       Separator between name + value is one of `-`, `:`, or `=` with
#       whitespace on both sides. The generic parser handles all three.
#
#   (b) services plugin — irregular block format. Each service is a
#       timestamp-delimited block of 6 named fields using `=` separator:
#           Fri Sep  7 03:05:11 2018 Z
#             Name      = BITS
#             Display   = @%SystemRoot%\system32\qmgr.dll,-1000
#             ImagePath = %SystemRoot%\System32\svchost.exe -k netsvcs
#             Type      = Share_Process
#             Start     = Auto Start
#             Group     = <blank>
#       The generic parser would produce ~6 scattered field-entries per
#       service without any way for the LLM to correlate them. The
#       services-specific path flattens each block into ONE RegripperEntry
#       per service, keyed by service Name, with Display / ImagePath /
#       Type / Start / Group packed into value_data_safe. last_write is
#       the block's timestamp.

_RIP_HIVE_FROM_HEADER = re.compile(r"\((Software|System|NTUSER\.DAT)[^)]*\)", re.IGNORECASE)
_RIP_LASTWRITE = re.compile(r"^LastWrite Time\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})Z?\s*$")
# `-`, `:`, and `=` are all accepted as name/value separators. `=` was added
# at Slice 5 post-7c after the services + schedagent plugins were found to
# drop nearly all entries — those plugins emit `Name = value`, not `Name - value`.
# Leading whitespace is optional (`\s*` not `\s+`) because schedagent emits
# field lines at column 0 while run / appinitdlls emit them indented. Key-path
# ambiguity is avoided by the separate key_path branch (requires a backslash
# in the name, which value-names never have).
_RIP_INDENTED_VAL = re.compile(r"^\s*([^\s].*?)\s+[-:=]\s+(.*)$")
_RIP_KEY_PATH = re.compile(r"^([A-Z][A-Za-z0-9_]*\\[^\s].*)$")  # starts with capital + contains \
_DAYS = frozenset({"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"})


def _rip_parse_lastwrite(s: str) -> datetime | None:
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _parse_services_timestamp(line: str) -> datetime | None:
    """Parse a regripper services-plugin block header like
    'Fri Sep  7 03:05:11 2018 Z' into a UTC datetime. Returns None on any
    shape mismatch (the caller uses None to signal 'this isn't a timestamp
    line')."""
    parts = line.strip().split()
    # Expected: [Day, Mon, DD, HH:MM:SS, YYYY, Z]  (6 tokens)
    if len(parts) != 6 or parts[0] not in _DAYS or parts[5] != "Z":
        return None
    try:
        return datetime.strptime(
            f"{parts[1]} {parts[2]} {parts[3]} {parts[4]}",
            "%b %d %H:%M:%S %Y",
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# Services-plugin field line: `  Name      = value` (any whitespace before name,
# whitespace around `=`, value may be empty/whitespace). `=` is the ONLY
# separator regripper uses for services; see plugin output format.
_RIP_SERVICES_FIELD = re.compile(r"^\s+([A-Z][A-Za-z0-9_]*)\s*=\s*(.*)$")

# Field order packed into value_data_safe for each service. Name is the entry's
# value_name so it's lifted out; the rest are packed stably.
_SERVICES_PACK_ORDER = ("Display", "ImagePath", "Type", "Start", "Group")


def _parse_services_plugin(text: str) -> list[RegripperEntry]:
    """Custom parser for the regripper `services` plugin. One RegripperEntry
    per service block; fields packed into value_data_safe so the LLM sees
    all forensically-relevant columns for a service in one place (Name +
    ImagePath are what flag attacker services like tbbd05 or a masquerading
    PerfMon)."""
    entries: list[RegripperEntry] = []
    current_block: dict[str, str] = {}
    current_ts: datetime | None = None

    def _flush() -> None:
        name = current_block.get("Name", "").strip()
        if not name:
            return
        parts = []
        for field in _SERVICES_PACK_ORDER:
            v = current_block.get(field, "")
            if v:  # skip empty Display / Group
                parts.append(f"{field}={v}")
        packed = " | ".join(parts)
        entries.append(RegripperEntry(
            key_path=f"ControlSet001\\Services\\{_safe_filename(name)}",
            value_name=_safe_filename(name),
            value_type="unknown",
            value_data_safe=_safe_filename(packed),
            last_write=current_ts,
        ))

    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        # Block header (timestamp)?
        ts = _parse_services_timestamp(raw_line)
        if ts is not None:
            _flush()
            current_block = {}
            current_ts = ts
            continue
        # Field line inside a block?
        m = _RIP_SERVICES_FIELD.match(raw_line)
        if m:
            current_block[m.group(1)] = m.group(2).strip()

    _flush()  # final block
    return entries


def parse_regripper(stdout: bytes, plugin: str) -> tuple[RegripperResult, str]:
    # 2026-04-27: empty stdout is parse_error, not empty. rip.pl always prints
    # at least its plugin banner on a successful invocation, so silent stdout
    # means the plugin crashed, rip.pl was not on PATH, or the hive was
    # unreadable. Critic R_06 / R_12 must see those as failures, not as
    # "legitimate evidence of absence." Caught 6/6 demo runs where winlogon_tln
    # against the SOFTWARE hive was silently producing no output.
    # See docs/submission/known-limitations.md for the full incident.
    if not stdout:
        return RegripperResult(plugin_name=plugin, hive_type="unknown", entries=[]), "parse_error"
    text = stdout.decode("utf-8", errors="replace")

    hive_match = _RIP_HIVE_FROM_HEADER.search(text)
    hive_type = hive_match.group(1) if hive_match else "unknown"

    # services plugin — use the block-format parser (see header comment).
    if plugin == "services":
        entries = _parse_services_plugin(text)
        if not entries:
            if re.search(r"has no (values|subkeys)|not found", text):
                return RegripperResult(plugin_name=plugin, hive_type=hive_type, entries=[]), "ok"
            return RegripperResult(plugin_name=plugin, hive_type=hive_type, entries=[]), "parse_error"
        return RegripperResult(plugin_name=plugin, hive_type=hive_type, entries=entries), "ok"

    # Generic key-value parser for every other plugin.
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
        # Indented name-value pair (`-`, `:`, or `=` separator)
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

    # Non-empty stdout with zero structured entries: either the plugin ran
    # cleanly with nothing to report ("has no values" / "not found") or the
    # parser genuinely missed the format. The status signal lets Critic's
    # R_09 distinguish the two.
    if not entries:
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


# --- Volatility 2 (memory-evidence) parsers --------------------------------
# Slice 6 Step 3b.6. Per-plugin output of `vol.py -f <img> --profile=<P> <plugin>`.
# 5-plugin allowlist: pslist, cmdline, netscan, dlllist, malfind.
# Vol2 wraps each run with import-failure warnings for community plugins we
# don't have; `_strip_volatility_warnings` drops those before parsing.

VOLATILITY_PLUGIN_ALLOWLIST: frozenset[str] = frozenset({
    "pslist", "cmdline", "netscan", "dlllist", "malfind",
})

_VOL_DT_FMT = "%Y-%m-%d %H:%M:%S"
_VOL_DT_RE = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
_VOL_BLOCK_SEP = re.compile(r"^\*{60,}\s*$", re.MULTILINE)
_VOL_PROC_HEADER = re.compile(r"^(\S+)\s+pid:\s+(\d+)\s*$", re.MULTILINE)
_VOL_DLL_ROW = re.compile(
    r"^(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+"
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s+\S+)\s+(.+)$"
)
_VOL_MALFIND_HEADER = re.compile(
    r"^Process:\s+(\S+)\s+Pid:\s+(\d+)\s+Address:\s+(0x[0-9a-fA-F]+)\s*$",
    re.MULTILINE,
)


def _vol_parse_dt(s: str) -> datetime | None:
    if not s:
        return None
    m = _VOL_DT_RE.search(s)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), _VOL_DT_FMT)
    except ValueError:
        return None


def _strip_volatility_warnings(text: str) -> str:
    out = []
    for line in text.splitlines():
        if line.startswith("*** Failed to import"):
            continue
        if line.startswith("Volatility Foundation Volatility Framework"):
            continue
        out.append(line)
    return "\n".join(out)


def _parse_vol_pslist(text: str, profile: str) -> tuple[VolatilityResult, str]:
    rows: list[VolatilityProcessEntry] = []
    in_data = False
    for ln in text.splitlines():
        if not ln.strip():
            continue
        if ln.startswith("Offset(V)"):
            continue
        if ln.startswith("--"):
            in_data = True
            continue
        if not in_data:
            continue
        parts = ln.split()
        if len(parts) < 8:
            continue
        try:
            dts = _VOL_DT_RE.findall(" ".join(parts[8:]))
            rows.append(VolatilityProcessEntry(
                offset_v=parts[0], name=parts[1],
                pid=int(parts[2]), ppid=int(parts[3]),
                threads=int(parts[4]), handles=int(parts[5]),
                session=parts[6], wow64=int(parts[7]),
                start_time=_vol_parse_dt(dts[0]) if len(dts) >= 1 else None,
                exit_time=_vol_parse_dt(dts[1]) if len(dts) >= 2 else None,
            ))
        except (ValueError, IndexError):
            continue
    if not rows:
        return VolatilityResult(plugin_name="pslist", profile=profile), "parse_error"
    return VolatilityResult(plugin_name="pslist", profile=profile, processes=rows), "ok"


def _parse_vol_cmdline(text: str, profile: str) -> tuple[VolatilityResult, str]:
    rows: list[VolatilityCmdlineEntry] = []
    for blk in _VOL_BLOCK_SEP.split(text):
        blk = blk.strip()
        if not blk:
            continue
        hdr = _VOL_PROC_HEADER.search(blk)
        if not hdr:
            continue
        cmd_match = re.search(r"^Command line\s*:\s*(.*)$", blk, re.MULTILINE)
        cmd = cmd_match.group(1).strip() if cmd_match else ""
        rows.append(VolatilityCmdlineEntry(
            name=hdr.group(1), pid=int(hdr.group(2)),
            command_line_safe=cmd[:4000],
        ))
    if not rows:
        return VolatilityResult(plugin_name="cmdline", profile=profile), "parse_error"
    return VolatilityResult(plugin_name="cmdline", profile=profile, cmdlines=rows), "ok"


def _parse_vol_netscan(text: str, profile: str) -> tuple[VolatilityResult, str]:
    rows: list[VolatilityNetworkEntry] = []
    for ln in text.splitlines():
        if not ln.strip():
            continue
        if ln.startswith("Offset(P)"):
            continue
        parts = ln.split()
        if len(parts) < 6:
            continue
        proto = parts[1] if len(parts) > 1 else ""
        if proto not in ("TCPv4", "TCPv6", "UDPv4", "UDPv6"):
            continue
        try:
            idx = 4
            state = ""
            if proto.startswith("TCP"):
                state = parts[idx]
                idx += 1
            try:
                pid = int(parts[idx])
            except ValueError:
                continue
            idx += 1
            owner = parts[idx] if idx < len(parts) else ""
            idx += 1
            rows.append(VolatilityNetworkEntry(
                offset_p=parts[0], proto=proto,  # type: ignore[arg-type]
                local_address=parts[2], foreign_address=parts[3],
                state=state, pid=pid, owner_safe=owner,
                created=_vol_parse_dt(" ".join(parts[idx:])),
            ))
        except (ValueError, IndexError):
            continue
    if not rows:
        return VolatilityResult(plugin_name="netscan", profile=profile), "parse_error"
    return VolatilityResult(plugin_name="netscan", profile=profile, connections=rows), "ok"


def _parse_vol_dlllist(text: str, profile: str) -> tuple[VolatilityResult, str]:
    rows: list[VolatilityDllEntry] = []
    for blk in _VOL_BLOCK_SEP.split(text):
        blk = blk.strip()
        if not blk:
            continue
        hdr = _VOL_PROC_HEADER.search(blk)
        if not hdr:
            continue
        cmd_match = re.search(r"^Command line\s*:\s*(.*)$", blk, re.MULTILINE)
        cmd = cmd_match.group(1).strip() if cmd_match else ""
        dlls: list[VolatilityDll] = []
        for ln in blk.splitlines():
            m = _VOL_DLL_ROW.match(ln)
            if m:
                dlls.append(VolatilityDll(
                    base=m.group(1), size=m.group(2),
                    load_count=m.group(3),
                    load_time=_vol_parse_dt(m.group(4)),
                    path_safe=m.group(5).strip()[:512],
                ))
        rows.append(VolatilityDllEntry(
            process_name=hdr.group(1), pid=int(hdr.group(2)),
            command_line_safe=cmd[:4000], dlls=dlls,
        ))
    if not rows:
        return VolatilityResult(plugin_name="dlllist", profile=profile), "parse_error"
    return VolatilityResult(plugin_name="dlllist", profile=profile, dll_entries=rows), "ok"


def _parse_vol_malfind(text: str, profile: str) -> tuple[VolatilityResult, str]:
    headers = list(_VOL_MALFIND_HEADER.finditer(text))
    if not headers:
        if not text.strip():
            return VolatilityResult(plugin_name="malfind", profile=profile), "empty"
        return VolatilityResult(plugin_name="malfind", profile=profile), "parse_error"
    rows: list[VolatilityMalfindEntry] = []
    for i, h in enumerate(headers):
        start = h.start()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        blk = text[start:end]
        vad_match = re.search(r"^Vad Tag:\s+(\S+)\s+Protection:\s+(.+)$", blk, re.MULTILINE)
        flags_match = re.search(r"^Flags:\s+(.+)$", blk, re.MULTILINE)
        hex_lines: list[str] = []
        disasm_lines: list[str] = []
        for ln in blk.splitlines():
            if re.match(r"^0x[0-9a-fA-F]+\s+(?:[0-9a-fA-F]{2}\s+){4,}", ln):
                hex_lines.append(ln)
            elif re.match(r"^0x[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+[A-Z]+", ln):
                disasm_lines.append(ln)
        rows.append(VolatilityMalfindEntry(
            process_name=h.group(1), pid=int(h.group(2)), address=h.group(3),
            vad_tag=vad_match.group(1) if vad_match else "",
            protection=(vad_match.group(2).strip() if vad_match else "")[:64],
            flags=(flags_match.group(1).strip() if flags_match else "")[:128],
            hex_excerpt="\n".join(hex_lines)[:2000],
            disasm_excerpt="\n".join(disasm_lines)[:2000],
        ))
    return VolatilityResult(plugin_name="malfind", profile=profile, malfind_hits=rows), "ok"


_VOL_DISPATCH = {
    "pslist": _parse_vol_pslist,
    "cmdline": _parse_vol_cmdline,
    "netscan": _parse_vol_netscan,
    "dlllist": _parse_vol_dlllist,
    "malfind": _parse_vol_malfind,
}

# 2026-04-27: per-plugin classification of "what does empty stdout mean."
# pslist / cmdline / dlllist always print on success against any real memory
# dump (System process always exists, every process has DLLs loaded). Silent
# stdout from those means the tool crashed.
# malfind / netscan can legitimately produce zero rows (clean host with no
# shellcode / no open sockets). For those, empty stays empty.
_VOL_EMPTY_LEGITIMATE = {"malfind", "netscan"}


def parse_volatility(stdout: bytes, plugin: str, profile: str) -> tuple[VolatilityResult, str]:
    if plugin not in _VOL_DISPATCH:
        return VolatilityResult(plugin_name=plugin, profile=profile), "parse_error"  # type: ignore[arg-type]
    if not stdout:
        status = "empty" if plugin in _VOL_EMPTY_LEGITIMATE else "parse_error"
        return VolatilityResult(plugin_name=plugin, profile=profile), status  # type: ignore[arg-type]
    text = _strip_volatility_warnings(stdout.decode("utf-8", errors="replace"))
    if not text.strip():
        status = "empty" if plugin in _VOL_EMPTY_LEGITIMATE else "parse_error"
        return VolatilityResult(plugin_name=plugin, profile=profile), status  # type: ignore[arg-type]
    return _VOL_DISPATCH[plugin](text, profile)


def volatility_free_text_fields(r: VolatilityResult) -> list[tuple[str, str]]:
    """Surface fields the injection scanner should examine. Hex/disasm excerpts
    are excluded — they're not natural-language attack surface."""
    out: list[tuple[str, str]] = []
    for i, p in enumerate(r.processes):
        if p.name:
            out.append((f"processes[{i}].name", p.name))
    for i, c in enumerate(r.cmdlines):
        if c.command_line_safe:
            out.append((f"cmdlines[{i}].command_line_safe", c.command_line_safe))
    for i, n in enumerate(r.connections):
        if n.owner_safe:
            out.append((f"connections[{i}].owner_safe", n.owner_safe))
    for i, d in enumerate(r.dll_entries):
        if d.command_line_safe:
            out.append((f"dll_entries[{i}].command_line_safe", d.command_line_safe))
        for j, dll in enumerate(d.dlls):
            if dll.path_safe:
                out.append((f"dll_entries[{i}].dlls[{j}].path_safe", dll.path_safe))
    for i, m in enumerate(r.malfind_hits):
        if m.process_name:
            out.append((f"malfind_hits[{i}].process_name", m.process_name))
    return out


__all__ = [
    "parse_fsstat", "fsstat_free_text_fields",
    "parse_fls", "fls_free_text_fields",
    "parse_icat", "icat_free_text_fields",
    "parse_regripper", "regripper_free_text_fields",
    "regripper_expected_paths", "REGRIPPER_EXPECTED_PATHS",
    "parse_scheduled_tasks", "scheduled_tasks_free_text_fields",
    "parse_volatility", "volatility_free_text_fields",
    "VOLATILITY_PLUGIN_ALLOWLIST",
]
