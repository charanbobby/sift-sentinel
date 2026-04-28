"""Fail-fast probe for Plan B Extract rewrite (Slice 6 Step B, 2026-04-26).

GOAL: validate the new host-type-aware + channel-aware Extract prompt produces
sensible candidates against the LIVE LLM before touching pipeline/nodes.py.

Probes:
  1. wkstn-05 (workstation, dual-channel) — should produce ~8-15 candidates
     including memory artifact_types (process_anomaly / network_connection /
     injected_region / dll_load_anomaly).
  2. base-dc (Domain Controller, disk-only) — should produce DC-specific
     candidates: SECURITY hive, SAM hive, NTDS-related services, DC-specific
     scheduled tasks. NO memory candidates.

Run:
    docker exec sift-sentinel uv run python /workspace/probe_extract_b.py
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter

sys.path.insert(0, "/workspace")

from openai import OpenAI
from pipeline.schemas import Candidates  # uses extended Literal


# ─────────────────────────────────────────────────────────────────────────────
# Host-type detection (mirrors what nodes.py will do)
# ─────────────────────────────────────────────────────────────────────────────
def _host_type_of(case_id: str) -> tuple[str, str]:
    """Return (host_type_id, host_description). Naming convention:
    SRL 2018: srl-2018-base-{dc|file|rd-NN} or srl-2018-{dmz|wkstn}-{ftp|NN}
    DFIR Madness: dfirmadness-NNN-{desktop|workstation}
    """
    cid = case_id.lower()
    if "wkstn" in cid:
        return ("workstation", "Windows workstation; user-mode persistence is the primary attack surface")
    if "desktop" in cid:
        return ("workstation", "Windows desktop; user-mode persistence is the primary attack surface")
    if "base-dc" in cid or cid.endswith("-dc"):
        return ("domain_controller", "Windows Domain Controller; AD-specific compromise vectors apply")
    if "base-file" in cid or "fileserver" in cid:
        return ("file_server", "Windows file server; share + replication misuse common")
    if "base-rd" in cid or "-rdp" in cid or "-rd-" in cid:
        return ("rdp_gateway", "RDP gateway / Remote Desktop server; logon-screen hijacks + cred caches in scope")
    if "dmz-ftp" in cid or "-ftp" in cid:
        return ("ftp_server", "FTP server in DMZ; IIS + web-shell + virtual-directory abuse common")
    if "dmz" in cid:
        return ("dmz_host", "DMZ-facing host; web-shell + IIS abuse common")
    if "mail" in cid:
        return ("mail_server", "Mail server; transport-rule + Exchange-specific compromise possible")
    return ("windows_host", "Generic Windows host")


# ─────────────────────────────────────────────────────────────────────────────
# New Extract prompt (host-type + channel aware)
# ─────────────────────────────────────────────────────────────────────────────
_EXTRACT_SCHEMA = json.dumps(Candidates.model_json_schema(), indent=2)

_HOST_GUIDANCE = {
    "workstation": """
Workstation compromise patterns to consider:
- Per-user persistence: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run keys (NTUSER.DAT for each profile)
- Browser-launched binaries / DLL hijacks in user app dirs
- Scheduled tasks under user context
- Startup folder for the active user
""",
    "domain_controller": """
Domain Controller compromise patterns to consider:
- SECURITY hive: LSA secrets, audit policy tampering, password policy modification
- SAM hive: krbtgt account, machine account anomalies (krbtgt password change is rare; recent modification is suspicious)
- HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS: NTDS service configuration, replication metadata
- DC-specific scheduled tasks: \\System32\\Tasks\\Microsoft\\Windows\\DirectoryServices\\, \\Active Directory Rights Management\\
- Service accounts running unusual binaries (KrbtgtAccount, DefaultAccount, etc.)
- Group Policy preferences (cpassword leaks)
""",
    "file_server": """
File server compromise patterns to consider:
- Share configurations (HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares) — unauthorized shares, ANONYMOUS_LOGON exposure
- DFS replication state (HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DFS)
- File-server-specific scheduled backups (replaceable as persistence vehicles)
- Service accounts that own shares running unusual binaries
""",
    "rdp_gateway": """
RDP gateway compromise patterns to consider:
- IFEO debugger hijack on accessibility tools (sethc, utilman, narrator) — gives SYSTEM shell at logon screen
- Saved RDP credentials (HKLM\\SOFTWARE\\Microsoft\\Terminal Server Client\\Servers)
- TermService configuration changes (HKLM\\SYSTEM\\CurrentControlSet\\Services\\TermService)
- RDP-related scheduled tasks
- Logon-script hooks
""",
    "ftp_server": """
FTP server / DMZ host compromise patterns to consider:
- IIS application pool configuration (HKLM\\SOFTWARE\\Microsoft\\InetStp)
- FTP virtual directories pointing to unexpected paths (web-shell upload locations)
- IIS-related scheduled tasks
- FTP service config (HKLM\\SYSTEM\\CurrentControlSet\\Services\\FTPSVC)
- Service accounts with elevated privileges
""",
    "dmz_host": """
DMZ-facing host compromise patterns to consider:
- IIS / web-server configuration paths
- Public-facing service config (FTP, SMTP, etc.)
- Web shell drop locations under wwwroot or virtual dirs
- Outbound-only persistence (less reliance on inbound connections)
""",
    "mail_server": """
Mail server compromise patterns to consider:
- Exchange transport-rule modifications
- Service accounts with mailbox access rights
- IIS / Exchange admin endpoints
- Scheduled tasks under Exchange service contexts
""",
    "windows_host": "",  # no extra guidance for unknown
}

_MEMORY_GUIDANCE = """

MEMORY-CHANNEL EVIDENCE (the case has a staged RAM image — propose memory candidates too):
Memory is RUNTIME evidence captured by volatility against a RAM dump. It is NOT a registry path or disk file.
Use these memory artifact_types ONLY when proposing volatility-based runtime analysis:
  - process_anomaly       — live process inventory via volatility pslist + cmdline. Look for: suspicious parent-child (e.g., PowerShell spawned from WmiPrvSE), unusual process names, processes with no on-disk binary path, command lines with encoded payloads or LLM-API references.
  - network_connection    — live TCP/UDP sockets via volatility netscan. Look for: outbound C2 to unusual ports, connections to LLM API endpoints (api.openai.com, api.anthropic.com), CLOSED/CLOSE_WAIT residue from terminated beacons.
  - injected_region       — code injection / hollowing via volatility malfind. Look for: process memory marked PAGE_EXECUTE_READWRITE, code caves in legitimate processes.
  - dll_load_anomaly      — loaded modules per process via volatility dlllist. Look for: AI-SDK modules (openai, anthropic, langchain) loaded in unusual processes, persistence DLLs in svchost or system processes.

For memory candidates, `path_hint` describes what to look for in RAM (not a registry or disk path):
  e.g., "live process tree, parent-child anomalies"
  e.g., "outbound connections to LLM API endpoints"
  e.g., "PAGE_EXECUTE_READWRITE regions in legitimate processes"

CRITICAL DISTINCTION: a registry value that CONFIGURES a kernel-level DLL load (e.g., AppInit_DLLs, LSA Security Packages, NetworkProvider DLLs) is a `registry_hive` candidate, NOT a `dll_load_anomaly` candidate. `dll_load_anomaly` is for inspecting which DLLs are LOADED in process memory at capture time via volatility. Same logic for `network_connection` — a registry-configured proxy is `registry_hive`; live TCP sockets in a memory dump are `network_connection`.
"""

_NO_MEMORY_GUIDANCE = """

MEMORY-CHANNEL ARTIFACT TYPES ARE UNAVAILABLE FOR THIS CASE:
This case has no staged RAM image. The artifact_types `process_anomaly`, `network_connection`, `injected_region`, and `dll_load_anomaly` REQUIRE a memory dump and are NOT available. DO NOT use them. Use `registry_hive` for anything stored in the registry (including registry values that configure DLL loads or service behavior), `scheduled_task_xml` for tasks, and `service_config` for service definitions.
"""

_BASE_EXTRACT_PROMPT_TEMPLATE = """You are listing the candidate artifact locations that could contain persistence
or compromise evidence on a Windows host. You are NOT analyzing evidence yet — just enumerating where to look.

HOST TYPE: {host_type} — {host_description}
EVIDENCE CHANNELS AVAILABLE: {channels}

Return a single JSON object matching exactly this schema (no prose, no markdown fences):

{schema}

Universal Windows persistence locations to consider (always applicable):
- HKLM\\SOFTWARE\\...\\Run, RunOnce, RunOnceEx
- HKCU\\SOFTWARE\\...\\Run, RunOnce, RunOnceEx (per-user, in NTUSER.DAT)
- Scheduled Tasks (\\System32\\Tasks\\, \\Tasks\\)
- Windows Services (HKLM\\SYSTEM\\CurrentControlSet\\Services)
- Winlogon Userinit, Shell, Notify (HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon)
- AppInit_DLLs (HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows)
- Image File Execution Options (debugger hijack — accessibility tools)
- WMI event subscriptions (HKLM\\SOFTWARE\\Microsoft\\WMI)
- Startup folder (per user)
{host_guidance}{memory_guidance}

Rules:
- Output 8-15 candidates total. Prioritize by likelihood for THIS host type.
- Each candidate uses exactly one `artifact_type` from the schema.
- Each candidate MUST have a non-empty `reason` describing why an attacker would put something here on a {host_type}.
- Do not invent paths. Use canonical Windows paths only.
- For host-specific candidates that are higher-yield than generic ones, give them P1.
"""


def _build_extract_prompt(host_type: str, host_description: str, has_memory: bool) -> str:
    return _BASE_EXTRACT_PROMPT_TEMPLATE.format(
        host_type=host_type,
        host_description=host_description,
        channels="disk + memory" if has_memory else "disk only",
        schema=_EXTRACT_SCHEMA,
        host_guidance=_HOST_GUIDANCE.get(host_type, ""),
        memory_guidance=_MEMORY_GUIDANCE if has_memory else _NO_MEMORY_GUIDANCE,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Probe drivers
# ─────────────────────────────────────────────────────────────────────────────
QUESTION = "Given a Windows disk image suspected of compromise, what persistence mechanisms did the attacker install?"

_OR_RATES = {
    "google/gemini-3-flash-preview": (0.30 / 1_000_000, 2.50 / 1_000_000),  # input, output per token
}

def _llm_cost_pre(phase: str, model: str, messages: list) -> None:
    n_chars = sum(len(m["content"]) for m in messages)
    print(f"  [PRE  {phase:7s}] model={model}  est input ~{n_chars//4} tokens (chars/4 heuristic)")

def _llm_cost_post(phase: str, model: str, usage) -> None:
    if usage is None:
        print(f"  [POST {phase:7s}] usage=None")
        return
    rates = _OR_RATES.get(model)
    if rates:
        in_cost = usage.prompt_tokens * rates[0]
        out_cost = usage.completion_tokens * rates[1]
        print(f"  [POST {phase:7s}] in={usage.prompt_tokens:>6d}  out={usage.completion_tokens:>6d}  "
              f"cost in=${in_cost:.6f} out=${out_cost:.6f} total=${in_cost+out_cost:.6f}")
    else:
        print(f"  [POST {phase:7s}] in={usage.prompt_tokens}  out={usage.completion_tokens}  rate unknown")


def probe_case(case_id: str, has_memory: bool, client: OpenAI, model: str) -> None:
    host_type, host_desc = _host_type_of(case_id)
    print(f"\n{'='*70}")
    print(f"PROBE: {case_id}")
    print(f"  host_type   = {host_type}")
    print(f"  has_memory  = {has_memory}")
    print(f"{'='*70}")

    system_prompt = _build_extract_prompt(host_type, host_desc, has_memory)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": f"Question: {QUESTION}"},
    ]

    _llm_cost_pre("extract", model, messages)
    resp = client.chat.completions.create(
        model=model,
        messages=messages,
        response_format={"type": "json_object"},
    )
    _llm_cost_post("extract", model, resp.usage)

    raw = resp.choices[0].message.content or ""
    try:
        data = json.loads(raw)
        # drop null path_hints same as production extract_node does
        data["candidates"] = [c for c in data.get("candidates", []) if c.get("path_hint")]
        candidates = Candidates.model_validate(data)
    except Exception as e:
        print(f"\n!!! VALIDATION FAILED: {e}")
        print(f"Raw response (first 800 chars):\n{raw[:800]}")
        return

    print(f"\nReturned {len(candidates.candidates)} candidates")
    types = Counter(c.artifact_type for c in candidates.candidates)
    print(f"  by artifact_type: {dict(types)}")
    has_memory_proposed = any(c.artifact_type in {"process_anomaly", "network_connection", "injected_region", "dll_load_anomaly"} for c in candidates.candidates)
    print(f"  memory candidates proposed: {has_memory_proposed}")
    if has_memory and not has_memory_proposed:
        print(f"  ⚠ EXPECTED memory candidates (case has staged RAM image) but got none")
    if (not has_memory) and has_memory_proposed:
        print(f"  ⚠ UNEXPECTED memory candidates (case has no RAM image)")

    print(f"\nCandidates:")
    for i, c in enumerate(candidates.candidates, 1):
        print(f"  [{i:2d}] P{c.priority} · {c.artifact_type:22s} · {c.path_hint[:60]}")
        print(f"       reason: {c.reason[:110]}")


def main() -> None:
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        print("OPENROUTER_API_KEY not set; cannot probe.")
        sys.exit(1)
    client = OpenAI(api_key=api_key, base_url="https://openrouter.ai/api/v1")
    model = "google/gemini-3-flash-preview"

    # Probe 1: workstation with memory (wkstn-05)
    probe_case("srl-2018-wkstn-05", has_memory=True, client=client, model=model)

    # Probe 2: domain controller, disk-only (base-dc)
    probe_case("srl-2018-base-dc", has_memory=False, client=client, model=model)

    # Probe 3: ftp server, disk-only (dmz-ftp) — second host-type to check branching works
    probe_case("srl-2018-dmz-ftp", has_memory=False, client=client, model=model)


if __name__ == "__main__":
    main()
