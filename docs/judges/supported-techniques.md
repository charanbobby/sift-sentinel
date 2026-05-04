# Supported techniques (judge scenarios)

This catalog lists what the synthetic-workstation builder can plant on a disk image, and what the sift-sentinel pipeline can detect on the resulting disk. Use it to know which attacker scenarios produce a meaningful test of our agent.

## Scope

- **Disk-only.** The pipeline analyzes a Windows NTFS partition. Memory-only artifacts (process injection, in-memory C2 beacons, fileless persistence) are out of scope for judge submissions.
- **Persistence focus.** The agent's primary question is "what persistence mechanisms did the attacker install?" Scenarios should imply at least one disk-resident persistence artifact (a file, a registry value, a scheduled task, or a service entry).
- **Static fixtures.** All planted artifacts are static files and registry data on a never-booted NTFS image. Nothing executes. Live C2 endpoints, real malware payloads, or actual exploits are not part of any submission.

## What we can plant (5 primitives)

The build harness (`experiments/synthetic-ai-workstation/build.py`) supports exactly these artifact types. A judge scenario translates into one or more of these.

### 1. `file_drop`

Writes a file (text or binary) to any path under the Windows root.

Common uses:
- **Web shell.** `inetpub/wwwroot/diag.aspx`, `Program Files/PaperCut MF/server/webapps/ROOT/system_check.jsp`. Detected by the pipeline's `web_shell` category.
- **AppInit DLL payload.** Drop a .dll under a path that a registry AppInit_DLLs value points at. Pair with primitive #5 below.
- **LOLBin staging.** Drop a `.bat`, `.ps1`, or signed-binary copy under `Users/Public/` or `ProgramData/`.
- **Credential staging.** Token files at `Users/<user>/AppData/Roaming/.huggingface/token`, `.aws/credentials`, etc.

Required fields: `file_path` (relative path, forward slashes), one of `file_content_text` or `file_content_b64`.

### 2. `scheduled_task_xml`

Plants a Windows Task Scheduler XML at `Windows/System32/Tasks/<task_install_path>`. Encoded UTF-16-LE with BOM, matching real Windows.

Common uses:
- Logon-trigger persistence (`<LogonTrigger>` runs a command at every login).
- Daily-trigger persistence (cron-like cadence).
- Indirect-injection chain (task description benign, action references a separate planted file like a web shell).

Required fields: `task_install_path`, `task_xml` (full XML body).

### 3. `registry_run_key`

Adds a value to a registry Run key in the requested hive.

Common uses:
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` -> attacker_persistence (most common).
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`.
- `HKCU\...\Run` (NTUSER.DAT hive, per-user).

Detected by the pipeline's `registry_run_key` category.

Required fields: `hive` (SOFTWARE / SYSTEM / NTUSER.DAT), `key_path`, `value_name`, `value_data`.

### 4. `registry_service`

Plants a service entry under `ControlSet001\Services\<service_name>` in the SYSTEM hive. RegRipper's services plugin and the agent both query this path.

Common uses:
- **Vendor masquerade.** ServiceName like `WindowsDefenderHelper` with a `service_image_path` under `ProgramData\Microsoft\Windows Defender\Platform\helper.exe`. Tests the agent's masquerade-counter-rule.
- **Named-pipe beacon.** ImagePath `cmd.exe /c echo <hex> > \\.\pipe\<num>`. Tests the Metasploit-PsExec rule.
- **Auto-start backdoor.** `service_start_type: 2` (auto), arbitrary ImagePath in a non-standard location.

Detected by the pipeline's `service` category.

Required fields: `service_name` (must be unique), `service_image_path`.
Optional: `service_display_name`, `service_description`, `service_start_type` (0 boot / 1 system / 2 auto / 3 manual / 4 disabled).

### 5. `registry_binary_value`

Sets a `REG_BINARY` value at any registry path. The general-purpose escape hatch when the other four primitives do not fit.

Common uses:
- **AppInit_DLLs.** Path `Microsoft\Windows NT\CurrentVersion\Windows`, value name `AppInit_DLLs`, binary value containing a path to a DLL planted via primitive #1.
- **IFEO Debugger hijack.** Path `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>`, value name `Debugger`, value pointing at attacker tool.
- **WDigest credential cache.** Path `Microsoft\Windows NT\CurrentVersion\SecurityProviders\WDigest`, value name `UseLogonCredentials`, value `0x01`.

Detected by the pipeline's `appinit_dll`, `ifeo_debugger`, or `logon_script` categories depending on the key path.

Required fields: `hive`, `key_path`, `value_name`, `value_binary_b64`.

## What the agent can detect (7 categories)

The pipeline classifies findings into:

| Category | Triggered by | What the agent looks for |
|---|---|---|
| `registry_run_key` | primitive #3 | Run / RunOnce keys with non-standard binaries, encoded payloads, masquerade naming |
| `service` | primitive #4 | Auto-start services in non-standard paths, masquerade names, named-pipe-beacon command shape |
| `scheduled_task` | primitive #2 | Tasks under non-Microsoft folders, logon triggers running cmd/powershell, references to writable paths |
| `ifeo_debugger` | primitive #5 (specific path) | Image File Execution Options Debugger value pointing at unexpected binary |
| `appinit_dll` | primitive #5 (specific path) + primitive #1 (the dll) | AppInit_DLLs value referencing user-writable DLLs |
| `logon_script` | primitive #5 (Userinit / Shell / Winlogon) | Userinit / Shell registry values modified beyond default |
| `web_shell` | primitive #1 with file under inetpub/wwwroot or vendor webapp roots | Server-side script files under web roots |

The agent assigns one of these classifications to each finding:
- `attacker_persistence` (HIGH confidence the artifact is malicious)
- `attacker_persistence_ai_assisted` (the artifact contains AI-tradecraft signals: prompt-injection strings, encoded directives)
- `requires_disambiguation` (suspicious but could be legitimate; needs analyst review)
- `legitimate_responder_tool` (DFIR / IR tool legitimately present, e.g. F-Response, Mnemosyne)
- `NOT_FOUND` (host appears clean)

## What we can NOT plant (out of scope for judges)

- **Memory-only artifacts.** No process injection, no in-memory shellcode, no DKOM. Memory-channel analysis is exploratory and not part of the judge submission flow.
- **Live exploit chains.** No working CVE exploitation, no actual code execution. Only static persistence artifacts.
- **Network captures.** No PCAP, no live C2 traffic. Domain names and IPs in artifacts are static fixtures (`example.invalid`, RFC 1918, etc.).
- **AD compromise.** No domain controller artifacts (KRBTGT replication, Golden Ticket forging). Domain-controller evidence sets are pre-recorded SANS images, not synthetic.
- **Bootkit / firmware.** No MBR / GPT modifications. Build harness only writes inside the NTFS partition.
- **Schema enum present but unimplemented:** `file_drop_sqlite_chrome_history` is in `manifest_schema.json` but `build.py` does not yet have a planter for it.

## What a judge scenario should describe

A good scenario specifies enough detail for the translator LLM to pick concrete primitives. Example shapes:

**Good (specific, disk-detectable):**
> A red-team operator compromised a Windows 7 workstation, dropped a fake Windows Defender service named "WindowsDefenderTelemetry" with ImagePath under ProgramData, and added a Run key called "DefenderUpdate" that launches a PowerShell-encoded command. They also dropped a JSP web shell under PaperCut's webapp directory.

This translates to: 1× `registry_service` (masquerade), 1× `registry_run_key` (encoded payload), 1× `file_drop` (web shell). All disk-detectable.

**Good (high-level, translator can map):**
> Cobalt Strike PsExec lateral movement landed on this host. Show me what disk artifacts that leaves.

Translator picks: 1× `registry_service` with named-pipe beacon ImagePath. Tests the existing named-pipe rule.

**Bad (memory-only, would be rejected):**
> A fileless PowerShell loader was injected into svchost.exe via WMI subscription.

Out of scope. Translator returns "your scenario implies in-memory execution and WMI subscription persistence; we currently support disk-resident persistence only. Closest variant: a `registry_run_key` that launches the loader at boot, leaving a registry-visible footprint."

**Bad (AD-side, would be rejected):**
> Domain controller pwned via Zerologon, KRBTGT hash dumped, Golden Ticket forged.

Out of scope. Domain controller artifacts are not buildable by our harness.

## Honest limitations

- **Detection coverage is real, not exhaustive.** The agent has rules for masquerade, named-pipe beacons, IFEO debuggers, web shells in standard inetpub paths, AppInit_DLLs in deprecated registry paths, and several specific TTPs that recur in SANS evidence. It does not have rules for every persistence technique ever documented.
- **Acknowledged-gap classification.** Scenarios that imply techniques we know we miss can be tagged `expected_detection: expected_miss_documented_gap`. The score report shows them under "acknowledged gaps" rather than "miss," and surprise detections are surfaced as "bonus."
- **Score is location-based.** A finding counts as detection only if it cites the planted artifact's discriminating locator (file path, registry value name, service name, task install path). The agent's classification text is not what scoring matches against; the locator string is. This makes scoring stable across LLM phrasing variations.
