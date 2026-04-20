# Cobalt Strike — DFIR Artifact Reference

## What Is Cobalt Strike

Commercial red team tool (Fortra/HelpSystems), heavily abused by real attackers (Conti, FIN7, APT29, APT41, ransomware operators). **Beacon** is the implant that runs on the target and communicates back to the Team Server.

Two delivery modes:
- **Staged** — small stager shellcode downloads full Beacon DLL from Team Server
- **Stageless** — full Beacon payload delivered as single artifact

---

## Host-Based Artifacts

### Processes
| Indicator | What to look for |
|-----------|-----------------|
| Default spawn-to | `rundll32.exe`, `dllhost.exe`, `gpupdate.exe`, `msbuild.exe` with no arguments or unusual parents |
| Orphaned rundll32 | `rundll32.exe` with no args, parent is `powershell.exe` or `winword.exe` |
| Process injection | `svchost.exe`, `explorer.exe`, `notepad.exe` with injected threads (start address outside any loaded module) |
| PowerShell cradles | `powershell -nop -w hidden -encodedcommand ...` |
| Unusual parent-child | `winword.exe` → `cmd.exe` → `powershell.exe` → `rundll32.exe` |

### Named Pipes (Sysmon Event ID 17/18)
```
\\.\pipe\msagent_##          (default SMB Beacon)
\\.\pipe\MSSE-####-server    (default post-ex)
\\.\pipe\postex_####
\\.\pipe\postex_ssh_####
\\.\pipe\status_##
```
Operators customize these via Malleable C2, but randomized names still stand out.

### Services
- Creates short-lived service with random 7-char alphanumeric name
- Writes binary to `\\<target>\ADMIN$\<random>.exe`, starts it, deletes it
- System Event Log ID 7045 (new service installed)

### Registry Persistence
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\SYSTEM\CurrentControlSet\Services\<random_name>
HKCU\Environment\UserInitMprLogonScript
```

### File System
- Stagers in `%TEMP%`, `%APPDATA%`, `C:\ProgramData`
- Random-named `.dll`, `.exe`, `.bin` in `C:\Windows\Temp\`
- PowerShell history: `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- Prefetch: `RUNDLL32.EXE-*.pf`, suspicious `DLLHOST.EXE-*.pf`
- Shimcache / Amcache entries for executed binaries

---

## Memory Artifacts

### Injection Techniques
| Technique | API Chain | MITRE |
|-----------|----------|-------|
| Classic injection | `OpenProcess` → `VirtualAllocEx` (RWX) → `WriteProcessMemory` → `CreateRemoteThread` | T1055.001 |
| APC injection | `QueueUserAPC` into suspended thread | T1055.004 |
| Process hollowing | `CreateProcess` (suspended) → `NtUnmapViewOfSection` → `WriteProcessMemory` → `ResumeThread` | T1055.012 |

**Key indicator:** RWX/RX memory regions in processes not backed by a file on disk (MEM_PRIVATE). Use Volatility `malfind` plugin.

### Reflective DLL Loading
- Beacon DLL loaded entirely from memory — never touches disk
- Look for PE headers (`MZ`/`PE` signatures) in `MEM_PRIVATE` regions
- String `ReflectiveLoader` may appear in memory (unless obfuscated)

### Beacon Configuration Block (~0x1000 bytes)
Extractable fields of interest:
```
BeaconType:    HTTP(0), Hybrid(1), HTTPS(8)
C2Server:      C2 domain/IP
SleepTime:     Callback interval
Jitter:        Percentage jitter
SpawnTo:       Binary for post-ex jobs (default: rundll32.exe)
PipeName:      Named pipe pattern for SMB beacon
Watermark:     License ID — ties payload to specific license (cracked = 0x12345678)
PublicKey:     Team Server public key — clusters activity
UserAgent:     HTTP User-Agent string
```

**Extraction tools:** SentinelOne CobaltStrikeParser, Didier Stevens 1768.py, JPCERT/CC extractor, Volatility cobaltstrike plugin

---

## Network Artifacts

### Default HTTP/HTTPS C2
```
GET /dpixel HTTP/1.1
GET /pixel.gif HTTP/1.1
GET /__utm.gif HTTP/1.1
Cookie: <base64-encoded metadata>

POST /submit.php?id=<id> HTTP/1.1
Content-Type: application/octet-stream
```

Default User-Agent: `Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)` — dated UA on modern systems is suspicious.

Regular callback interval (default 60s) with jitter produces distinctive periodic pattern in netflow.

### Malleable C2 Detection
- Default TLS cert JARM hash: `07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1`
- JA3/JA3S fingerprints specific to Java-based Team Server
- Self-signed or anomalous certificate metadata

### DNS Beaconing
```
<encoded-data>.stage.12345678.<c2domain.com>    (staging)
<encoded-data>.<c2domain.com>                    (communication)
```
Uses A, AAAA, TXT records. High volume DNS to single domain with long subdomains.

### SMB/TCP Beacon (Internal Pivoting)
- Communicates over named pipes (port 445) — no direct external C2
- Chains through HTTP/DNS parent Beacon
- Unusual SMB traffic between workstations (not to file servers)

---

## Event Log Artifacts

### Security Log
| Event ID | Significance |
|----------|-------------|
| 4688 | Process creation — track rundll32, powershell, cmd with suspicious command lines |
| 4624 (Type 3, 9, 10) | Logon events — pass-the-hash shows as Type 9 (NewCredentials) |
| 4672 | Special privileges assigned — accompanies admin lateral movement |
| 4648 | Explicit credential logon — PsExec lateral movement |

### System Log
| Event ID | Significance |
|----------|-------------|
| 7045 | New service installed — random name, `%COMSPEC%` or `rundll32` in path |
| 7036 | Service start/stop — correlate with 7045 |

### PowerShell Logs
| Event ID | Significance |
|----------|-------------|
| 4103 | Module logging — pipeline execution details |
| 4104 | **Script block logging — captures deobfuscated PowerShell including stagers** |

### Sysmon (if deployed)
| Event ID | Significance |
|----------|-------------|
| 1 | Process creation with full command line + hashes |
| 3 | Network connection — outbound C2 from injected processes |
| 8 | CreateRemoteThread — inter-process injection |
| 10 | ProcessAccess — LSASS access for credential dumping |
| 17/18 | Named pipe created/connected — SMB Beacon and post-ex |
| 22 | DNS query — DNS Beacon resolution |

---

## MITRE ATT&CK Mapping

| Tactic | ID | Technique | CS Feature |
|--------|-----|-----------|-----------|
| Execution | T1059.001 | PowerShell | `powershell`, `powerpick` |
| Execution | T1569.002 | Service Execution | `psexec`, lateral movement |
| Persistence | T1547.001 | Registry Run Keys | Run key persistence |
| Privilege Esc | T1055.001 | DLL Injection | `inject`, `shinject` |
| Privilege Esc | T1055.012 | Process Hollowing | `spawn` with `ppid` |
| Defense Evasion | T1620 | Reflective Code Loading | Reflective DLL loader |
| Defense Evasion | T1218.011 | Rundll32 | Default spawn-to |
| Credential Access | T1003.001 | LSASS Memory | `logonpasswords` (Mimikatz) |
| Credential Access | T1558.003 | Kerberoasting | `kerberoast` |
| Lateral Movement | T1021.002 | SMB/Admin Shares | `psexec`, `jump` |
| C2 | T1071.001 | Web Protocols | HTTP/HTTPS Beacon |
| C2 | T1071.004 | DNS | DNS Beacon |
| C2 | T1573.002 | Asymmetric Crypto | RSA+AES encrypted C2 |

---

## IOC Checklist

```
[ ] rundll32.exe with no arguments or unusual parent
[ ] Named pipes matching CS patterns (msagent_*, MSSE-*-server, postex_*)
[ ] Periodic HTTP(S) callbacks with consistent intervals (+/- jitter)
[ ] Self-signed or anomalous TLS certificates
[ ] JARM fingerprint matching known CS Team Server
[ ] Short-lived services with random names (Event ID 7045)
[ ] RWX memory regions in legitimate processes not backed by files on disk
[ ] PowerShell script block logs with IEX download cradles
[ ] LSASS access (Sysmon 10) from unexpected processes
[ ] Beacon watermark / public key in extracted config
[ ] Prefetch + Shimcache/Amcache entries corroborating execution timeline
```
