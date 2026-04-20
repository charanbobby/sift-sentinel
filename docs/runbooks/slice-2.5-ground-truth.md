# Slice 2.5 — Ground truth for `base-wkstn-05`

**Status:** in progress — waiting on your verdicts. Tick boxes in the [`Findings`](#the-4-findings-the-agent-produced) section and fill `out/ground_truth.json` per the [Output contract](#output-contract).

## What this is (plain English)

The agent produced 4 findings in [`out/findings.json`](../../experiments/slice-2-notebook/out/findings.json). Some may be real attacker persistence; some may be **tools the incident responders themselves installed** (DFIR agents, memory acquisition drivers, etc.) that look like persistence because they *are* persistence — just not the *attacker's*. Neither the agent nor we know for certain. This runbook walks you through making that call for each one, and the output becomes our Slice 2.5 scoring baseline.

**A "good" outcome of this work is not "agent was right on all 4."** A good outcome is *you produce defensible verdicts* that tell us what the agent is actually doing: over-flagging responder tools? missing subtle persistence? getting easy ones right? That's how Slice 3's Critic knows what to improve.

## Vocabulary (skip if familiar)

- **Persistence mechanism** — a way the attacker made sure their code runs again after a reboot (a registry Run key pointing to their malware, a service they registered, a scheduled task, etc.). Persistence is the highest-yield thing to hunt on a compromised disk because it's *designed* to survive, which means it sits on disk waiting to be found.
- **True positive (TP)** — the agent flagged it AND it really is attacker persistence.
- **False positive (FP)** — the agent flagged it but it's NOT attacker persistence (it's a responder tool, a legitimate product, or a benign Windows default).
- **False negative (FN)** — the agent missed a real attacker persistence entry. We spot-check for these at the end.
- **Unclear** — you can't tell without more info (binary signature, threat intel, memory forensics). Fine to mark.

## How to use this runbook

For each of the 4 findings below:

1. Read the agent's claim + the evidence.
2. Work through the **Investigative questions** in order. Google each unfamiliar name or path. If you learn something decisive, write it in **Your notes**.
3. Tick one verdict box (`TP` / `FP` / `UNCLEAR`).

No hurry. One finding at a time. I'll answer questions as you work through them if you want — ping me mid-way.

---

## The 4 findings the agent produced

### Finding 1 — `F-Response Subject` service

- **Agent's claim (high confidence):** Windows auto-start service running `C:\windows\subject_srv.exe`, connecting outbound to `base-hunt.shieldbase.lan:5682`. Agent flags this as attacker persistence because the binary lives in `C:\windows\` (not `System32`) and talks to an external host on a non-standard port.
- **Evidence source:** step 14 (regripper `services` on SYSTEM hive), cross-referenced with step 3 (fls listing of `/Windows`).
- **Evidence excerpt:**
  ```
  Name      = F-Response Subject
  Display   = F-Response Subject
  ImagePath = C:\windows\subject_srv.exe -s "base-hunt.shieldbase.lan:5682" -l 3262 -v "F-Response Subject" -k ""
  Type      = Own_Process
  Start     = Auto Start
  ```

**Investigative questions:**

1. **What is "F-Response"?** Google the product name. Is it a commercial product? Who publishes it? What does it do?
2. If it's a commercial product — is it something an **attacker** would install, or something **incident responders** install to investigate a compromised machine?
3. The hostname `base-hunt.shieldbase.lan` — "hunt" and "shield" are strong words. Does that sound like an attacker's C2 (command-and-control) domain, or like a DFIR team's internal hunt node?
4. Does the binary being in `C:\windows\` automatically make it suspicious, if the product that installed it is a legitimate DFIR tool?

**Your notes:**
```
- F-Response is a commercial DFIR product by F-Response LLC for remote live
  disk/memory access over the network.
- Primary userbase is incident responders, not attackers. Attacker mimicry
  would be narrow tradecraft; simpler hypothesis = responders installed it.
- Hostname `base-hunt.shieldbase.lan:5682` uses `.lan` (non-routable) plus
  "hunt"/"shield" naming — pattern matches DFIR team infrastructure, not C2.
- `C:\windows\` location alone is not disqualifying for legitimate vendor tools.
- Caveat: would still validate via digital signature / install provenance in a
  real investigation.
```

**Verdict:**
- [ ] True positive — attacker persistence
- [x] False positive — legitimate (responder/vendor/default)
- [ ] Unclear

---

### Finding 2 — `mnemosyne` kernel driver

- **Agent's claim (high confidence):** Kernel driver `C:\windows\Mnemosyne.sys` registered as a service. Agent's own note acknowledges: *"mnemosyne is a known memory-acquisition/DFIR tool driver but its presence alongside an attacker-controlled service warrants flagging."*
- **Evidence excerpt:**
  ```
  Name      = mnemosyne
  Display   = mnemosyne
  ImagePath = \??\C:\windows\Mnemosyne.sys
  Type      = Kernel driver
  Start     = Manual
  ```

**Investigative questions:**

1. Google "mnemosyne kernel driver" or "Mnemosyne.sys forensics". What context does the name come up in?
2. If Mnemosyne is a tool used by memory-forensics practitioners (live memory acquisition from a running system), who would install it — an attacker or a responder?
3. Does the `Manual` start type change your read? (Manual means it doesn't run at boot; something has to launch it explicitly.)
4. The agent's logic was *"even if this is a DFIR tool, it arriving on the same day as Finding 1 makes it suspicious."* Do you agree, or do you read it as "the responders installed both tools as a package during incident response"?

**Your notes:**
```
- "Mnemosyne" appears in memory-forensics / live RAM acquisition contexts —
  DFIR-adjacent tooling, not attacker malware families.
- Manual start = on-demand execution, fits "load → capture → unload" pattern
  for live memory imaging. Attacker persistence would favour Auto/Boot start.
- Same-day co-occurrence with Finding 1 cuts toward "responder toolkit
  deployed together," not "attacker dropped two tools."
- Agent's own note conceded it's a known DFIR tool; rationale for flagging
  was weak.
- Caveat: validate driver signature and install chain before final sign-off.
```

**Verdict:**
- [ ] True positive — attacker persistence
- [x] False positive — legitimate (responder/vendor/default)
- [ ] Unclear

---

### Finding 3 — `PerfMon` / `perfmonsvc64.exe`

- **Agent's claim (high confidence):** Auto-start service named `PerfMon`, display name `Perf Monitor`, running `c:\windows\system32\perfmonsvc64.exe`. Agent flags this as name-mimicry of a legitimate Windows component.
- **Evidence excerpt:**
  ```
  Name      = PerfMon
  Display   = Perf Monitor
  ImagePath = c:\windows\system32\perfmonsvc64.exe
  Type      = Own_Process
  Start     = Auto Start
  ```

**Investigative questions:**

1. Is there a legitimate Windows service called `PerfMon` that ships a binary called `perfmonsvc64.exe`? (Legitimate Performance Monitoring in Windows is `perfmon.exe` — the GUI tool — and performance-related services are things like `PerfHost`, `WmiApSrv`. There's no stock `perfmonsvc64.exe`.)
2. "Mimicking a real Windows component" is a classic attacker trick (T1036 — Masquerading in the MITRE ATT&CK framework). Does this fit that pattern?
3. Would a legitimate software vendor (Microsoft, a DFIR tool vendor, McAfee etc. — compare against Finding 1) name their service `PerfMon` when that name is so close to a Windows built-in?
4. Any chance this is a legitimate third-party monitoring product? Google `perfmonsvc64.exe` — does it turn up on VirusTotal, on malware analysis sites, or as a known product?

**Your notes:**
```
- No legitimate Windows service named "PerfMon" using `perfmonsvc64.exe`
  ships with the OS. Real perf components are `perfmon.exe` (GUI), `PerfHost`,
  `WmiApSrv`.
- Name collides with Microsoft built-in — textbook MITRE ATT&CK T1036.005
  (Match Legitimate Name or Location).
- System32 placement + OS-adjacent naming is the exact masquerading pattern.
- Reputable vendors brand clearly (McAfeeUpdaterUI, VMware User Process in
  this machine's Run keys); nobody legitimate picks a name colliding with a
  Windows component.
- `perfmonsvc64.exe` surfaces on malware analysis platforms (VirusTotal),
  not as a known product.
```

**Verdict:**
- [x] True positive — attacker persistence
- [ ] False positive — legitimate (responder/vendor/default)
- [ ] Unclear

---

### Finding 4 — `tbbd05` service with pipe-echo command

- **Agent's claim (medium confidence):** Service with randomly-named key `tbbd05`, no display name, ImagePath is a `cmd.exe` one-liner that echoes a hex string to a named pipe. Agent flags as "classic Metasploit/post-exploitation service-creation artifact."
- **Evidence excerpt:**
  ```
  Name      = tbbd05
  Display   =
  ImagePath = %COMSPEC% /c echo b6a1458f396 > \\.\pipe\334485
  Type      = Own_Process
  Start     = Disabled
  ```

**Investigative questions:**

1. What does an attacker *do* with a service whose ImagePath is `cmd.exe /c echo <hex> > \\.\pipe\<num>`? It's not running anything useful. Google "Metasploit service creation pipe echo" or "PSEXEC service pipe".
2. Why would *any* legitimate product create a service that just writes a hex token to a named pipe and then gets disabled?
3. The service is `Start = Disabled` — is the threat still present if the service can't start anymore? (Hint: the attacker may have *used* this service to get code execution once, then disabled it. The registry key *is* the forensic artifact, regardless of current start state.)
4. Random 5-char name + empty display name + no binary + disabled — what's the probability profile? Legitimate vendor vs. attacker one-off?

**Your notes:**
```
- ImagePath `cmd.exe /c echo <hex> > \\.\pipe\<num>` is not meant to execute
  business logic — it's a one-shot write to a named pipe used as a signal
  channel for another process.
- This is the signature PsExec / Metasploit service-creation pattern: the
  service is a vehicle to get SYSTEM-level execution; the ImagePath is
  intentionally meaningless.
- Legitimate software does not create random-named services whose only job
  is echoing a hex token into a pipe.
- `Start = Disabled` is not exculpatory — the attacker's code already ran;
  the disabled state is post-use cleanup. The registry key itself is the
  forensic artifact.
- Random 5-char name + empty display + no real binary + disabled = transient
  attacker/red-team execution artifact. No benign explanation in view.
```

**Verdict:**
- [x] True positive — attacker persistence
- [ ] False positive — legitimate (responder/vendor/default)
- [ ] Unclear

---

## False-negative spot-check (recommended)

The agent may have missed things. Quick checks on the unflagged outputs:

### Registry areas the agent scanned and produced NO findings for

These are small outputs — worth eyeballing to confirm the agent didn't miss anything subtle. (The agent saw the whole text of each — it didn't flag them because it judged nothing suspicious. Your job: second opinion.)

**SOFTWARE / Run (step 8, 42 lines) — contents:**
```
Microsoft\Windows\CurrentVersion\Run:
  VMware User Process  →  C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
Wow6432Node\Microsoft\Windows\CurrentVersion\Run:
  McAfeeUpdaterUI      →  C:\Program Files\McAfee\Agent\x86\UpdaterUI.exe
  ShStatEXE            →  C:\Program Files (x86)\McAfee\VirusScan Enterprise\SHSTAT.EXE
(other Run/RunOnce subkeys: all empty)
```
- **Spot-check:** VMware tools + McAfee AV = normal corporate workstation. No obvious misses.

**NTUSER (Administrator) / Run (step 18, 33 lines) — contents:**
```
Software\Microsoft\Windows\CurrentVersion\Run            — empty
Software\Microsoft\Windows\CurrentVersion\RunOnce        — empty
(all user-level Run variants: empty)
```
- **Spot-check:** no HKCU persistence at all. Confirms no user-level Run-key persistence on the Administrator profile.

**SOFTWARE / runonceex, appinitdlls, imagefile, winlogon_tln, schedagent (steps 9–13):** all empty or default values. No findings expected.

### Areas the agent might have missed entirely (important)

1. **SYSTEM / services (step 14) was truncated.** MCP server capped `stdout_excerpt` at 64 KB; the full output was 97 KB (3,684 lines). The agent only saw the first ~65 %. Services past the cutoff were invisible to it. Worth a spot scan.
   - **One-liner to dump all service names from the full output** (run from the host; sift-home is mounted into the notebook container):
     ```bash
     MSYS_NO_PATHCONV=1 docker exec find-evil-notebook grep -E '^  Name      =' \
       /home/sansforensics/cases/srl-2018-wkstn-05/analysis/raw/293e79aa-7ba9-4e55-bc8e-bd9bbebda90e.stdout \
       | sort -u
     ```
   - Eyeball that list for: random-looking names (like `tbbd05`), names that mimic legitimate Windows services (like `PerfMon`), unusual capitalization, or any non-printable / weird characters.
2. **NTUSER for non-Administrator users.** The plan only extracted Administrator's NTUSER.DAT. Other user profiles on the disk (if any) weren't checked for HKCU persistence. **Scope-expansion candidate for Slice 3+, not a miss this cycle.**
3. **Scheduled tasks.** The plan covered registry `SchedulingAgent` keys (benign metadata, step 13) but NOT scheduled task XML files (`C:\Windows\System32\Tasks\*`). That's a persistence blind spot; add to Slice 3 backlog.
4. **Startup folder.** `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` — another common persistence location, not in this plan. Slice 3 backlog.

**Record any false negative you find below:**
```
false_negative_1:
  what_was_missed: (describe)
  where: (hive + plugin, or file path)
  evidence_excerpt: (literal quote)
  severity: (low|medium|high)
```

---

## Output contract

When you're done with verdicts, we consolidate into machine-readable ground truth. Create `experiments/slice-2-notebook/out/ground_truth.json` with this shape:

```json
{
  "case_id": "srl-2018-wkstn-05",
  "e01_path": "/mnt/hackathon/base-wkstn-05-cdrive.E01",
  "annotated_by": "<your name>",
  "annotated_at": "2026-04-XX",
  "agent_findings_verdicts": [
    {
      "finding_index": 0,
      "finding_summary": "F-Response Subject service",
      "verdict": "TP|FP|UNCLEAR",
      "rationale": "<1-2 sentences on why>"
    },
    {"finding_index": 1, "finding_summary": "mnemosyne kernel driver", "verdict": "...", "rationale": "..."},
    {"finding_index": 2, "finding_summary": "PerfMon / perfmonsvc64.exe", "verdict": "...", "rationale": "..."},
    {"finding_index": 3, "finding_summary": "tbbd05 pipe-echo service", "verdict": "...", "rationale": "..."}
  ],
  "false_negatives": [
    // fill in ANY real persistence the agent missed. Empty list = agent had no false negatives.
    // {"what": "...", "where": "...", "evidence_excerpt": "...", "severity": "..."}
  ],
  "notes": "<any caveats or observations that don't fit above>"
}
```

Once this file exists, Slice 2.5 scoring code (to be built) computes:
- **Precision** = TP / (TP + FP) — when the agent flags, how often is it right?
- **Recall** = TP / (TP + FN) — of all real persistence, what fraction did the agent catch?
- **Hallucination count** = evidence entries whose `output_excerpt` isn't actually in the cited stdout (C9 already warns on this; ground truth confirms).

These are the Slice 2 baseline numbers. Slice 3's Critic is judged by whether it improves precision without wrecking recall.

---

## Parallel track — DFIR Madness Case 001

While you annotate `base-wkstn-05`, we'll run the same pipeline against the DFIR Madness workstation image (`DESKTOP.E01`). That gives us a **second data point** where ground truth is already published — sanity-check that our hand-annotation of `base-wkstn-05` doesn't have major blind spots.
