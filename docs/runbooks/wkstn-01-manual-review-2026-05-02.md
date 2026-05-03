---
created: 2026-05-02
status: open
context: dual-mode sweep flagged wkstn-01 as NOT_FOUND but owner says the host was compromised. Manual review to figure out what the agent missed and decide whether the classifier or the host (or both) is to blame.
---

# Manual review of wkstn-01 false negative

## TL;DR

The dual-channel sweep on 2026-05-02 ran wkstn-01 and reported two NOT_FOUND findings: one saying disk persistence looked clean, one flagging a suspicious svchost connection to `172.16.4.10:8080` but classifying it as "requires_disambiguation". The owner has confirmed wkstn-01 was compromised. Cross-checking the other dual runs, FOUR different captured hosts beacon to `172.16.4.10:8080` (wkstn-01, wkstn-05, file, rd-02), and wkstn-01 is the only one with an ESTABLISHED record at capture time. That makes the second finding the smoking gun: the agent had it, just under-classified it. This runbook walks through the cross-host evidence, the parse-error gaps, the quarantined tool call, and writing up the verdict.

## What is "local" vs what is "in the image" (mental model)

There are three networks in this project and they are NOT the same thing. Confusing them is the main failure mode when reading any IP in this runbook.

| Layer | IP range | What it is |
|---|---|---|
| Your laptop, Docker network | `172.17.0.0/16` (the `17`) | The two containers `sift-mcp` and `sift-sentinel` run here. Active. Ours. |
| Hetzner VPS for judges | `46.62.255.66` | Public IPv4. Same containers, exposed for the judge submit-a-scenario flow. |
| SANS lab from 2018 (in the image) | `172.16.0.0/12` (the `16`) | Frozen snapshot. NOT live. Only exists as data inside the `.E01` and `.img` files. |

Every IP in this runbook (`172.16.4.10`, `172.16.7.11`, `172.16.4.5`, etc) belongs to the third layer. They are labels for what other machines `wkstn-01` was talking to back in 2018, preserved in `wkstn-01`'s captured kernel socket table. Volatility's `netscan` plugin walks that table out of the memory dump, prints the addresses it finds. We cannot ping or connect to any of them today; they are evidence, not infrastructure.

## Investigative question

**Was wkstn-01 actually compromised, and if so, why did our agent come back NOT_FOUND?**

Three possible answers we need to land on:
1. **Agent under-classified existing evidence.** The `172.16.4.10:8080` connection was right there, the agent saw it, but called it "medium / requires_disambiguation" instead of HIGH C2 beacon. Fix: tighten the classifier so a known-bad-IP-from-a-sibling-host gets escalated.
2. **Agent did not pull the right evidence.** Two registry parses failed silently (Winlogon, WDigest/SecurityProviders); persistence may live there. Fix: rerun those plugins or pull the hives manually.
3. **The compromise is invisible at this snapshot.** Dormant implant, in-memory loader cleared before capture, etc. Fix: document as a real limit and explain in the submission.

## Where the artifacts are

Run dir on the Windows host:
```
experiments/slice-2-notebook/out/runs/srl-2018-base-wkstn-01-dual/srl-2018-base-wkstn-01-dual-003/
```

Files of interest:
- `01_extract_candidates.json` - what disk artifacts the EXTRACT phase pulled.
- `02_plan_tool_plan.json` - the 28-step plan PLAN emitted.
- `04_execute_evidence.jsonl` - 26 evidence records, one per tool call. This is the agent's eyeball.
- `05_interpret_findings.json` - the two final findings (already reviewed in this runbook).
- `06_critic_disagreements.jsonl` - both findings escalated by the critic to `human_review`. The critic AGREED they need human eyes; this runbook is that human pass.
- `07_terminal.QUARANTINED` - one tool call got injection-quarantined (token T1033 in raw bytes triggered `INJ_ATTCK_EMIT`).

## Step-by-step review

Run from Git Bash on the Windows host. Each step is read-only and free.

### 1. Pin the canonical run dir as a shell var

```bash
export RUN_DIR="experiments/slice-2-notebook/out/runs/srl-2018-base-wkstn-01-dual/srl-2018-base-wkstn-01-dual-003"
ls "$RUN_DIR"
```

- [ ] Eight files listed (the seven I named plus `integrity_ledger.jsonl`).

### 2. Eyeball the two findings the agent shipped

```bash
jq '.findings[] | {category, classification, mechanism, value, confidence, notes: .notes[0:200]}' "$RUN_DIR/05_interpret_findings.json"
```

- [ ] Confirm finding 1 is `legitimate_windows_default` (disk persistence clean).
- [ ] Confirm finding 2 is the `172.16.4.10:8080` svchost connection.

### 3. Confirm `172.16.4.10:8080` is the known C2 (cross-host evidence pre-extracted)

I already pulled this out of every dual-sweep run dir. Four hosts in the SANS dataset have `netscan` records to `172.16.4.10:8080`:

| Captured host | Captured host IP | Records | Connection states observed |
|---|---|---|---|
| wkstn-01 | 172.16.7.11 | 3 | 1 ESTABLISHED, 2 CLOSED |
| wkstn-05 | 172.16.7.15 | 6 | 4 CLOSE_WAIT, 2 CLOSED |
| file | 172.16.4.5 | 4 | 1 CLOSE_WAIT, 3 CLOSED |
| rd-02 | 172.16.6.12 | 2 | 2 CLOSED |

What this tells us:
- Four different hosts on three different subnets all beacon to the same internal address on the same port. That is a real internal C2, not a coincidence.
- wkstn-01 is the **only** host with an ESTABLISHED record at capture time. Implant was alive on wkstn-01 the moment the dump was taken.
- The other three hosts show `CLOSE_WAIT` and `CLOSED` with exited PIDs — classic detached-implant footprints. The accuracy report (line 180) already classifies wkstn-05's pattern as a `c2_beacon`.

Verdict for this step: `172.16.4.10:8080` is attacker infrastructure inside the lab. wkstn-01's finding 2 should have been HIGH `c2_beacon`, not "medium / requires_disambiguation".

If you want to re-run the extraction to verify, this is the one-liner that produced the table above:
```bash
for run in experiments/slice-2-notebook/out/runs/srl-2018-base-{wkstn-01,wkstn-05,file,rd-02}-dual/*/04_execute_evidence.jsonl; do
  echo "--- $run ---"
  grep -oE '"local_address":"[^"]+","foreign_address":"172\.16\.4\.10:8080","state":"[A-Z_]+"' "$run"
done
```

- [ ] Confirm the four-host table above by running the one-liner. Save the output if you want it in the submission.

### 4. List every tool call the agent made and its status

```bash
jq -r '[.step_id, .tool, .args | tostring | .[0:60], .tool_execution_status] | @tsv' "$RUN_DIR/04_execute_evidence.jsonl" | column -t -s $'\t'
```

- [ ] 26 rows. Note any row where `tool_execution_status` is NOT `ok`.

Expected non-ok rows from the findings notes:
- step 9 (Winlogon) - `parse_error`
- step 14 (WDigest/SecurityProviders) - `parse_error`
- one quarantined step (the INJ_ATTCK_EMIT one)

### 5. Read the two parse-error rows (raw output already pulled, see below)

The agent flagged step 9 (`winlogon_tln`) and step 14 (`securityproviders`) as `parse_error` and dropped them. I went and read the raw files anyway. Here is what the regripper plugins actually emitted on disk for wkstn-01:

```
=== winlogon_tln (raw_path: .../cba789b3-...raw) ===
1612389097|ALERT|||Microsoft\Windows NT\CurrentVersion\Winlogon Shell value not explorer.exe: 0
1612389097|ALERT|||Microsoft\Windows NT\CurrentVersion\Winlogon Shell value not explorer.exe: sihost.exe
1525457714|ALERT|||Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon Shell value not explorer.exe: 0

=== securityproviders (raw_path: .../83bd009b-...raw) ===
LastWrite: 2018-05-04 18:15:09Z
SecurityPrividers = credssp.dll
```

Two things to do here.

**5a. Decide if the Winlogon ALERTs are real persistence or a regripper false positive.** This matters: if real, it is the on-disk corroborating finding our pipeline missed (T1547.004 Winlogon Shell hijack). If false, it is just noise we can safely drop.

Reality check before celebrating: I ran the same `winlogon_tln` plugin output on the other three dual-sweep hosts and rd-02 has the IDENTICAL alert pattern (Shell value 0 + sihost.exe), even though rd-02 is reportedly compromised in a different way (masquerade services, process injection). file and wkstn-05 produced empty output (Win Server / Win7 hives behave differently for this plugin).

So the ALERTs come down to one of:
- **Win10 regripper false positive.** The `winlogon_tln` plugin's "Shell != explorer.exe" rule may not understand the Win10 `Shell` value being a `REG_MULTI_SZ` list, and may be misreading null-prefixed binary bytes as the string `"0"`. `sihost.exe` is the legitimate Shell Infrastructure Host that Windows starts as a Shell extension.
- **Both wkstn-01 and rd-02 share the same compromise pattern.** Possible if the attacker pushed the same persistence change across multiple hosts via a shared script.

How to tell them apart:
- [ ] Decode the actual `Shell` value bytes. Run:
  ```bash
  docker exec sift-mcp bash -lc '
    rip.pl -r /home/sansforensics/cases/srl-2018-base-wkstn-01-dual/analysis/hives/SOFTWARE -p winlogon
  '
  ```
  The plugin (without `_tln`) will print the human-readable form: `Shell : <values>`. Confirm whether the values are literally `0` or whether they are mis-read binary, and whether `sihost.exe` is in a list with `explorer.exe` or replaces it.
- [ ] Compare the same on rd-02 and on a known-clean baseline (wkstn-05's win7 doesn't help; instead diff against a fresh Windows 10 reference image if you have one).

**5b. Securityproviders is fine.** The raw output shows `credssp.dll` only. That is the stock Windows value. The "parse_error" was our parser's fault, not real evidence of tamper. Note this as a parser bug for the writeup but do not chase further.

(The agent's `05_interpret_findings.json` calls these "step 9 (Winlogon) and step 14 (WDigest/SecurityProviders)" but no `wdigest` plugin was actually planned. The model invented "WDigest" in the notes. That is a separate prompt-discipline issue.)

### 6. Why the parser dropped the Winlogon ALERTs

The `volatility_run` / `regripper_run` MCP tool builds a `structured_fields` JSON object from each plugin's stdout. For `winlogon_tln` the output format is regripper's TLN timeline (`epoch|TYPE|host|user|description`) and our parser does not currently understand that format. So `entries` came back empty and the call was tagged `parse_error`. This is a documented parser gap, not an attacker-induced failure.

Action item from this finding (not for tonight, just record it):
- [ ] Add a TLN-format branch to the regripper output parser so `ALERT` rows are surfaced as structured `alerts: [{epoch, message}]` to the LLM. That would have given the agent something concrete to reason about regardless of whether the alerts are FPs.

### 7. Look at the quarantined tool call

```bash
cat "$RUN_DIR/07_terminal.QUARANTINED"
grep INJECTION_QUARANTINE "$RUN_DIR/06_critic_disagreements.jsonl"
```

- [ ] The flag is `INJ_ATTCK_EMIT` matching the literal token `T1033`. Find the `tool_call_id` in the quarantine event.
- [ ] Pull the corresponding raw evidence:
```bash
jq --arg tcid "<paste the id>" 'select(.tool_call_id == $tcid)' "$RUN_DIR/04_execute_evidence.jsonl"
```
- [ ] Decide: does the quarantined call look like real attacker output (a binary blob containing the literal MITRE technique ID), or is it a regripper plugin that legitimately echoes ATT&CK IDs in its banner? If the latter, this is a false-positive injection guard and we add a counter-rule.

### 8. Look at the C2 connection's process tree more deeply

The agent saw PID 2332 (`svchost.exe -k utcsvc -p`) talking to `172.16.4.10:8080`. Pull every record about that PID:

```bash
jq 'select(. | tostring | contains("2332"))' "$RUN_DIR/04_execute_evidence.jsonl" | jq '{tool: .tool_name, status: .tool_execution_status, fields: .structured_fields}' | head -200
```

- [ ] Confirm parent of PID 2332 is `services.exe` (PID 776). Yes = expected for svchost.
- [ ] Confirm command line is `C:\WINDOWS\system32\svchost.exe -k utcsvc -p`. The `-k utcsvc` group hosts DiagTrack (Windows telemetry).
- [ ] The agent already noted DiagTrack normally talks to Microsoft endpoints, not internal RFC1918 addresses. We now have external proof (sibling host wkstn-05) that `172.16.4.10` is attacker-owned. Conclusion: `svchost.exe -k utcsvc` was probably hollowed or piggybacked for C2.

### 9. Look at any other PID with traffic to `172.16.4.10`

```bash
jq 'select(.tool_name == "volatility_run")
    | select((.structured_fields // {}) | tostring | contains("172.16.4.10"))
    | {step: .step_id, plugin: .args.plugin, fields: .structured_fields}' \
   "$RUN_DIR/04_execute_evidence.jsonl"
```

- [ ] List every PID and connection state. Multiple PIDs with CLOSED records = repeated callback pattern, not a one-shot.

### 10. Write up the verdict

Add a short section to `docs/submission/memory-sweep-2026-05-02.md` (or a sibling file) that records:
- [ ] Whether the FN is "agent under-classified existing evidence" (most likely, based on step 3).
- [ ] What the parse_error registry values turned out to be (step 6).
- [ ] What the quarantined call really was (step 7).
- [ ] Whether `wkstn-01` should now be re-flagged as TRUE POSITIVE (likely yes).
- [ ] What classifier rule or prompt change would have caught it on the first pass (probably: "if a destination IP appears in another host's c2_beacon finding from the same case, escalate to HIGH").

## What this gives the submission

A worked example of "our agent was wrong, here is why, here is the fix." That is more credible than a clean perfect score and matches the "honest scope" tone we already have in the judges docs.

## Pre-extracted summary (skim if you want the headline before walking the steps)

What I already know from the evidence (no human review needed for these):
- wkstn-01 had an ESTABLISHED TCP connection at capture time from PID 2332 (`svchost.exe -k utcsvc -p`, the DiagTrack telemetry service) to `172.16.4.10:8080`. Three other captured hosts in the dataset also beacon to the same internal address. This is the C2 channel.
- The agent classified that connection as "medium / requires_disambiguation" instead of HIGH `c2_beacon`. Cross-host corroboration would have escalated it.
- Two of the agent's plugin calls came back `parse_error`. One (`securityproviders`) had clean output, only our parser failed. The other (`winlogon_tln`) emitted ALERT rows about the `Shell` registry value being something other than `explorer.exe`, but rd-02 emitted IDENTICAL alerts and we suspect a Win10 regripper false-positive on `REG_MULTI_SZ` Shell values. Step 5a above is the disambiguation work.
- One plugin call was injection-quarantined because its raw output contained the literal token `T1033`. Step 7 above checks whether that was real attacker output or a regripper banner and decides whether to write a counter-rule.

Headline verdict (subject to step 5a confirming the Winlogon ALERTs):
- **wkstn-01 IS compromised. Pipeline saw the C2 beacon, mis-graded it. The on-disk persistence story may or may not corroborate; the parser-error plus ambiguous regripper output is a real gap either way.**

## Independent verification pass (2026-05-02)

Second-pass verdict: **confirmed false negative by under-classification.** I re-read the run artifacts directly from `srl-2018-base-wkstn-01-dual-003`, not just this runbook.

Evidence checked:
- `05_interpret_findings.json` contains the exact suspicious connection: `172.16.7.11:51892 -> 172.16.4.10:8080 ESTABLISHED`, PID 2332, `svchost.exe -k utcsvc -p`. The final classifier labeled it `NOT_FOUND / requires_disambiguation / medium`.
- `04_execute_evidence.jsonl` has three wkstn-01 callbacks to `172.16.4.10:8080`: PID 2332 `ESTABLISHED`, PID 544 `CLOSED`, and PID 0 `CLOSED`.
- Cross-host artifact scan confirms the same destination on multiple hosts: `base-file`/`base-file-dual`, `base-rd-02-dual`, `base-wkstn-05-dual`, and the prior `srl-2018-wkstn-05` runs. The repeated same-IP/same-port pattern across hosts is enough to promote the destination to known internal C2 for this case.
- PID 2332 process context is normal-looking service hosting: parent PID 776 `services.exe`, command line `C:\WINDOWS\System32\svchost.exe -k utcsvc -p`. That does not clear the activity; it only explains why the original classifier hesitated.
- The quarantined tool call was the extracted `SOFTWARE` hive itself (`magic_bytes` begins `regf`). The `T1033` hit is a raw-hive byte-pattern false positive, not attacker-controlled terminal output.
- Non-ok tool statuses remain: `winlogon_tln` parse error, `securityproviders` parse error, and empty `malfind`. These are coverage gaps, but they do not negate the live C2 evidence.

Actionable rule change:
- If a destination IP:port appears in a sibling host's confirmed or strongly suspected C2 finding for the same case family, escalate matching network evidence to HIGH `c2_beacon`, especially when the local host has an `ESTABLISHED` connection at capture time.

## Proposed cross-host C2 escalation rule (for review)

The wkstn-01 FN was caused by the agent treating each host as if it were the only run in the world. There are three ways to add cross-host context. Each is a real option; pick one before we touch code.

### Option A: post-hoc aggregator (smallest blast radius)

A separate script `scripts/cross_host_escalate.py` walks every run dir under a sweep label (e.g. `out/runs/srl-2018-base-*-dual/<latest>/05_interpret_findings.json`), builds a global table of suspicious destinations by `(ip, port)`, and re-grades per-host findings whose value contains a destination that appears in another host's `c2_beacon` finding. Output: a sweep-level report `docs/submission/cross-host-escalations-<date>.md` with the original verdict, the escalated verdict, and the supporting hosts.

Pros: agent stays untouched, pure post-processing, reversible, easy to audit by hand. Best for the submission writeup. We can also run it on past sweeps without re-running anything.

Cons: each individual run dir still has the unescalated verdict; the aggregator is a separate artifact judges have to read.

### Option B: prompt-injected known-bad list (medium change)

`run_case.py` accepts a new optional `--known-bad-destinations <path>` flag. INTERPRET's prompt has a new section "If the finding's value mentions any address from this list, treat it as cross-host-corroborated C2 and escalate." For the SRL-2018 sweep we prepopulate the list from the disk-only sweep's `c2_beacon` findings.

Pros: per-host run dir already has the right verdict. Self-documenting in the prompt.

Cons: prompt-only, no enforcement layer. The model can still ignore it. Also requires us to seed the list correctly per sweep.

### Option C: critic rule R_18 (largest change)

A new rule in `experiments/slice-2-notebook/pipeline/critic.py` that, given a `Finding` whose `value` contains an IP:port, checks a passed-in `cross_host_destinations` index built by the runner before the critic spans up. If the destination appears in another host's confirmed `c2_beacon`, the rule fails the finding and forces re-classification (severity=`escalate`, action=`re_plan`).

Pros: hard enforcement, integrated with the disagreement ledger, judges see it in `06_critic_disagreements.jsonl` automatically.

Cons: changes `CriticContext` shape (needs cross-case data passed in). Needs the runner to load other hosts' findings before each run, which couples runs together. Also our critic scope today is "this finding vs this run's evidence"; widening to "this finding vs every other run" is a real architectural shift.

### Recommendation

Start with Option A (the aggregator). It pays for itself in two hours, gives us the submission artifact, and unblocks the FN-fix narrative without touching the agent. Promote to Option B if we ship a v2.

- [ ] Decide A / B / C.
- [ ] For Option A, sketch the script (no code yet) and mark this runbook complete.
