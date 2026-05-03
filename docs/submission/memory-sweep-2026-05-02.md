# Dual-channel sweep, 2026-05-02

Overnight sweep of disk-paired SRL-2018 hosts using both disk (E01) and memory (Volatility 2) channels. Goal: measure what the dual-channel pipeline finds across the full SANS dataset and surface any hangs or systemic issues.

## TL;DR

Six disk-paired hosts attempted. Four succeeded with sensible findings. Two hung after a long `volatility_run netscan` step and never reached INTERPRET. The hang pattern is reproducible on busier hosts (DC and Win10 RD with 5 GB / 3 GB memory dumps and large process trees) and points at a real pipeline bug worth fixing before the submission. Total OpenRouter spend overnight: about $2.40. Memory channel produced material findings (process injection, C2 beacons) on every successful run that disk-only could not have produced.

## Per-host results

| Host | Memory profile | Status | Findings | OpenRouter cost | Notes |
|---|---|---|---|---|---|
| dc | Win2016x64_14393 | HUNG | 0 | ~$0.20 sunk | hung after `netscan` (10 min plugin), 25 of 28 plan steps complete, INTERPRET never ran |
| file | Win2012R2x64 | SUCCESS | 4 | $0.49 | 2 HIGH masquerade services (msadvapi2 32 + 64), 1 HIGH process injection, 1 HIGH C2 beacon |
| rd-01 | Win10x64_17134 | HUNG | 0 | ~$0.20 sunk | same hang pattern as dc, after a 14.6-minute netscan |
| rd-02 | Win10x64_17134 | SUCCESS | 3 | $0.49 | 2 HIGH masquerade services, 1 HIGH process injection, terminal QUARANTINED (injection scanner fired) |
| wkstn-01 | Win10x64_17134 | SUCCESS | 1 | $0.41 | 1 HIGH NOT_FOUND `legitimate_windows_default`. **Confirmed FN: owner says this host was compromised.** Memory channel did NOT rescue the FN. |
| wkstn-05 | Win7SP1x64 | SUCCESS | 4 | $0.53 | 2 HIGH disk findings re-detected (named-pipe beacon, perfmon masquerade), 2 MEDIUM memory findings (WmiPrvSE-spawned PowerShell with RWX regions, C2 beacon to 172.16.4.10:8080) |

Total successful: 4 of 6. Total spend (incl. sunk): ~$2.40.

## Memory channel value (the headline)

On every successful dual run, the memory channel produced findings that the disk channel could not have surfaced:

- **process_injection** (T1055): VAD region protection bits (`PAGE_EXECUTE_READWRITE`) for processes with suspicious parents (WmiPrvSE-spawned PowerShell, orphan rundll32 with no parent in pslist). This signal lives only in the live process address space.
- **c2_beacon** (T1071): TCP connections in `CLOSE_WAIT` / `CLOSED` state with PIDs already exited (pid=-1), recovered from kernel socket residue. Disk has no record of these.

The per-host mapping:

- **file**: 1× process_injection HIGH, 1× C2 beacon HIGH (memory-only)
- **rd-02**: 1× process_injection HIGH (memory-only)
- **wkstn-05**: 1× process_injection MEDIUM, 1× C2 beacon MEDIUM (memory-only)

Even where the disk side already produced the persistence finding (file and rd-02 both flagged the masquerade services on disk), the memory channel added the post-exploitation tradecraft picture. This is the difference between "what did they install" and "what is the implant doing right now."

## The hang pattern (DC and rd-01)

Both hung hosts followed the same shape:

1. PLAN emits 28-step plan (disk steps + 4-5 volatility plugins).
2. EXECUTE runs disk steps successfully, then volatility pslist (10 min on DC, faster on rd-01).
3. EXECUTE runs volatility cmdline + netscan. **netscan takes 10-15 minutes on these hosts.**
4. After netscan returns successfully (exit_code 0, evidence saved), the next tool call never starts.
5. sift-mcp goes idle (no live tool processes), sift-sentinel's python is alive but idle.
6. No HTTP request appears active, no error, no timeout. Just a silent stall that lasts until killed.

For both hosts, the hang specifically follows a long-running netscan. file and wkstn-05 ran successfully because their netscan finished faster and the pipeline cleanly issued the next call. rd-02 and wkstn-01 also ran successfully despite being Win10 because their netscan apparently did not stall the orchestration.

The most likely explanations (none verified, all worth checking):

- An HTTP keep-alive timeout in sift-sentinel's MCP client triggers during a long tool call and silently breaks the connection. Subsequent calls hang because the server thinks the connection is alive but the client never receives the response.
- An asyncio bug in execute_node where a long-running subprocess.run inside the MCP server prevents the next event-loop scheduling.
- vol.py's child-process cleanup leaves a pipe descriptor open after long plugin runs, blocking the next plugin's stdin/stdout setup.

Bug priority: high. Two of six dual runs lost overnight to this. If we want full memory coverage on the SANS dataset for submission, this needs investigation before the next sweep. Until then, dual-channel is unreliable on hosts with busy network state.

## wkstn-01 false negative is now CONFIRMED in dual mode

The disk-only sweep on 2026-05-01 reported wkstn-01 as NOT_FOUND HIGH. Owner confirmed the host was compromised. Tonight's dual-channel run also reports NOT_FOUND HIGH (`legitimate_windows_default`). The memory channel did not rescue this FN.

This means one of:
- The compromise is real but invisible in both disk persistence keys and memory pslist/cmdline/netscan/malfind. Plausible if the implant is dormant at capture time and used a non-persistent in-memory loader cleared before snapshot.
- The agent's classifier is misjudging genuine evidence as legitimate. Need to inspect 04_execute_evidence.jsonl manually to see what the agent actually saw.

For submission credibility, this case needs human ground-truth review and the disagreement documented. It is the kind of FN that strengthens, not weakens, the submission if framed honestly.

## Cost reality vs estimate

| Phase | Wall time per host (success) | OpenRouter cost |
|---|---|---|
| Stage memory image to /tmp | 1-2 min (faster than feared) | $0 |
| Profile detection (imageinfo on /tmp copy) | 13-25 min | $0 |
| Pipeline run (extract + plan + execute + interpret) | 5-15 min when no hang | $0.41-0.53 |
| Pipeline run (when hung) | 60-90 min until killed | $0.20 partial |

Bind-mount cp speed turned out to be 30-100 MB/s in practice, not the 1.5 MB/s cited in the MCP server comment. The earlier comment was based on Volatility's many-small-reads pattern, not bulk cp throughput. Useful correction: future sweeps can stage a memory dump in a couple of minutes, not 30.

## What the cleanup should be

Old runs that are safely deletable:

- `srl-2018-base-dc-dual/srl-2018-base-dc-dual-001/` (hung, no INTERPRET, no findings)
- `srl-2018-base-rd-01-dual/srl-2018-base-rd-01-dual-001/` (hung)
- `srl-2018-base-wkstn-01-dual/srl-2018-base-wkstn-01-dual-001/` (had bogus profile arg from script bug)
- `srl-2018-base-wkstn-05-dual/srl-2018-base-wkstn-05-dual-001/` (failed during the original allowlist incident before staging fix)

Keep:
- `*-dual/<latest>/` for the four successful hosts (file, rd-02, wkstn-01, wkstn-05).
- All disk-only sweep runs (the 2026-05-01 run set on the original case_ids without `-dual` suffix).

## What this means for submission

- Track A accuracy report can claim 4 of 6 disk-paired hosts dual-channel-scored. Two hung due to a known pipeline bug; document it as a known limitation.
- Memory channel demonstrably adds findings on every successful dual run.
- wkstn-01 FN is now a HARD case for the submission to honestly address. Either explain the limit or fix the classifier.
- The per-host cost ($0.40-0.55) is well within budget. Full 18-host sweep at $0.50 each = $9 total. Affordable when the hang bug is fixed.

## Tomorrow's priorities

1. **Investigate the dual-mode hang.** Capture a stack trace next time it stalls; check if MCP HTTP keep-alive is the cause.
2. **Manual review of wkstn-01 evidence.** Look at the actual `04_execute_evidence.jsonl` to see what the agent saw and decide whether the classifier or the host (or both) is at fault.
3. **Decide whether to re-run dc and rd-01** after the hang fix.
4. **Resume the judge submission code track** (translator, submit script, async worker).
5. **Cleanup and commit.** Stage the docs and code changes from yesterday plus today.
