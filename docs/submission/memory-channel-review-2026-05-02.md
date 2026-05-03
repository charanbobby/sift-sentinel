---
created: 2026-05-02
purpose: Separate from the findings second-opinion brief. Memory work has higher cost variance, so we want a fresh LLM to sanity-check what we have probed before we kick off the 13-host standalone memory sweep.
---

# Memory-channel review: what we probed, what we did not, what could go wrong

## Section 0: Question for the reviewing LLM

We are about to run our memory-only triage pipeline on 13 standalone Windows memory dumps from the SANS 2018 lab. Estimated cost is around 5 dollars OpenRouter total (~0.40 per host) and 7-10 hours wall time. We want you to look at what we have probed and validated so far, and tell us:

1. **Are we missing a probe that would catch a high-leverage bug before we burn the budget?**
2. **Are there host types in the queue (Domain Controller, mail server, SharePoint, AV server) where our prompts and tool surface are likely to behave differently from the workstation we smoke-tested on?**
3. **Is our cost reasoning sound, or are there scenarios where a single host could blow past 0.40?**
4. **What additional cost guards should we add before running?**

## Section 1: What memory-channel work has shipped (with the probe that validated it)

### 1a. Tool surface: the 5 Volatility 2 plugins
- `pslist`: process tree (PID, PPID, threads, start time)
- `cmdline`: full command line per process
- `netscan`: TCP/UDP connections (proto, local, foreign, state, owner)
- `dlllist`: loaded modules per process (HIGH VOLUME, gated)
- `malfind`: memory regions with anomalous protection (PAGE_EXECUTE_READWRITE, etc)

Validation: each of these has been called by the agent across the 6 dual-channel runs. Tool counts per run, with evidence-file size:

| Host | evidence size (KB) | pslist | cmdline | netscan | malfind | dlllist |
|---|---|---|---|---|---|---|
| dc | 2562 | 1 | 1 | 1 | 1 | 0 |
| file | 1741 | 1 | 1 | 1 | 1 | 0 |
| rd-01 | 2298 | 1 | 1 | 1 | 1 | 0 |
| rd-02 | 2281 | 1 | 1 | 1 | 1 | 0 |
| wkstn-01 | 2281 | 1 | 1 | 1 | 1 | 0 |
| wkstn-05 (dual) | 1673 | 1 | 1 | 1 | 1 | 0 |
| wkstn-05 (memory-only smoke) | 853 | 1 | 1 | 1 | 1 | **1** |

Note: in dual mode, the agent never called `dlllist` (the cost-guarded plugin). In memory-only mode it called it once (on a flagged PID, which is the rule). This is a behavior shift to watch.

### 1b. Memory-channel guidance in the EXTRACT prompt
Sources: `_MEMORY_GUIDANCE` (dual mode) and `_MEMORY_ONLY_GUIDANCE` (memory-only mode).

Both tell the LLM to propose memory-channel artifact_types: `process_anomaly`, `network_connection`, `injected_region`, `dll_load_anomaly`. `_NO_MEMORY_GUIDANCE` (disk-only) explicitly forbids those types.

`_MEMORY_ONLY_GUIDANCE` additionally forbids disk artifact_types in memory-only mode so the LLM cannot propose a registry-hive candidate that has no executor.

Validation: a regression probe (`probe_memory_only_prompts_2026-05-02.py`) byte-checks that the disk-only and dual EXTRACT prompts have not regressed, plus asserts the memory-only EXTRACT contains the right tokens (process_anomaly, network_connection, injected_region) and omits the disk-channel sections (Universal Windows persistence locations, File-drop staging, Web-shell drop). The probe passes.

### 1c. Memory-channel rules in the PLAN prompt
Section: `Memory-evidence rules` block, only rendered when `has_memory=True`. Pinned rules:
- `pslist` MUST be planned first; other plugins must depend on it
- `dlllist` MUST be gated by a triggering signal (malfind hit OR suspicious cmdline OR unexpected parent-child)
- `dlllist` is forbidden as a sweep over all processes
- Typical memory triage shape: 5 steps (pslist, cmdline, netscan, malfind, optional dlllist for flagged PIDs)
- LITERAL `memory_image` and `memory_profile` MUST come from case constants (no LLM invention)

In memory-only mode, the disk-only sections of the PLAN prompt are gated away (Argument templating, Filesystem navigation, Hard rules for hive-extract chains). The schema enum is also filtered to only advertise tools the channel mix actually supports (so a memory-only run cannot emit a `regripper_run` step that would have no executor).

Validation: the same probe as 1b also covers the PLAN prompt. It byte-checks legacy modes for regression and asserts memory-only PLAN omits `Argument templating`, `Filesystem navigation`, `icat_extract`, `regripper_run`, `fls_list`, `/Windows/System32/config`, and the `e01_path:` constant. The probe passes.

### 1d. Cost guards specific to memory
Two are in place:
- `dlllist` is restricted by the PLAN rules above. The dual sweep saw zero dlllist calls; the memory-only smoke saw one (within the rule).
- `netscan` output trimming: the `volatility_run` MCP tool side already filters out connection records on listening sockets and other low-signal entries before returning structured fields. (This was a fix from 2026-04-26 after a 519 KB / ~130k-token spike on a Domain Controller netscan.)

What we have NOT explicitly guarded:
- `pslist` size on hosts with very large process counts (a domain controller in production can have 200+ processes; 7 of our 13 standalone hosts are unknown role).
- `cmdline` size when many processes have very long argv (fileserver / sql-server processes can have multi-KB cmdlines).
- The total INTERPRET bundle size when ALL plugins return non-trivial output. We have not measured this on a host larger than wkstn-05.

### 1e. Hang fix
The MCP client `streamablehttp_client` had a 300s SSE read timeout that broke the stream when a Volatility plugin ran longer than 5 minutes (netscan on a busy Win10 host took 14+ minutes during the original sweep). Fix: lifted to 3600s (`pipeline/nodes.py:1259`). Validated end-to-end on dc retry (28/28 steps, no hang).

This matters for the standalone sweep because mail server (2.7 GB dump) and SharePoint (953 MB) likely have longer netscan runs than the workstations we have measured.

### 1f. Placeholder-resolver tolerance
Independent issue: the LLM sometimes emits placeholders with double braces (`{{step:N.foo()}}`) instead of single (`{step:N.foo()}`). Fix: regex now matches 1 or 2 braces on each side. Validated on a 7-case probe.

This is mostly a disk-channel concern (memory plugins do not use the placeholder DSL) but the fix is in place if it ever shows up in memory steps.

### 1g. Memory-only mode end-to-end smoke test
Single run: `srl-2018-base-wkstn-05-memonly` against the staged `/tmp/base-wkstn-05-memory.img` with profile `Win7SP1x64`. Result: terminal SUCCESS, 3 findings (2 process_injection + 1 c2_beacon), evidence file 853 KB, ran in ~5 minutes wall time. The LLM correctly did not emit any disk artifact_type candidates, and the schema enum filter held.

### 1h. Cross-host aggregator
Now picks up memory-only run dirs alongside dual run dirs. Confirmed with the in-flight smoke test data.

## Section 2: What we have NOT probed (and the risk each one carries)

### 2a. Profile detection (vol.py imageinfo) accuracy
Each standalone host needs `imageinfo` to detect its Volatility 2 profile. The runner script (`scripts/standalone_memory_sweep.sh`) parses the first suggested profile from the imageinfo output. We have not validated:
- Hosts where imageinfo returns multiple plausible profiles (e.g., Win10 vs Win10x64_17134 vs Win10x64_19041). Picking the wrong revision can break later plugins.
- Hosts where imageinfo fails (corrupted dump, truncated dump, non-Windows OS). The runner skips on failure but does not auto-recover.
- Time cost: imageinfo can take 13-25 minutes per host on dumps over 1 GB. The 13 hosts may total 3-4 hours of imageinfo wall time alone.

### 2b. Volatility plugin compatibility on uncommon hosts
We have run plugins against:
- Win7x64 (wkstn-05 only)
- Win10x64_17134 (wkstn-01, rd-02, rd-01)
- Win2012R2x64 (file)
- Win2016x64_14393 (dc)

The standalone queue includes likely Win Server 2008/2012/2016 variants (mail, sp, av) and possibly older OS families where Volatility 2 plugin output schema can shift. Each plugin output is parsed by our MCP server into structured fields; if a plugin emits an unexpected column, the parser falls back to `parse_error` and the agent loses signal.

### 2c. Memory-only mode on non-workstation hosts
The smoke test ran on a workstation. We have not validated memory-only mode on:
- A Domain Controller (different host_type guidance, different baseline process names)
- A mail server (Exchange has unique processes the agent has not seen before)
- A SharePoint server (web/sql-mixed)
- An AV server (legitimate AV processes look like attacker tradecraft to a naive classifier)

The host_type-specific guidance in `_HOST_GUIDANCE` is currently a TODO for memory-only mode (we drop it in `_build_extract_prompt` when has_disk=False). The memory-only EXTRACT prompt currently has zero host_type tailoring. That may produce more generic findings on non-workstation hosts.

### 2d. Long netscan runtime in memory-only mode
We hit the 300s SSE timeout on dc and rd-01 in dual mode and lifted it to 3600s. We have NOT measured netscan runtime on:
- mail server (2.7 GB dump, likely >100 active connections)
- av server (2.1 GB dump)
- sp (SharePoint, web traffic heavy)

Risk: even with the 3600s timeout, a netscan that takes >1 hour will time out. Cost guard: probably set a 1.5x safety margin or accept that a few hosts may need a re-run with longer timeout.

### 2e. dlllist cost behavior in memory-only mode
The smoke test saw one dlllist call (vs zero in any dual run). The dlllist plugin output is high-volume per process; a single dlllist call on a process with 200+ loaded DLLs produces a large structured field (multi-KB). The memory-only-mode behavior of "call dlllist when triggered" may fire more often when the LLM is under less competing-budget pressure. We have not measured the worst case.

### 2f. INTERPRET bundle size on big hosts
Our INTERPRET bundle is built from all `structured_fields` from EXECUTE steps. We have measured this on 7 hosts with 5 memory plugins each. We have not measured on:
- Hosts with 200+ processes in pslist (DC-class)
- Hosts with very long cmdlines (database / antivirus)
- Hosts where malfind hits 50+ regions (heavy injection)

A single host could plausibly produce a 200-300 KB INTERPRET bundle, which is ~75k tokens of input at our typical Sonnet cost. That is around 0.20-0.30 just for one INTERPRET call.

### 2g. False-positive regripper alerts on standalone memory-only hosts
Memory-only mode does not call regripper, so the Win10 winlogon_tln false positive does not apply. Good.

### 2h. Injection-guard quarantines
Three of six dual runs ended in `terminal=QUARANTINED` because raw bytes containing the literal token `T1033` triggered our injection scanner. The cause was the extracted SOFTWARE hive itself (regripper banner + raw hive bytes). Memory-only mode does NOT extract registry hives, so this specific false-positive class should not fire. But other byte-patterns might.

### 2i. Synthetic AI-attacker memory dumps
We do not have a synthetic dump where we KNOW what the answer should be. All validation has been against real lab data with no answer key. A reviewer might ask: "how do you know the agent did not silently miss persistence on memory-only mode?"

## Section 3: Cost reasoning, with token measurements

For wkstn-05 memory-only smoke test:
- Evidence file size: 853 KB
- Approximate token count (4 chars per token rule of thumb): ~213k tokens
- Realistic OpenRouter cost at Sonnet 4.6 input rates ($3/M tokens): around 0.30 per INTERPRET call, plus EXTRACT (~0.05) and PLAN (~0.10) and CRITIC (~0.05) = roughly 0.40-0.50 total.

Per-host estimate of 0.40 is the OPTIMISTIC case. Risk factors:
- DC-class hosts: 200+ processes -> larger pslist + cmdline -> bundle could hit 400-500 KB -> ~0.60-0.80 per host.
- Mail server: extremely large netscan -> bundle could hit 500-700 KB -> ~0.80-1.00 per host.
- A retry pass (if INTERPRET emits an out-of-schema finding) doubles the INTERPRET cost.

Worst case for 13 hosts:
- 8 small hosts at 0.40 = 3.20
- 3 medium hosts at 0.60 = 1.80
- 2 big hosts (mail, av) at 1.00 = 2.00
- Total: ~7.00, with a retry pass on 2 of them adding maybe 0.50 more.

Upper bound: about 8 dollars. Lower bound (no surprises): about 5 dollars.

## Section 4: Specific risks for the 13-host standalone sweep

Listed by severity, highest first:

1. **Imageinfo failure on a corrupted dump**. The runner skips that host. We then have a coverage gap. Mitigation: log the imageinfo output and let the operator pick the profile manually for failed hosts.
2. **Wrong profile picked**. Imageinfo can return multiple suggestions; we take the first. If the first is the SP1 profile but the dump is SP2, all subsequent plugins fail with `parse_error`. Mitigation: ask the operator to confirm the profile when there are multiple suggestions.
3. **netscan or pslist takes >1 hour on a busy server**. Times out even with the 3600s fix. Mitigation: log the start time per plugin; consider a 7200s timeout for known-large hosts.
4. **INTERPRET bundle blows past 500 KB on a busy host**. Cost overshoots estimate. Mitigation: add a pre-INTERPRET size measurement and trim per-PID dlllist output if total is above 300 KB.
5. **Memory-only host_guidance is generic**. Findings on mail / SharePoint / DC may miss role-specific tradecraft. Mitigation: add memory-only host guidance per host_type (currently a TODO).
6. **base-elf is Linux**. The runner script omits it explicitly. Confirmed.
7. **Volatility 2 profile incompatibility on Win Server 2019 / 2022**. We have not seen one in the dataset, but if present, our profile list may not cover it. Mitigation: log "imageinfo could not parse" and skip.

## Section 5: What we would still like the reviewing LLM to flag

- Probes we should add before running. For example: a worst-case bundle-size probe on the largest available memory dump (`base-mail-memory.img` at 2.7 GB extracted), measuring evidence file size and predicting INTERPRET bundle size.
- Cost guards we should add. For example: a "hard ceiling on combined plugin output" check in the MCP server before returning structured fields.
- Plugins we should NOT enable yet. For example: should we disable dlllist entirely on the first standalone sweep until the cost-guard behavior is validated?
- Sequencing decisions. For example: should we run small hosts (rd-05, rd-06, wkstn-06 at ~500-600 MB) first as a second smoke test before turning loose on the bigger ones?

## Section 6: What we are confident about

- The PLAN and EXTRACT prompts are byte-equality-checked against gold for legacy modes. Memory-only mode passes additional structural assertions.
- The schema enum filter prevents the LLM from emitting tool calls that have no executor in memory-only mode.
- The hang fix is validated end-to-end on a 5 GB DC dump.
- The placeholder-resolver tolerance is validated on 7 input shapes.
- The memory-only smoke test produced sensible findings (matched the dual run's process_injection + c2_beacon on the same host) with terminal SUCCESS.
- The cross-host aggregator picks up memory-only runs alongside dual runs.

End of brief.
