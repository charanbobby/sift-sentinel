# Known limitations

**Last updated:** 2026-04-27
**Scope:** failure modes the team identified during Slice 5 and Slice 6 work, the fixes shipped where applicable, and the gaps left open for the submission window.

Per the hackathon brief, "failure modes = signal, not weakness." This document is the honest version of that: every entry below is something we caught, decided how to handle, and either fixed in code or carried as a labeled gap. Read it as a companion to `accuracy-report.md`. The accuracy report says how the pipeline scored; this one says what it cannot yet do, and why.

---

## 1. Parser silent-failure class (winlogon_tln + four other tools)

**Investigative question:** when the agent says "no persistence found in the Winlogon Registry hive," is that a real negative result, or did the tool silently fail and the agent never noticed?

### What we observed

Across 6 demo runs in late April 2026, the RegRipper plugin `winlogon_tln` was returning empty stdout when invoked against the SOFTWARE hive on the SRL-2018 workstation cases. The pipeline treated the empty output as a legitimate "the plugin ran cleanly with nothing to report" signal. None of the Critic rules escalated because the parser status code was `ok` / `empty`, not `parse_error`. The investigator-facing finding said "no persistence at this Registry path." That conclusion was uncited and, more importantly, untestable: the plugin had not actually examined anything.

### Why the bug was easy to miss

`winlogon_tln` is one plugin in a per-plugin RegRipper registry of seven. The other six were producing real output on the same runs. The single silently-failing plugin disappeared into the noise of "we got data from RegRipper, things are fine." Nothing in the Critic layer was watching for tool-by-tool success.

### How we fixed it

The fix lives at [`pipeline/mcp/parsers.py`](../../experiments/slice-2-notebook/pipeline/mcp/parsers.py). The pattern is the same in five places: a tool that always prints something on a successful invocation should treat empty stdout as a `parse_error`, never as a legitimate empty result. Critic rules R_06 (Negative-Result-Metadata) and R_12 (Evidence-of-Absence vs Absence-of-Evidence) both escalate on `parse_error`, so flipping the status code is enough to make the silent failure visible.

The five parsers we touched:

| Parser | Old behavior on empty stdout | New behavior | Why empty cannot be legitimate |
|---|---|---|---|
| `parse_regripper` | `ok` (silent miss) | `parse_error` | rip.pl always prints a "Launching <plugin>" banner |
| `parse_fsstat` | `empty` | `parse_error` | fsstat always prints File System Type / Cluster Size / MFT location |
| `_parse_vol_pslist` | `empty` | `parse_error` | the System process always exists in any real memory dump |
| `_parse_vol_cmdline` | `empty` | `parse_error` | every running process has a command line |
| `_parse_vol_dlllist` | `empty` | `parse_error` | every process has loaded DLLs |

Two Volatility plugins were left alone because empty output from them is a real clean-host signal, not a tool failure:

- `_parse_vol_malfind` keeps `empty` as a legitimate status. A clean host has no shellcode injection hits.
- `_parse_vol_netscan` keeps `empty` as a legitimate status. A host with no open sockets at acquisition time produces zero rows.

The dispatcher at [`parse_volatility`](../../experiments/slice-2-notebook/pipeline/mcp/parsers.py#L770) holds the per-plugin classification in `_VOL_EMPTY_LEGITIMATE = {"malfind", "netscan"}`.

### What this changes for an investigator

Before the fix, a HUMAN_REVIEW status meant "the LLM was uncertain." After the fix, HUMAN_REVIEW also surfaces "a tool we relied on did not actually run." The status code is the only reliable signal: a Critic rule with logic about empty stdout per plugin would be brittle and out of place; classifying at the parser level keeps the boundary clean.

### What this does not catch

- Tool exit code 0 with garbage on stdout. The parser will return `parse_error` if the format does not match, so the same escalation path applies.
- A tool that prints something benign on every invocation regardless of whether it actually examined the target. RegRipper does this for some plugins (the "has no values" / "not found" paths), so we keep a status of `ok` with zero entries when the plugin emits one of those phrases. A genuine wedge case here would be a plugin that printed "has no values" on a hive it did not actually open. We have not seen this in practice, but it is theoretically possible and would not be caught.
- Statistical anomalies. A Critic rule that compared "tool X usually returns N rows for hosts of class Y, today it returned 0" would catch context-anomalous failures. That is a real future-work item; we did not build it.

---

## 2. dlllist bundle-trim survived its own ablation

**Investigative question:** the pipeline trims the Volatility `dlllist` output before sending it to the analysis LLM, keeping only DLL entries for processes the upstream layers already flagged as suspicious. Does that trim cost us coverage on real findings?

### What we did

We added an `ABLATION_NO_DLLLIST_TRIM=1` environment flag to the bundle builder in [`pipeline/nodes.py`](../../experiments/slice-2-notebook/pipeline/nodes.py) and re-ran an existing case (wkstn-05, run 008) with the trim disabled. The trim is in place because dlllist on a Windows DC produces a 500+ KB connection table of DLL paths for every running process, of which the analysis LLM only needs the entries for the small set of PIDs already flagged.

### What we found

| Configuration | Findings | Specificity of mechanism description | Terminal status |
|---|---|---|---|
| Trim on (production default, run 007) | 6 | Specific PID + DLL path for each finding | SUCCESS (auto-commit) |
| Trim off (ablation, run 008) | 5 | Less specific, more "process X loaded suspicious DLLs" without naming the DLL | HUMAN_REVIEW |

This is one data point, not a measurement. Treat it as a smoke test, not a benchmark.

### What we read into it

The trim is acting as a focusing mechanism, not a coverage gap. With trim off, the LLM had more raw material but produced fewer findings, less specific findings, and escalated to HUMAN_REVIEW. The most plausible explanation is that the unfiltered dlllist drowned the LLM in DLL paths from clean processes and made it harder to attach a specific DLL to a specific suspicious PID.

### What this does not prove

- Whether the trim ever silently drops a finding the unfiltered version would catch. To prove that, we would need ground truth on a case where dlllist evidence is essential and an attacker happens to reside in a PID our upstream layers do not flag. We do not have such a case in the bounded Reference Dataset.
- Whether the trim's PID filter is the right one. The current logic filters to "PIDs flagged by an upstream tool in this run." A more conservative filter would also include all child processes of suspicious PIDs. We did not test that variant.

---

## 3. fls_list and icat_extract have an honest ambiguity in stdout-only mode

**Investigative question:** when `fls_list` returns nothing on a directory, did the directory exist and have no entries, or did the tool fail to read it?

### The ambiguity

`fls` (from The Sleuth Kit) prints one line per file in a directory and exits 0. There is no banner, no header, and no "directory has zero entries" sentinel. Three different states all produce empty stdout with exit code 0:

1. The directory exists and is genuinely empty.
2. The directory does not exist.
3. The directory exists but the tool could not enumerate it (FUSE permission issue, sparse / missing inode, NTFS attribute the tool does not understand).

The same shape applies to `icat_extract`: `bytes_written = 0` could mean the file is genuinely zero bytes, or the inode pointed at unallocated space, or the attribute marker did not resolve.

### What we shipped

Both parsers currently classify empty stdout as `empty` (legitimate). This is wrong in cases 2 and 3, but right in case 1. We did not change them in the parser silent-failure pass for one reason: distinguishing the three states would require either parsing stderr (which is not currently captured per call) or running a probe sibling command (e.g., `mmls` on the parent inode) before each call. Both add complexity outside the hackathon scope.

### What this means downstream

A NOT_FOUND finding sourced from an empty `fls_list` or zero-byte `icat_extract` carries the same uncertainty. The pipeline mitigates this through R_06 (Negative-Result-Metadata) which requires the structured fields to list the paths actually examined, but the underlying primitive cannot tell us whether the tool truly examined them or silently bailed.

### What we would do with more time

Add a `_run_and_record` enhancement that also captures stderr per call, then have the fls and icat parsers consult stderr for known "permission denied" / "no such file or directory" / "attribute not found" patterns. This is a roughly half-day change, scoped out of the hackathon window.

---

## 4. Synthetic adversary-AI workstation is future work

**Investigative question:** we recalibrated the injection guard on 2026-04-27 (decode-then-scan instead of "any long base64 = quarantine"). How do we know it actually catches AI-era injection attempts?

### The validation gap

The 2018 SANS dataset we used through Slice 5 and Slice 6 is a high-quality forensic corpus, but it was created before LLMs were a concern. It can produce true negatives for prompt injection (none of those E01s contain injection patterns because the threat did not exist), but it cannot produce true positives for the recalibrated guard. The fix to `INJ_BASE64_LONG` was probe-verified across 6 hand-crafted scenarios, but probes are not the same as a forensic image.

### What we designed

A staged synthetic adversary-AI workstation built reproducibly inside the existing `sift-mcp` container. Five layers of injection sophistication, plus an offensive-AI tradecraft layer (LLM API calls in netscan, prompt history files, AI-generated PowerShell fingerprints), plus a clean dev workstation as the negative control. The toolchain (raw to NTFS to E01 inside the existing container) is probe-verified. The design lives in [`memory/project_synthetic_ai_workstation_design.md`](../../memory/project_synthetic_ai_workstation_design.md).

### What we did not build

The workstation itself. It is a 2 to 3 hour focused build session of its own and was not on the critical path for the Slice 5 / Slice 6 architectural work. Three open decisions (cinematic incident vs collection of independent artifacts, which threat family to mimic for the offensive-AI layer, target finding count) are documented and ready to pick up.

### What this means for the submission

The recalibrated injection guard ships in the submitted code, with the decode-then-scan logic documented and unit-tested. We claim it correctly handles the cases it was designed for, but we cannot claim a measured precision / recall against a real AI-attacker corpus in the submission window. The synthetic workstation is named in the future-work section of the accuracy report so a reader knows exactly what evidence is missing and what we would do with it.

---

## How to read this document at submission time

Each of the four entries above falls into one of three buckets:

- **Caught and fixed** (parser silent-failure): the bug was real, the fix is shipped, and the document is here so a reviewer can audit the decision.
- **Tested and labeled** (dlllist trim): the production choice survived a deliberate ablation, with the size of the test sample stated honestly.
- **Acknowledged gap** (fls / icat ambiguity, synthetic workstation): the limitation is real, the workaround we would build is named, and the scope reason for not building it is on the page.

What is not in this document: failure modes we have not yet noticed. The pipeline has been exercised on roughly 10 cases across the SRL-2018 corpus and DFIR Madness Case 001. A larger or more adversarial corpus would surface more limitations. The Reference Dataset for the submission is bounded by design; recall on out-of-distribution attacker behavior is unmeasured.
