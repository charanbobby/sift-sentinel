---
created: 2026-05-09
status: open
host: local Docker only (sift-sentinel + sift-mcp on D:); VPS reserved for the daily cron loop
dataset: SRL-2015 (SANS hackathon, Apr 2015 evidence)
---

# SRL-2015 pipeline runs (local Docker)

## TL;DR

Recommended starter case: **xp-tdungan**. It has the smallest disk image at 15.4 GB, a clean 2 GB memory dump, and the simplest OS (Windows XP SP3) in the bundle, so EXTRACT and PLAN have less surface to scan and the run finishes faster than the other three hosts. Run it disk-only first to confirm the pipeline likes the converted .raw image, then come back later for a dual-channel run if you want memory coverage. Each run lands in OpenRouter spend territory of roughly $0.30 to $0.80 based on the closest comparable case (openuni22-server-cdrive total run_cost $0.81 on a similar 50 GB Windows server image).

Do **not** blast all four hosts in one sitting. Pick one, read the findings, then decide whether to spend on the next.

## What we're testing

SRL-2015 is the older SANS challenge dataset (Stark Research Labs Data Breach Intrusion, acquired April 2012, packaged for the FOR508 USB in 2015). It is materially different from the rest of our corpus:

- **Different forensic profile from SRL-2018.** SRL-2018 is a multi-host enterprise sweep (base-dc, base-file, base-rd-*, base-wkstn-*) where most images are Win10/Server 2016 and ground truth is built on modern artifacts. SRL-2015 is older Windows (XP SP3, Win7 SP1 32/64-bit, Win Server 2008 R2), which exercises different RegRipper plugins, older NTLM credential stores, pre-AppLocker autoruns, and a much smaller default scheduled-task set.
- **Different from OpenUni22.** OpenUni22 is one downloaded server image with .huggingface artifacts and a Sysinternals PsExec scheduled task; the only finding so far is a single medium-confidence PsExec entry. SRL-2015 is a four-host realistic intrusion across a domain controller and three workstations on the 10.3.58.x subnet.
- **MCT challenge dataset.** The .E01 acquisition descriptions (`Stark Research Labs Data Breach Intrusion`) confirm this is the canonical hackathon-flavored breach scenario; running it on the pipeline gives us a credibility data point alongside SRL-2018.

What we want to learn:

1. Does EXTRACT pick reasonable candidates on an XP-era disk where `C:\Users\` is `C:\Documents and Settings\`?
2. Does PLAN drift on Win2008R2 vs Win7 (different default scheduled-task layout, different NTUSER.DAT locations)?
3. On dual-channel runs later, does the Volatility profile autodetect work for these older images, or do we need to pin profiles?

## Per-host inventory

All disk images are converted .raw files staged at `/mnt/derived/` inside the sift-mcp container. Memory dumps are raw .001 files staged in their original SANS layout under `/mnt/hackathon/srl-2015/`. MD5s come from `_provenance.md`.

| Host | OS | Disk image (host) | Disk image (container) | Memory dump (container) | Pipeline mode | case_id slug |
|---|---|---|---|---|---|---|
| xp-tdungan | Windows XP SP3 | `HACKATHON-2026/derived/xp-tdungan-c-drive.raw` (15.4 GB, MD5 `60b778a1...`) | `/mnt/derived/xp-tdungan-c-drive.raw` | `/mnt/hackathon/srl-2015/xp-tdungan-10.3.58.7/xp-tdungan-memory/xp-tdungan-memory-raw.001` (2 GB) | disk-only first, dual later | `srl-2015-xp-tdungan` |
| win7-32-nromanoff | Win7 SP1 x86 | `HACKATHON-2026/derived/win7-32-nromanoff-c-drive.raw` (25.4 GB, MD5 `e381e006...`) | `/mnt/derived/win7-32-nromanoff-c-drive.raw` | `/mnt/hackathon/srl-2015/win7-32-nromanoff-10.3.58.5/win7-32-nromanoff-memory/win7-32-nromanoff-memory-raw.001` (2 GB) | disk-only first, dual later | `srl-2015-win7-32-nromanoff` |
| win7-64-nfury | Win7 SP1 x64 | `HACKATHON-2026/derived/win7-64-nfury-c-drive.raw` (28.9 GB, MD5 `a98416e6...`) | `/mnt/derived/win7-64-nfury-c-drive.raw` | `/mnt/hackathon/srl-2015/win7-64-nfury-10.3.58.6/win7-64-nfury-memory/win7-64-nfury-memory-raw.001` (2 GB) | disk-only first, dual later | `srl-2015-win7-64-nfury` |
| win2008R2-controller | Win2008 R2 x64 (Domain Controller) | `HACKATHON-2026/derived/win2008R2-controller-c-drive.raw` (31.8 GB, MD5 `3a33c416...`) | `/mnt/derived/win2008R2-controller-c-drive.raw` | `/mnt/hackathon/srl-2015/win2008R2-controller-memory/win2008R2-controller-memory-raw.001` (2.7 GB) | disk-only first, dual later | `srl-2015-win2008R2-dc` |

Notes on the table:

- The `c-drive` raws are logical-drive NTFS images, not full-disk images. They were produced by `ewfexport -u -f raw` from the source .E01s on 2026-05-07 (see `HACKATHON-2026/derived/_provenance.md`). The pipeline's `fsstat_e01` step works directly on these; no partition slicing needed (unlike the openuni22 full-disk image, which needed a `dd skip=...` to extract C:).
- Memory dumps are FTK-Imager raw `.001` outputs from 2012; treat them as Volatility 2 inputs with profile autodetect via `imageinfo`.
- The Win2008R2 memory file lives at `HACKATHON-2026/srl-2015/win2008R2-controller-memory/` (parallel to the `win2008R2-controller-10.3.58.4/` host folder), not nested inside it. The path in the table is correct.

## Step-by-step (disk-only run for one host)

### 1. Container check (read-only sanity)

```
docker ps --format "{{.Names}}\t{{.Status}}"
```

You should see `sift-sentinel` and `sift-mcp` both `Up`. If either is not, `docker compose up -d` from `docker/` first. **Do not** rebuild containers for this runbook; the existing images already have the venv provisioned.

### 2. Confirm the disk image is visible inside sift-mcp

```
docker exec sift-mcp ls -la /mnt/derived/xp-tdungan-c-drive.raw
```

Expect 16,114,483,712 bytes. If size differs, stop and check `_provenance.md`; do not run the pipeline against a corrupted raw.

### 3. Dry-run filesystem stat (optional, single tool call, no LLM)

```
docker exec sift-mcp /workspace/.venv/bin/python -c "from pipeline.tools.tsk import fsstat_e01; print(fsstat_e01('/mnt/derived/xp-tdungan-c-drive.raw')[:400])"
```

This is `<TBD: Charan, the exact import path may not be public; the safe equivalent is plain mmls / fsstat from outside the pipeline>`. If you don't want to bother, skip this step. The `fsstat_e01` step inside the pipeline will tell us in step 1 of EXECUTE whether the raw is parseable.

### 4. Run the pipeline (disk-only, single host, recommended starter)

This is the one command that costs money. Run it once.

```
docker exec sift-sentinel bash -c "cd /workspace && uv run python run_case.py --case srl-2015-xp-tdungan --e01 /mnt/derived/xp-tdungan-c-drive.raw"
```

Output streams to your terminal. The PRE/POST cost lines from EXTRACT, PLAN, INTERPRET print as the run advances; these are the same `_llm_cost_pre` / `_llm_cost_post` helpers you instrumented across the project. Watch for:

- `[extract] POST` near the top: confirms gemini-3-flash-preview answered, ~$0.004.
- `[plan] POST`: confirms claude-sonnet-4-6 emitted a tool plan, ~$0.07-$0.09.
- `[interpret] POST`: the expensive call, ~$0.30-$0.40 on a host with full evidence.
- `run_cost=$X.XX / limit=$1.50` after each LLM call: the running per-process budget cap. The pipeline halts if this exceeds $1.50 mid-run.

If anything triggers a retry pass at INTERPRET (the planner fires again because findings did not satisfy the expected range), expect a second `[plan] POST` and a second `[interpret] POST`; total run cost on that path tracks the openuni22-cdrive ceiling at $0.81.

### 5. Where artifacts land

Inside the container:
- `/workspace/out/runs/srl-2015-xp-tdungan/srl-2015-xp-tdungan-001/` (run dir, sequential)
- `/workspace/out/runs/srl-2015-xp-tdungan/latest.txt` (points at `srl-2015-xp-tdungan-001`)

On the host (since `/workspace` is a bind mount to `experiments/slice-2-notebook/` on D:):
- `experiments/slice-2-notebook/out/runs/srl-2015-xp-tdungan/srl-2015-xp-tdungan-001/`

Files in that directory worth opening first:
- `02_plan_tool_plan.json`: the tool plan EXTRACT + PLAN produced.
- `04_execute_evidence.jsonl`: every tool call's structured output.
- `05_interpret_findings.json`: the structured findings the LLM emitted.
- `07_terminal.SUCCESS` / `.HUMAN_REVIEW` / `.QUARANTINED`: which terminal route the graph took.

### 6. Reading findings (no LLM cost)

```
cat experiments/slice-2-notebook/out/runs/srl-2015-xp-tdungan/srl-2015-xp-tdungan-001/05_interpret_findings.json | jq '.findings | length, [.[] | {category, classification, mechanism, confidence, value}]'
```

Or open the run viewer at `http://localhost:8080/viewer/` if it's running on the local stack and the case is in `keep_runs.json`. New cases are not in `keep_runs.json` until they're explicitly added; for the first SRL-2015 run, read the JSON directly.

### 7. When to stop

Stop after one run and before launching the second host if any of these are true:

- Total `run_cost` exceeds $1.20 on the first run (signals the per-tool size guards may not be holding on this OS).
- The terminal marker is `07_terminal.QUARANTINED` (an injection guard tripped; review the quarantined evidence record before deciding).
- INTERPRET emitted zero findings AND the evidence file shows fewer than 5 successful tool calls (PLAN drift; investigate with the smallest-unit replay before re-spending).
- You're tired or distracted. The pipeline does not get cheaper at 2am.

## Estimated cost per case

Anchored on the closest comparable run we have, openuni22-server-cdrive, which is a 50 GB Windows server image with a similar Persistence question:

- openuni22-server-cdrive total `run_cost`: **$0.81** (32-step plan, 31/32 evidence records, two INTERPRET passes due to findings-range debounce, single medium finding, terminal `HUMAN_REVIEW`).
- openuni22-server total `run_cost`: **$0.12** (halted at fsstat because the input was a multi-partition raw; not a useful comparison, included only to show the early-halt floor).

Expected SRL-2015 ranges, assuming evidence flows normally:

- xp-tdungan: smaller filesystem, fewer scheduled tasks; **estimate $0.30 to $0.50**, but measure on first run.
- win7-32-nromanoff and win7-64-nfury: similar size to openuni22; **estimate $0.40 to $0.80**, measure on first run.
- win2008R2-controller (DC): largest disk, more services, more scheduled tasks, possibly retry pass; **could trip the $1.50 cap if the per-tool guards under-shoot on a DC**. Run it last, after you've calibrated on the workstations.

These are forecasts, not commitments. The actual cost prints live in the run log as the pipeline executes; trust those over this table.

## Dual-channel (disk + memory) runs

Defer until at least one disk-only run on the same host has succeeded. Pattern is:

1. Stage the memory dump into sift-mcp's `/tmp` (the dual_sweep.sh script has done this before for SRL-2018; the memory file at `/mnt/hackathon/...` is read-only and Volatility wants to write a side file in some plugins, so the script copies to `/tmp` first):
   ```
   docker exec sift-mcp cp /mnt/hackathon/srl-2015/xp-tdungan-10.3.58.7/xp-tdungan-memory/xp-tdungan-memory-raw.001 /tmp/xp-tdungan-memory-raw.001
   ```
2. Detect the Volatility 2 profile:
   ```
   docker exec sift-mcp bash -c "vol.py -f /tmp/xp-tdungan-memory-raw.001 imageinfo > /tmp/xp-tdungan-imageinfo.txt 2>&1 && grep 'Suggested Profile' /tmp/xp-tdungan-imageinfo.txt"
   ```
   Expect something like `WinXPSP3x86, WinXPSP2x86`. Pin the first.
3. Run the pipeline with the dual-channel flags, using a `-dual` suffix on the case_id to keep the run dirs separate from the disk-only sibling:
   ```
   docker exec sift-sentinel bash -c "cd /workspace && uv run python run_case.py --case srl-2015-xp-tdungan-dual --e01 /mnt/derived/xp-tdungan-c-drive.raw --memory-image /tmp/xp-tdungan-memory-raw.001 --memory-profile WinXPSP3x86"
   ```

Profile suggestions per host (these are the expected `imageinfo` outputs; verify before running):

| Host | Expected Volatility 2 profile |
|---|---|
| xp-tdungan | `WinXPSP3x86` |
| win7-32-nromanoff | `Win7SP1x86` |
| win7-64-nfury | `Win7SP1x64` |
| win2008R2-controller | `Win2008R2SP1x64` |

Dual-channel runs cost more than disk-only because the memory plugins add evidence records to the INTERPRET bundle. Apply the per-tool size guard rule from `CLAUDE.md` and the `feedback_llm_bundle_size_guard.md` memory note: if any new memory plugin's output exceeds 50 KB on these older OSes, trim before adding it to the bundle.

## Memory-only runs (not recommended for SRL-2015)

The pipeline supports memory-only mode (`--memory-image` + `--memory-profile`, no `--e01`), but for SRL-2015 we have disks for all four hosts, so memory-only adds cost without coverage benefit. Skip this mode for SRL-2015.

## Do not yet (callout)

**Do not** queue all four hosts back-to-back in one shell. The pipeline is designed for human-in-the-loop adjudication between runs. After the first SRL-2015 host finishes:

1. Read the findings JSON.
2. Decide if the result is sane (right OS-era artifacts, sensible classifications, no obvious hallucinations).
3. Only then run the next host.

If the first run produces something nonsensical, fix the prompt or the bundle guard before spending again. The cost compounds quickly: four hosts at $0.80 each is $3.20 of OpenRouter spend with nothing to show if EXTRACT was wrong on host 1.

## Open questions for Charan

These are the spots in the runbook where the repo could not give a definitive answer and the user has to fill in or accept the placeholder:

1. **Step 3 (dry-run fsstat).** I marked the import path as `<TBD>` because the public surface of the `tsk` tool wrapper is not obvious from the repo. The pipeline will run fsstat as step 1 of EXECUTE regardless, so this dry-run is optional. If you want a quick parseability probe outside the pipeline, the simplest one-liner is `docker exec sift-mcp mmls /mnt/derived/xp-tdungan-c-drive.raw` followed by `docker exec sift-mcp fsstat /mnt/derived/xp-tdungan-c-drive.raw 2>&1 | head -20`. If the raw is a logical-drive NTFS image, `mmls` may return "Cannot determine partition type"; that is fine because the pipeline does not call mmls, it calls fsstat directly.
2. **Whether to use the local stack or the VPS.** The user has previously said the VPS is reserved for the daily 22:30 UTC cron loop; new test cases run locally. This runbook follows that rule. If you change your mind and want to put SRL-2015 on the VPS instead, the command structure is identical; the volume mount paths are also identical (`/mnt/hackathon/`, `/mnt/derived/`).
3. **Whether to add the case to `keep_runs.json` after run 001.** New runs do not show up in the viewer until they are added to the allowlist (see `project_viewer_dashboard_curation` memory). Decide post-run whether SRL-2015 is exhibit-quality before promoting.

---

## Appendix: source-of-truth references

- Conversion provenance: `HACKATHON-2026/derived/_provenance.md` (commit 3cf0266).
- Pipeline entry point: `experiments/slice-2-notebook/run_case.py`.
- Closest comparable run log: `experiments/slice-2-notebook/out/runs/_openuni22_cdrive_run_log.txt`.
- Dual-channel sweep reference (SRL-2018): `scripts/dual_sweep.sh`.
- Run viewer curation: `experiments/slice-2-notebook/viewer/keep_runs.json`.
