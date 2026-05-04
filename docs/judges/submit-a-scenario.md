# Submit a scenario (for SANS hackathon judges)

You describe an attack in plain English. Our system translates it into a synthetic Windows disk, plants the artifacts, and runs our forensics agent against the disk. You get a scorecard showing what the agent caught and what it missed.

This is the actual product. Not a canned demo, not a recorded video. You design the test, we run it.

## What this exercises

The submission has three working pieces, and your scenario exercises all of them:

1. **A research / translator agent** that turns a free-form scenario into a structured manifest of forensic artifacts to plant.
2. **A synthetic-workstation builder** that materializes the manifest as files and registry entries on a never-booted Windows NTFS image.
3. **An autonomous DFIR agent (sift-sentinel)** that examines the disk and reports persistence mechanisms, with no human-in-the-loop reasoning.

The scorecard at the end shows location-by-location whether the agent's findings matched your planted artifacts.

## Important: scope is disk-only persistence

Before you write your scenario, please read `docs/judges/supported-techniques.md`. Short version:

- We can plant files, registry values, scheduled tasks, and services on a Windows NTFS disk.
- The agent looks for persistence mechanisms (Run keys, services, scheduled tasks, IFEO debuggers, AppInit_DLLs, logon scripts, web shells).
- We cannot do memory-only artifacts, live exploit chains, network captures, or domain-controller compromise.
- Scenarios that imply out-of-scope techniques get rejected by the translator with an explanation, not silently mis-built.

## Prerequisites

- Docker Desktop or Docker Engine (recent version), running and reachable from your shell.
- About 80 GB of free disk. Image build is ~5 GB; the synthetic Windows base raw is 30 GB; the planted working copy is another 30 GB; pipeline outputs add a couple GB.
- Bash or PowerShell.
- Browser to read the scorecard.

You do NOT need:
- Your own OpenRouter / Anthropic / OpenAI API key (we provide one).
- Forensic-software licenses (the agent uses open-source tools inside the container).
- Windows specifically. Linux, macOS, and WSL all work.

## Honest timing expectations

Per submission, end to end, from your scenario text to a scorecard:

| Phase | Wall time | Notes |
|---|---|---|
| Translator (your scenario -> manifest JSON) | ~10 sec | One LLM call |
| Image build (first time only) | ~10 to 20 min | Docker image build, package install, tool download |
| Planting (apply manifest to base disk) | ~3 to 6 min | sparse copy of 30 GB raw + ntfs-3g mount + plant + unmount |
| Pipeline run (sift-sentinel scans the disk) | ~6 to 10 min | Multi-stage agent run, varies with manifest size |
| Scoring + report | seconds | location-based match against findings |

Total first run: roughly 25 to 40 minutes. Subsequent runs reuse the image, so 10 to 20 minutes.

This is too long to make you stare at a terminal, so the flow is async: you submit, get a job id, walk away, come back and check status (or get an email if you provided one).

## Step 1: Get the project

```bash
git clone https://github.com/<owner>/find-evil.git
cd find-evil
```

If you were given a tarball, extract it and `cd` into the extracted folder.

## Step 2: Get the API key (password-gated)

The pipeline needs an OpenRouter API key. Rather than asking you to provision one, we provide ours behind a password we share separately (email or in the submission cover note).

```bash
bash scripts/judge-key.sh
```

The script prompts for the password, verifies against a project-provided hash, and on success writes `docker/.env` with the key set (gitignored, never committed). The key has a per-day call cap, so even if shared the total cost is bounded. Per scenario submission costs about 40 cents in OpenRouter spend.

> **Status:** `scripts/judge-key.sh` and the key vault are still being implemented. See "Open work" at the bottom.

## Step 3: Build the containers

```bash
docker compose -f docker/compose.yml build
```

About 10 to 20 minutes the first time (image pulls + uv install + Volatility + RegRipper + python deps). Subsequent builds are seconds. This is where the bulk of first-run time goes.

## Step 4: Submit your scenario

### 4a. Read the supported-techniques catalog

```bash
less docs/judges/supported-techniques.md
```

This tells you exactly what we can plant and what we can detect. It also lists what we cannot do, so you can shape your scenario inside the supported envelope.

### 4b. Write your scenario

Two ways to phrase it:

**Free-form English (recommended for the wow factor):**
> A red-team operator landed on a Windows 7 workstation, dropped a fake Windows Defender service named "WinDefenderTelemetry" with the binary at C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\helper.exe, and added a Run key under HKLM Run named "DefenderUpdate" that calls powershell.exe with a base64-encoded payload. They also dropped a JSP web shell at Program Files/PaperCut MF/server/webapps/ROOT/diag.jsp.

The translator picks the right plant primitives, fills in registry hives and key paths, generates the encoded payload, and writes a schema-valid manifest. We have validated this end to end; see `experiments/synthetic-ai-workstation/_judge_probe/translated_manifest.json` for a real translator output.

**Reference-card style (terser, equally valid):**
> Cobalt Strike PsExec lateral movement landed here. Show me what disk artifacts that leaves.

The translator picks: a registry service with the named-pipe-beacon ImagePath that exercises our existing detection rule.

### 4c. Submit

```bash
bash scripts/judge-submit.sh "<your scenario text here>"
```

The script:
1. Calls the translator (one Sonnet call, ~10 sec, ~$0.04 in OpenRouter spend).
2. Validates the resulting manifest against `manifest_schema.json`.
3. Confirms every artifact uses a plant type the builder supports.
4. If the scenario implies out-of-scope techniques, the translator emits a single `expected_miss_documented_gap` artifact with an explanation, and the script asks you to confirm before proceeding.
5. On approval, queues a job and prints a job id like `judge-2026-05-01-001`.

> **Status:** `scripts/judge-submit.sh`, the job queue, and the status page are still being implemented. The translator itself is validated.

### 4d. Review the manifest before the loop runs (optional)

```bash
cat out/judge-jobs/<job-id>/manifest.json
```

If anything looks off, edit it and resubmit, or hand-correct it before the build phase starts.

## Step 5: Wait for the loop, or come back later

```bash
bash scripts/judge-status.sh <job-id>
```

Possible states:
- `queued` (waiting for builder)
- `building` (planting on the synthetic disk)
- `scanning` (pipeline running)
- `scoring`
- `complete` (REPORT.md written)
- `failed` (with reason)

If you want a notification when the job completes, pass `--email you@example.com` to the submit script. The notification arrives via the project author's existing openclaw email channel and tells the project author the same scorecard summary you see, so they know which scenario was tested.

## Step 6: Read the scorecard

```bash
cat out/judge-jobs/<job-id>/REPORT.md
```

The scorecard reports:

- **Regression** (out of 2 baseline plants on the base disk): how many of the two known-positive plants the agent re-detected. Should be 2/2 every run; if not, the build itself regressed.
- **Extension** (out of N plants from your scenario): how many of YOUR planted artifacts the agent caught. This is the headline number for your test.
- **Acknowledged gaps** + **bonus**: artifacts you marked as `expected_miss_documented_gap` (because they imply out-of-scope techniques) split into "as-expected miss" vs "surprise detection."
- **Per-artifact breakdown:** for each artifact, PASS / MISS, the matching finding excerpt if PASS, the rationale if MISS.

## Step 7: See the self-correction story (optional)

Each completed scenario produces a `06_critic_disagreements.jsonl` file showing where the critic agent overruled the LLM's emissions. Common rule violations:

- `R_02 PATH_INCONSISTENCY` (finding's mechanism text not anchored in cited evidence)
- `R_16 AI_ASSIST_ANCHOR_MISSING` (classified AI-assisted but no AI artifact in cited excerpts)
- `R_05 EVIDENCE_TOOL_EXIT_NONZERO` (finding cited a tool that errored)

Each disagreement either retried (LLM re-emits a corrected version) or escalated to human review. The pattern of "agent emits, critic overrules, system retries to a stronger answer" is the durability story.

## What you cannot break

By design, your scenario cannot:

- Run real exploits. Every artifact is static data on a never-booted disk.
- Reach external networks. Domains in the manifest are example.invalid (RFC 2606, non-resolvable).
- Use real credentials. Token slots are ALLCAPS_PLACEHOLDER strings.
- Cost us more than the per-day OpenRouter key cap, regardless of how many scenarios you submit.

## What if your scenario fails

The translator will reject scenarios that:

- Imply memory-only artifacts (process injection, fileless, in-memory C2).
- Imply domain-controller compromise (Zerologon, Golden Ticket, KRBTGT replication).
- Imply techniques the builder cannot plant (bootkit, firmware, AD-side, network-only).

Rejection is not silent. The translator emits a manifest with one `expected_miss_documented_gap` artifact explaining what was rejected and why, and proposes the closest in-scope variant. You can accept the variant, edit your scenario, or proceed knowing the score will be 0 on that artifact.

If the build phase fails (rare), the job state goes to `failed` with the build's exit code and stderr surfaced. If the pipeline fails mid-scan, same surface. Both states are visible to the project author via the email channel.

## Where to go next

- `docs/judges/supported-techniques.md`: the capability catalog you used in step 4a.
- `docs/submission/sweep-2026-05-01.md`: a sweep across 7 historical SANS evidence sets, showing the agent against pre-recorded ground truth.
- `docs/submission/known-limitations.md`: what the system does NOT do well.
- `docs/submission/design-decisions.md`: the architectural reasoning trail.

## Open work (project author notes)

These items still need to be built before judges can use this guide as written:

1. **`scripts/judge-key.sh`** + a small password-protected key vault. Currently the OpenRouter key sits in `docker/.env` directly, which is gitignored but not safe to share.
2. **`scripts/judge-submit.sh`**, **`scripts/judge-translate.py`** (promoted from the validated probe), **`scripts/judge-status.sh`**, and a tiny job queue under `out/judge-jobs/`. The translator probe at `experiments/slice-2-notebook/_judge_probe/probe.py` is the validated reference.
3. **Async build + scan worker** that consumes jobs from the queue, runs the existing build.py + run_case.py end to end, and emits status into a per-job state file.
4. **`scripts/judge-status.sh`** to read job state. Trivial wrapper.
5. **Email notification** when a judge job completes. Piggy-back on the existing openclaw email channel running on the project VPS. Notification carries: job id, scenario summary, scorecard headline, link to the scorecard.
6. **Repo-root README.md** with one-paragraph project pitch and a single link pointing here.
7. **Demo video** for judges who would rather watch than run.
8. **Date injection in the translator.** The validated probe showed Sonnet anchors `manifest_id` to its training-time date. The wrapper must inject today's date deterministically before sending to the LLM, OR overwrite the field after parse.
