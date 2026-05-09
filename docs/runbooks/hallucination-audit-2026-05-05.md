---
created: 2026-05-05
status: open
context: extending the "0 hallucinations" claim from the 7 curated runs in keep_runs.json to all runs in out/runs/. Pure desk work, no LLM cost. Runs entirely on the LOCAL Docker stack; no VPS interaction.
---

# Hallucination audit of non-curated runs (local-only)

## TL;DR

The current "0 hallucinations across 7 runs" claim in `docs/submission/accuracy-report.md` rests on the curated allowlist `experiments/slice-2-notebook/viewer/keep_runs.json`. There are roughly 60 to 80 other run directories under `experiments/slice-2-notebook/out/runs/` that have not been audited. This runbook walks you through deciding, for each of those, whether anything in the findings looks fabricated. The protocol is: triage runs by a cheap automated check (do all cited tool_call_ids resolve to real evidence records), then eyeball only the runs where the cheap check flagged something or the count of findings is unusually high. Most runs are expected to clear in seconds; the suspicious ones are where you spend real time.

Everything runs on local. Source data is at `D:/Python Applications/Find Evil - Hackathon/experiments/slice-2-notebook/out/runs/`, which is also visible inside the `sift-sentinel` container at `/workspace/out/runs/`. The audit script runs inside `sift-sentinel` (Python 3.12 already there); output goes to a local file in the repo. VPS is not involved.

## What counts as a hallucination

A hallucination is a finding that asserts something the cited evidence does not support. The accuracy report's existing scoring rule:

- `tool_call_id` cited in a finding must exist in `04_execute_evidence.jsonl` for that run. A miss is a hard hallucination.
- The `excerpt` field of an evidence record must contain the substring the finding's `rationale` quotes. A drifted quote (whitespace, casing) is the R_05 false-positive class, NOT a hallucination, but worth flagging.
- A finding cannot claim a tool was run that is not in `02_plan_tool_plan.json`. Out-of-plan claims are a hallucination.
- Critic events of class `INJECTION_QUARANTINE` are defense layers firing as designed; never a hallucination.

## Investigative question

**Out of all non-curated runs, which ones contain at least one finding that fails any of the four checks above?**

The answer is a list of runs to manually review. For each manually-reviewed run you decide: real hallucination, R_05 normalize artifact (already known, since fixed), or false alarm.

## Where the runs live (local)

Host path: `D:/Python Applications/Find Evil - Hackathon/experiments/slice-2-notebook/out/runs/<case>/<run-id>/`.

Container path (inside `sift-sentinel`): `/workspace/out/runs/<case>/<run-id>/`.

Each per-run directory has the same set of artifacts:

- `01_extract_candidates.json`
- `02_plan_tool_plan.json`
- `03_approve.SUCCESS` (or `.HUMAN_REVIEW`, `.QUARANTINED`)
- `04_execute_evidence.jsonl`
- `05_interpret_findings.json`
- `06_critic_disagreements.jsonl` (only if Critic disagreed)
- `07_terminal.SUCCESS` (or `.HUMAN_REVIEW`, `.QUARANTINED`)
- `integrity_ledger.jsonl`

## Step-by-step

### 1. Verify the local container is up

From a Git Bash shell on Windows:

```bash
docker ps --filter "name=sift-sentinel" --format "{{.Names}}\t{{.Status}}"
```

- [ ] sift-sentinel shows `Up <duration>`. If not, start it: `docker compose -f docker/docker-compose.yaml up -d sift-sentinel`.

### 2. List every run directory and partition curated vs non-curated

Pin the curated allowlist into a shell-friendly form, then enumerate runs.

```bash
MSYS_NO_PATHCONV=1 docker exec sift-sentinel bash -c '
cd /workspace/out/runs && \
for d in */; do \
  for r in "$d"*/; do \
    [ -d "$r" ] && [ -f "$r/05_interpret_findings.json" ] && echo "$r" | sed "s|/$||"; \
  done; \
done' > out/all_runs.txt
wc -l out/all_runs.txt
```

- [ ] Got a count (expected order of magnitude: 60 to 80 runs).

Then strip out the curated allowlist, also inside the container so we use the same Python that owns the repo:

```bash
MSYS_NO_PATHCONV=1 docker exec sift-sentinel python - <<'PY'
import json, pathlib
keep = json.load(open("/workspace/viewer/keep_runs.json"))
allow = set()
for case, runs in keep.items():
    for r in runs:
        allow.add(f"{case}/{r}")
all_runs = pathlib.Path("/workspace/../out/all_runs.txt").read_text().splitlines() if pathlib.Path("/workspace/../out/all_runs.txt").exists() else []
# Fallback if the relative path didn't resolve in your environment, paste the list:
if not all_runs:
    import sys; sys.exit("paste all_runs.txt content into the script if /workspace/../out/all_runs.txt is missing")
non_curated = [r for r in all_runs if r not in allow]
pathlib.Path("/workspace/../out/non_curated.txt").write_text("\n".join(non_curated))
print(f"all={len(all_runs)} curated={len(allow)} non_curated={len(non_curated)}")
PY
```

If the `/workspace/../out/` relative does not resolve cleanly in the container, the simpler form:

```bash
MSYS_NO_PATHCONV=1 docker cp out/all_runs.txt sift-sentinel:/tmp/all_runs.txt
MSYS_NO_PATHCONV=1 docker exec sift-sentinel python - <<'PY'
import json, pathlib
keep = json.load(open("/workspace/viewer/keep_runs.json"))
allow = {f"{c}/{r}" for c, rs in keep.items() for r in rs}
runs = pathlib.Path("/tmp/all_runs.txt").read_text().splitlines()
nc = [r for r in runs if r not in allow]
pathlib.Path("/tmp/non_curated.txt").write_text("\n".join(nc))
print(f"all={len(runs)} curated={len(allow)} non_curated={len(nc)}")
PY
MSYS_NO_PATHCONV=1 docker cp sift-sentinel:/tmp/non_curated.txt out/non_curated.txt
```

- [ ] non_curated.txt count looks right (all minus the 7 in keep_runs).

### 3. Triage each non-curated run with the cheap check

Save the script below as `scripts/audit_runs.sh` in the repo, then run it inside `sift-sentinel`. Output is a CSV.

```bash
#!/usr/bin/env bash
# Triage cheap check: per-run finding/citation/critic counts.
# Run inside sift-sentinel: bash /workspace/scripts/audit_runs.sh < /tmp/non_curated.txt > /tmp/audit_report.csv
set -euo pipefail
RUNS_BASE=/workspace/out/runs
echo "run,n_findings,n_citations,n_unresolved_citations,n_critic_events,terminal_status"
while read -r run; do
  d="$RUNS_BASE/$run"
  [ -d "$d" ] || { echo "$run,MISSING,,,,"; continue; }
  findings_file="$d/05_interpret_findings.json"
  evidence_file="$d/04_execute_evidence.jsonl"
  ledger="$d/integrity_ledger.jsonl"
  terminal=$(ls "$d" | grep -E '^07_terminal\.' | head -1 | sed 's/^07_terminal\.//' || echo "MISSING")

  if [ ! -f "$findings_file" ]; then
    echo "$run,NOFINDINGS,,,,$terminal"
    continue
  fi

  python - "$findings_file" "$evidence_file" "$ledger" "$run" "$terminal" <<'PY'
import json, sys, pathlib
findings_path, evidence_path, ledger_path, run, terminal = sys.argv[1:]
findings = json.load(open(findings_path)).get("findings", [])
n_f = len(findings)
cites = []
for f in findings:
    for ev in f.get("evidence", []):
        cites.append(ev.get("tool_call_id"))
cites = [c for c in cites if c]
n_c = len(cites)

evidence_ids = set()
if pathlib.Path(evidence_path).exists():
    for line in open(evidence_path):
        try:
            r = json.loads(line)
            tid = r.get("tool_call_id") or r.get("id")
            if tid:
                evidence_ids.add(tid)
        except Exception:
            pass
n_unresolved = sum(1 for c in cites if c not in evidence_ids)

n_critic = 0
if pathlib.Path(ledger_path).exists():
    for line in open(ledger_path):
        try:
            r = json.loads(line)
            if r.get("event_type", "").startswith("CRITIC_") or r.get("rule_id"):
                n_critic += 1
        except Exception:
            pass

print(f"{run},{n_f},{n_c},{n_unresolved},{n_critic},{terminal}")
PY
done
```

Then, from Git Bash on the host:

```bash
chmod +x scripts/audit_runs.sh
MSYS_NO_PATHCONV=1 docker exec -i sift-sentinel bash /workspace/scripts/audit_runs.sh < out/non_curated.txt > out/audit_report.csv
wc -l out/audit_report.csv
head -5 out/audit_report.csv
```

- [ ] CSV row count matches non_curated count + 1 header.

### 4. Read the CSV and pick the rows to eyeball

Open `out/audit_report.csv` in your editor or in a spreadsheet tool.

Bucket the rows:

- **Bucket A (clean, no eyeball needed):** `n_unresolved_citations == 0` AND `terminal_status == SUCCESS` AND `n_findings <= 3`. These pass the cheap check and have a typical finding count.
- **Bucket B (eyeball the findings):** `n_unresolved_citations > 0`. Any unresolved citation is the definition of a real hallucination flag. Open every one of these by hand.
- **Bucket C (eyeball selectively):** `n_findings >= 5` OR `n_critic_events >= 3` AND `terminal_status != QUARANTINED`. High finding count or noisy critic ledger; spot-check 1 in 3.
- **Bucket D (defense layer fired, not hallucination):** `terminal_status == QUARANTINED`. Skim to confirm but do not score as hallucination.

Mark the bucket against each row in the spreadsheet.

- [ ] Every row labeled A through D.

### 5. Eyeball the Bucket B and C rows

For each Bucket B row, paste the run path and read the artifacts straight from the host filesystem (Windows-side, no container needed for read):

```bash
RUN="<paste the run path from CSV, e.g. srl-2018-base-rd-02/srl-2018-base-rd-02-003>"
cat "experiments/slice-2-notebook/out/runs/$RUN/05_interpret_findings.json"
echo "=== LEDGER ==="
cat "experiments/slice-2-notebook/out/runs/$RUN/integrity_ledger.jsonl"
```

Or open the same files in your editor (paths above).

- For each finding with an unresolved tool_call_id, copy the citation into a notes file. Decide:
  - Is the cited evidence really missing? Real hallucination.
  - Or is the citation a typo or stale id? Soft bug, not a hallucination per the SANS rubric, but flag it.
- For Bucket C, read every finding's `rationale` and confirm the cited evidence supports the claim. Skim, do not deep-read.

Notes file format (one block per real hallucination), save at `docs/submission/hallucination-audit-notes-2026-05-05.md`:

```
RUN: <case>/<run-id>
FINDING_ID: <id>
CITED_TOOL_CALL: <id>
WHY_HALLUCINATION: <one sentence>
```

- [ ] Notes file written for any real hallucination found.

### 6. Decide the headline number

After Buckets B and C are eyeballed, count:

- **Real hallucinations:** sum of finding-level entries in the notes file from step 5.
- **Defense fires (not hallucinations):** count of Bucket D rows.
- **R_05 normalize artifacts (not hallucinations):** count of rows with `n_critic_events > 0` whose ledger entries are `R_05` and whose findings still cite real evidence; these are documented in the existing accuracy report.

Headline update for `docs/submission/accuracy-report.md`:

- If real hallucinations == 0: extend the claim from "across 7 runs" to "across N runs" where N is the total non-skipped run count.
- If real hallucinations > 0: do NOT extend the claim. Open a new section in the accuracy report describing each real hallucination and either fix the rule that should have caught it or document as a known limitation.

- [ ] Headline number decided.
- [ ] If clean: edit `accuracy-report.md` section 1 to reflect new total run count.
- [ ] If not clean: write the limitations section.

### 7. Update the For-judges page wording

If the claim extends:
- File: search `experiments/slice-2-notebook/site/` for the "0 hallucinations" phrase and update the count from 7 to the audited total.
- Add a sentence: "Audited 2026-05-05 across N runs; protocol in docs/runbooks/hallucination-audit-2026-05-05.md."

If the claim does NOT extend:
- Soften the wording on the judges page to match the bounded scope.
- Leave a one-line breadcrumb to the limitations section in the accuracy report.

- [ ] Site copy reflects the audit outcome.

### 8. Commit and push (no VPS interaction)

```bash
git add docs/runbooks/hallucination-audit-2026-05-05.md \
        scripts/audit_runs.sh \
        docs/submission/accuracy-report.md \
        docs/submission/hallucination-audit-notes-2026-05-05.md \
        experiments/slice-2-notebook/site/
git commit -m "audit: hallucination check across N non-curated runs"
git push origin main
```

The cron on VPS picks up the new HEAD on its next 22:30 UTC `git pull`. Do not push to the `vps` remote or scp anything; that path is reserved for when the cron itself needs an update, not for audit work.

- [ ] Commit landed on origin.

## Why this is desk work, not LLM work

Every step above is grep, JSON parsing, and human eyeballing. No paid LLM calls. No inference. The accuracy claim is about what the LLM already produced, not about producing more output. This is exactly the kind of work the project memory says you drive, not me.

## Estimated effort

- Steps 1 to 3 (scripted): 5 to 10 minutes.
- Step 4 (bucket the rows): 15 minutes.
- Step 5 (eyeball Bucket B+C): depends on bucket size, likely 30 to 90 minutes.
- Steps 6 to 8 (decide + write up + commit): 30 minutes.

Total: 1 to 3 hours of focused desk work. Run it in one sitting; the trail of decisions is easier to keep coherent that way.
