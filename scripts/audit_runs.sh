#!/usr/bin/env bash
# Triage cheap check: per-run finding/citation/critic counts.
# Run inside sift-sentinel: bash /workspace/scripts/audit_runs.sh < /tmp/non_curated.txt > /tmp/audit_report.csv
#
# 2026-05-09: RUNS_BASE matches container layout (/workspace = slice-2-notebook dir,
# so runs live at /workspace/out/runs). No path adjustment from runbook needed; the
# runbook value /workspace/out/runs is correct for this mount.
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
