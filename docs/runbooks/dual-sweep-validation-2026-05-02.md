---
created: 2026-05-02
status: open
context: same human-review pass we did for wkstn-01, applied to the other three successful dual-sweep hosts (file, rd-02, wkstn-05). Goal is to (a) catch any FNs of the same shape, (b) verify the dual-sweep findings list did not regress vs the earlier disk-only sweep.
---

# Dual-sweep manual validation: file, rd-02, wkstn-05

## TL;DR

The 2026-05-02 dual sweep produced findings on four hosts. wkstn-01 has its own runbook (the FN deep dive). This runbook covers the other three: `file`, `rd-02`, `wkstn-05`. For each, the human review compares the dual-sweep findings to the earlier disk-only sweep findings, looks for anything that vanished or got down-graded, and runs the same C2 cross-host check. The dual-sweep counts felt thin to the user (we previously had a host with around six findings; the new runs show one to four). This runbook is the disciplined pass that confirms or denies that gut feel.

## Reminder on the network model

Before reading any IPs in any run: see the "What is local vs what is in the image" sidebar at the top of `wkstn-01-manual-review-2026-05-02.md`. The same three-layer rule applies. Every `172.16.x.x` here is a 2018-frozen address inside the captured image, not on your laptop.

## What we are checking for

Two distinct questions:

1. **Regression check.** Did the dual-sweep findings for this host include everything the disk-only sweep already found? Anything missing is a regression introduced by the dual-channel changes (extra prompt context, dual-tool surface, etc) and is a real bug.
2. **Same-pattern FN check.** Does this host show evidence the agent saw but under-classified, the way wkstn-01 did with `172.16.4.10:8080`? If yes, the same one-rule fix (or aggregator script) closes it.

Comparison artifacts per host:

| Host | Disk-only canonical | Dual canonical |
|---|---|---|
| file | `srl-2018-base-file/srl-2018-base-file-005/` | `srl-2018-base-file-dual/srl-2018-base-file-dual-001/` |
| rd-02 | `srl-2018-base-rd-02/srl-2018-base-rd-02-004/` | `srl-2018-base-rd-02-dual/srl-2018-base-rd-02-dual-002/` |
| wkstn-05 | `srl-2018-base-wkstn-05/srl-2018-base-wkstn-05-002/` | `srl-2018-base-wkstn-05-dual/srl-2018-base-wkstn-05-dual-002/` |

(Source: each host's `latest.txt`. If `latest.txt` has been updated since, use whatever path it points at.)

All paths below are relative to `experiments/slice-2-notebook/out/runs/`.

## Per-host walkthrough

For each host, do the same five steps. Fill in the cells; treat any cell you cannot answer "no, no surprises" as a real regression to investigate.

### Step 1 — pin both run dirs as shell vars

```bash
# Replace HOST with file, rd-02, or wkstn-05
HOST=file
ROOT="experiments/slice-2-notebook/out/runs"
DISK="$ROOT/srl-2018-base-$HOST/$(cat $ROOT/srl-2018-base-$HOST/latest.txt)"
DUAL="$ROOT/srl-2018-base-$HOST-dual/$(cat $ROOT/srl-2018-base-$HOST-dual/latest.txt)"
echo "DISK=$DISK"
echo "DUAL=$DUAL"
ls "$DISK" "$DUAL"
```

- [ ] Both dirs list a full `01_..` through `06_..` set (or at least `05_interpret_findings.json`).

### Step 2 — count and list findings on both sides

```bash
echo "--- disk-only ---"
jq '.findings | length, [.[] | {category, classification, mechanism, confidence}]' "$DISK/05_interpret_findings.json"
echo "--- dual ---"
jq '.findings | length, [.[] | {category, classification, mechanism, confidence}]' "$DUAL/05_interpret_findings.json"
```

Fill in the table for this host:

| Host | Disk-only count | Dual count | Disk-only classifications | Dual classifications |
|---|---|---|---|---|
| file |  |  |  |  |
| rd-02 |  |  |  |  |
| wkstn-05 |  |  |  |  |

- [ ] If dual count is LOWER than disk-only: regression candidate. Continue to Step 3 and identify which one disappeared.
- [ ] If dual count is HIGHER (memory channel added findings): expected. Note which `classification` is new (`process_injection`, `c2_beacon`, etc).

### Step 3 — find any disk-only finding that vanished in the dual run

For each disk-only finding, check whether the dual run produced a finding with the same `mechanism` or `value`:

```bash
jq -r '.findings[] | "\(.classification) | \(.mechanism) | \(.value)"' "$DISK/05_interpret_findings.json"
echo "---"
jq -r '.findings[] | "\(.classification) | \(.mechanism) | \(.value)"' "$DUAL/05_interpret_findings.json"
```

- [ ] Eyeball the two lists. Note any disk-only line that has no dual-side counterpart.
- [ ] If something disappeared: is the underlying evidence still in `04_execute_evidence.jsonl` for the dual run? If yes, INTERPRET dropped it (LLM bug). If no, EXECUTE never ran the right plugin (PLAN drift).

```bash
# For an evidence dive on a specific dropped mechanism, search both evidence files for the same key signature:
grep -i 'masquerade\|persistence\|named-pipe\|tbbd\|perfmon' "$DUAL/04_execute_evidence.jsonl" | head
```

### Step 4 — apply the same C2 cross-host check

```bash
grep -oE '"local_address":"[^"]+","foreign_address":"172\.16\.4\.10:8080","state":"[A-Z_]+"' "$DUAL/04_execute_evidence.jsonl"
```

- [ ] Number of records. (For wkstn-05 we expect 6, file 4, rd-02 2.)
- [ ] Did the dual-run INTERPRET stage classify any of these as `c2_beacon`? Compare to `05_interpret_findings.json`.
- [ ] If records exist but no `c2_beacon` finding was emitted: this is the same wkstn-01-style FN. Note it.

### Step 5 — scan for parse_error and quarantined steps

```bash
grep -E '"tool_execution_status":"(parse_error|capability_denied|permission_denied|timeout)"' "$DUAL/04_execute_evidence.jsonl" | grep -oE '"plugin_name":"[^"]+"|"tool_execution_status":"[^"]+"' | paste -d' ' - -
ls "$DUAL"/07_terminal.* 2>/dev/null
```

- [ ] List of failed plugins (and their status). Compare to the disk-only run's failure list.
- [ ] If a `07_terminal.QUARANTINED` exists: same drill as in the wkstn-01 runbook step 7. Pull the raw blob from the `INJECTION_QUARANTINE` event and decide if the quarantine was a real attacker artifact or a regripper banner.

## Cross-host C2 destination audit

(Already pre-extracted in the wkstn-01 runbook step 3. The four-host table is reproduced here so you do not have to flip files.)

| Captured host | Captured host IP | Records to 172.16.4.10:8080 | States |
|---|---|---|---|
| wkstn-01 | 172.16.7.11 | 3 | 1 ESTABLISHED, 2 CLOSED |
| wkstn-05 | 172.16.7.15 | 6 | 4 CLOSE_WAIT, 2 CLOSED |
| file | 172.16.4.5 | 4 | 1 CLOSE_WAIT, 3 CLOSED |
| rd-02 | 172.16.6.12 | 2 | 2 CLOSED |

For each of the three hosts in this runbook:

- [ ] Confirm `c2_beacon` classification appears in the dual run's `05_interpret_findings.json`. wkstn-05 already has it (per accuracy report line 180). The other two are the question.

If file or rd-02 do NOT have a `c2_beacon` finding even though their evidence file shows multiple records to 172.16.4.10:8080, that is the same FN class as wkstn-01.

## Final regression matrix

Fill this in at the end of all three host walkthroughs:

| Host | Findings vanished vs disk-only? | Same-pattern FN spotted? | Verdict |
|---|---|---|---|
| file |  |  |  |
| rd-02 |  |  |  |
| wkstn-05 |  |  |  |

If any "vanished" or "same-pattern FN spotted" is yes: that is a regression and should be added as a new section in `docs/submission/memory-sweep-2026-05-02.md` so the submission report is honest about the dual-channel coverage gaps.

## What this gives the submission

Two artifacts:
1. A per-host audit log proving the dual sweep did not silently drop disk-only findings. Or, if it did, the exact mechanism and a known-cause story.
2. A list of additional FN candidates of the same shape as wkstn-01, scoped tightly so the cross-host escalation rule (see the wkstn-01 runbook bottom section) can be evaluated against ALL of them, not just one anecdote.

## What this does NOT cover

- Hosts that hung (dc, rd-01). Those need the SSE-timeout fix re-run before they have findings to validate.
- The 11 memory-only hosts that have no disk image. Those wait for the memory-only mode prompt rewrite that is half-done in the working tree.
- The disk-only-only hosts where we do not yet have memory data. They will be added later in a separate pass.
