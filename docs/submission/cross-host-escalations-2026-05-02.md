# Cross-host C2 escalations, 2026-05-02

## TL;DR

Cross-host aggregator scanned 6 dual-sweep run dirs. Built a global C2 destination index of 1 unique (ip, port) pairs supported by at least one host's `c2_beacon` finding. Flagged 2 per-host escalations where local evidence matches a known C2 destination but the local finding either does not exist or is graded lower than `c2_beacon`.

## Hosts scanned

| Case | Local IPs | Findings | c2_beacon findings | Distinct foreign destinations |
|---|---|---|---|---|
| `srl-2018-base-dc-dual` | 10.10.4.4, 172.16.4.4 | 3 | 0 | 146 |
| `srl-2018-base-file-dual` | 10.10.4.5, 172.16.4.5 | 4 | 1 | 36 |
| `srl-2018-base-rd-01-dual` | 172.16.6.11 | 4 | 1 | 11 |
| `srl-2018-base-rd-02-dual` | 10.10.150.180, 172.16.6.12 | 3 | 0 | 8 |
| `srl-2018-base-wkstn-01-dual` | 172.16.7.11 | 2 | 0 | 7 |
| `srl-2018-base-wkstn-05-dual` | 172.16.7.15 | 4 | 1 | 5 |

## Known C2 destinations (any host classified as c2_beacon)

| Destination | Supporting hosts |
|---|---|
| `172.16.4.10:8080` | srl-2018-base-file-dual, srl-2018-base-rd-01-dual, srl-2018-base-wkstn-05-dual |

## Escalations

| Case | Destination | States | ESTABLISHED? | Sibling hosts | Local classification | Local confidence |
|---|---|---|---|---|---|---|
| `srl-2018-base-rd-02-dual` | `172.16.4.10:8080` | CLOSED | no | srl-2018-base-file-dual, srl-2018-base-rd-01-dual, srl-2018-base-wkstn-05-dual | (no finding) | (no finding) |
| `srl-2018-base-wkstn-01-dual` | `172.16.4.10:8080` | CLOSED, ESTABLISHED | YES | srl-2018-base-file-dual, srl-2018-base-rd-01-dual, srl-2018-base-wkstn-05-dual | requires_disambiguation | medium |

### Per-escalation detail

#### `srl-2018-base-rd-02-dual` -> `172.16.4.10:8080`

- States observed: CLOSED
- Live at capture (ESTABLISHED present): no
- Sibling hosts already classifying as c2_beacon: srl-2018-base-file-dual, srl-2018-base-rd-01-dual, srl-2018-base-wkstn-05-dual
- Local finding classification: `(no finding)`
- Local finding confidence: `(no finding)`
- Local finding excerpt: `(no local finding mentions this destination)`

#### `srl-2018-base-wkstn-01-dual` -> `172.16.4.10:8080`

- States observed: CLOSED, ESTABLISHED
- Live at capture (ESTABLISHED present): YES
- Sibling hosts already classifying as c2_beacon: srl-2018-base-file-dual, srl-2018-base-rd-01-dual, srl-2018-base-wkstn-05-dual
- Local finding classification: `requires_disambiguation`
- Local finding confidence: `medium`
- Local finding excerpt: `172.16.7.11:51892 → 172.16.4.10:8080 ESTABLISHED (PID 2332, svchost.exe -k utcsvc -p)`


## How to apply this

For each escalation row, the local host's verdict should be promoted to HIGH `c2_beacon` (or at minimum to `requires_disambiguation` MEDIUM if the states are CLOSED only with no ESTABLISHED). Update the per-run `05_interpret_findings.json` by hand or, in the next pipeline rev, fold this aggregator's output into the INTERPRET prompt as a `--known-bad-destinations` list (Option B from the wkstn-01 runbook).
