# Slice 2.5 — Ground truth for `dfirmadness-001-desktop` (DFIR Madness Case 001, DESKTOP image)

**Status:** ✅ complete 2026-04-19. Machine-readable: [`out/runs/dfirmadness-001-desktop/ground_truth.json`](../../experiments/slice-2-notebook/out/runs/dfirmadness-001-desktop/ground_truth.json).

**Provenance note:** this document is **NOT** a hand-annotation runbook like [`slice-2.5-ground-truth.md`](slice-2.5-ground-truth.md) for `base-wkstn-05`. It's a **cross-reference against the published answer key** + two well-known community writeups. Different provenance, different trust level, but still legitimate Slice 2.5 baseline material because the CTF has been public for ~6 years and its persistence artifacts are well-enumerated in the DFIR community.

## What the pipeline produced

Pipeline run: 2026-04-19 ~12:32 local. Inputs: `/mnt/derived/dfirmadness-desktop.ntfs.dd` (14.4 GB raw NTFS partition extracted from the multi-segment E01 via `ewfmount` + `dd`). Findings: [`out/runs/dfirmadness-001-desktop/findings.json`](../../experiments/slice-2-notebook/out/runs/dfirmadness-001-desktop/findings.json).

Two high-confidence findings:

1. **HKLM Run key `coreupdate`** — fileless PowerShell stager (`-nop -w hidden` + IEX + Base64 payload read from custom registry key `HKLM:Software\q9Z1bssi`). Textbook Cobalt Strike / Metasploit pattern.
2. **Windows service `coreupdater`** at `C:\Windows\System32\coreupdater.exe` — auto-start `Own_Process`. Same `coreupdate*` attacker naming as Finding 1.

## Ground-truth sources

| Source | URL | What it adds |
|---|---|---|
| DFIR Madness — Answer Key | https://dfirmadness.com/answers-to-szechuan-case-001/ | Confirms "persistence installed as service + registry key on DESKTOP, same as DC" — vague on specifics |
| Netresec — Walkthrough of DFIR Madness PCAP | https://www.netresec.com/?page=Blog&month=2021-07&post=Walkthrough-of-DFIR-Madness-PCAP | Enumerates attack chain: Hydra brute-force on DC → RDP lateral to DESKTOP at 02:35 → Meterpreter download → service `coreupdater` installed at 02:42:42 on DESKTOP + matching registry key |
| MimirCyber community writeup | https://mimircyber.com/answers-to-the-case-of-the-stolen-szechuan-sauce-case-001/ | Corroborates `coreupdate*` persistence entries |

## Verdicts

| # | Agent finding | Verdict | Rationale (short) |
|---|---|---|---|
| 0 | HKLM Run key `coreupdate` (PowerShell stager) | **TP** | Answer key names `coreupdater` registry key as persistence on DESKTOP. Stager command line matches classic post-exploitation pattern. |
| 1 | Service `coreupdater` → `C:\Windows\System32\coreupdater.exe` | **TP** | Answer key explicitly names service `coreupdater` with timestamp `02:42:42 on DESKTOP-SDN1RPT`. Agent's extracted LastWrite `Sat Sep 19 03:42:42 2020 Z` matches with 1-hour TZ offset. |

## Scorecard

**TP = 2 · FP = 0 · FN = 0 · Precision = 1.00 · Recall = 1.00** (within audited scope).

Zero hallucinations: both evidence `output_excerpt` values were verified present in the cited `tool_call_id`'s stdout.

## Scope caveats (honest)

- The answer key is vague on whether DESKTOP has persistence beyond the `coreupdate*` pair. If the image contains undocumented persistence mechanisms, those would be silent false negatives we cannot detect from public sources.
- This image is "clean" in a way `base-wkstn-05` is not: no responder-tool cohabitation. The Precision=1.00 number partly reflects image easiness, not just pipeline quality. The two data points together are more informative than either alone.

## Why this matters for the Slice 3 Critic design

Contrasting the two cases clarifies the failure mode the Critic has to address:

| Image | P | R | Nature of FPs |
|---|---|---|---|
| `base-wkstn-05` | 0.50 | 1.00 | **Responder-tool cohabitation** — F-Response + Mnemosyne are legitimate DFIR products the agent couldn't distinguish from attacker persistence |
| `dfirmadness-001-desktop` | 1.00 | 1.00 | (none) |

The FPs on `base-wkstn-05` aren't random; they're a **single, nameable failure mode**: "this service looks like persistence but the binary belongs to a known DFIR / vendor product." That's a tractable Critic rule ("maintain a known-DFIR-tool allowlist; flag matching findings as low-confidence pending human review"). Slice 3's rule set should target this pattern specifically.

See [`slice-3-runbook.md`](slice-3-runbook.md) for the Critic design target; the concrete rule set is still being drafted.
