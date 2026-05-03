# Memory channel risk factors (2026-05-02)

Snapshot of what we learned about the memory-evidence pipeline tonight, and what is still unbuilt or fragile. Carries forward from `memory-pipeline-analysis-2026-05-01.md` with the validation results and a refined understanding.

## Validated tonight

The dual-channel pipeline works end-to-end. Confirmed by `srl-2018-base-wkstn-05-dual-002` at 2026-05-02T01:01:05Z. All 10 failure points from the prior failure-point analysis (M1 through M10) are green:

| # | Layer | Result | Evidence |
|---|---|---|---|
| M1 | Volatility 2 install | PASS | vol.py 2.6.1 in sift-mcp |
| M2 | Profile knowledge | PASS | Win7SP1x64 set on case manifest |
| M3 | Profile detection | n/a | known profile |
| M4 | MCP wrapper accepts staged path | PASS | `/tmp/base-wkstn-05-memory.img` accepted |
| M5 | PLAN with proper memory args | PASS | `image_path` arg key correct, plugins from allowlist |
| M6 | Plan-coverage trim preserves volatility_run | PASS | 4 vol steps survived in run-002 |
| M7 | EXECUTE happy path | PASS | exit 0, evidence written |
| M8 | INTERPRET bundle size | PASS | 129k input tokens, fit in budget |
| M9 | INTERPRET memory rules | PASS | 4 findings emitted, correct categories and tactic mapping |
| M10 | Cost ceiling | PASS | $0.53 vs $0.30-0.50 estimate, single percent overrun |

## The /tmp staging constraint (key finding)

The MCP volatility_run wrapper restricts memory-image paths to `/var/lib/find-evil/memory`, `/home/sansforensics`, and `/tmp`. It does NOT accept `/mnt/hackathon/`.

This is intentional. Bind-mounted reads from `/mnt/hackathon/` clock at ~1.5 MB/s on Windows Docker Desktop, making per-plugin Volatility runs unusably slow. The design requires staging each dump into a container-fast location first.

**Implications for any future memory work:**
- A 3 GB memory dump takes ~30 minutes to copy from `/mnt/hackathon` to `/tmp` (bottlenecked by the bind-mount read speed, not disk write speed).
- For 18 dumps total at this rate, full staging is 9+ hours of pure cp time.
- The right longer-term fix is to provision the `/var/lib/find-evil/memory` named Docker volume in `docker/compose.yml` so dumps stage once and persist across container restarts.
- The current `/tmp` staging is ephemeral. Container restart loses it.

## Profile detection latency

`vol.py imageinfo` on a bind-mounted dump is also slow (KDBG search reads many offsets). Running rd-01 and rd-02 imageinfo via bind mount tonight took >15 minutes each and were still in the KDBG-search phase when interrupted. Once a dump is staged into `/tmp`, imageinfo should drop to a few minutes.

**Profile catalog as of 2026-05-02:**

| Host | Profile | Source | Verified |
|---|---|---|---|
| base-wkstn-05 | Win7SP1x64 | dataset_manifest.md | yes (used in dual-002) |
| base-file | Win2012R2x64 | dataset_manifest.md | yes (kdbgscan + pslist prior) |
| base-dc | Win2016x64_14393 | dataset_manifest.md | yes (kdbgscan + pslist prior) |
| base-mail | unknown | needs imageinfo | no |
| base-rd-01 | unknown | needs imageinfo | no (in flight via bind mount, slow) |
| base-rd-02 | unknown | needs imageinfo | no (in flight via bind mount, slow) |
| base-wkstn-01 | unknown | needs imageinfo | no |
| 11 memory-only hosts | unknown | needs imageinfo | no |

## Memory-only mode is NOT shipped

The pipeline currently requires a paired E01 disk image. Memory-only runs (the 11 memory-only SANS hosts: admin, elf, hunt, rd-03, rd-04, rd-05, sp, wkstn-02, wkstn-03, wkstn-04, wkstn-06) are not yet supported.

**Code in flight tonight (NOT VALIDATED, do not rely on):**

I started a memory-only support pass that is partially complete. The changes are backward-compatible with dual-channel runs (default `has_disk=True`) but the new memory-only code path is unfinished:

| File | Change | Status |
|---|---|---|
| `run_case.py` | `--e01` made optional, runtime guard requires at least one channel | done |
| `pipeline/nodes.py:_available_tools_spec` | added `has_disk` parameter, omits disk tools when False | done |
| `pipeline/nodes.py:_plan_system_prompt` | accepts `e01_path=None`, computes `has_disk`, raises if neither channel | done |
| `pipeline/nodes.py:_plan_system_prompt` body | "Argument templating", "Filesystem navigation", and "Hard rules" are still 100% disk-specific in the rendered prompt even when `has_disk=False` | NOT DONE |
| `pipeline/nodes.py:_build_extract_prompt` | does not yet branch for memory-only; "Universal Windows persistence locations" + "Web-shell drop locations" sections always render | NOT DONE |
| `pipeline/nodes.py:extract_node` | does not pass `has_disk` to the prompt builder | NOT DONE |

**To finish memory-only support, the unbuilt work is roughly:**

1. Rewrite or gate the disk-specific PLAN prompt sections (Argument templating, Filesystem navigation, Hard rules for hives + scheduled tasks) so they are absent when `has_disk=False`.
2. Add a memory-only branch to `_build_extract_prompt` that:
   - Replaces "Universal Windows persistence locations" with memory-only candidate guidance.
   - Removes the "File-drop staging locations" and "Web-shell drop locations" sections.
   - Uses `channels="memory only"` in the prompt header.
3. Update `extract_node` to compute `has_disk = bool(E01_PATH)` and pass it through.
4. Probe with one host (suggested: stage wkstn-05 mem to /tmp and re-run with `--e01` omitted; we have a known profile and a known-positive comparison from the dual run).
5. Validate the 11 memory-only hosts produce sensible findings.

Estimated effort: 2-3 hours of focused prompt engineering plus probe iteration. Cost per validation run ~$0.50.

## Cost profile (single dual-channel run)

For a dual-channel run on an SRL-2018 host of comparable size to wkstn-05:

| Phase | Input tokens | Output tokens | Cost |
|---|---|---|---|
| extract (Gemini Flash) | 1,745 | 890 | $0.0035 |
| plan (Sonnet 4.6) | 4,975 | 3,932 | $0.077 |
| interpret (Sonnet 4.6) | 129,332 | 3,726 | $0.450 |
| **Total** | | | **$0.53** |

The interpret stage dominates because the bundle includes pslist, cmdline, netscan, and malfind output plus the full disk-side evidence. Hosts with larger memory dumps or noisier process tables (DC, mail server) may push the bundle higher and need a re-check against the size-guard rule.

## Open risks for the dual-channel sweep

1. **Bundle size on busier hosts.** wkstn-05 fit at 129k input tokens. A domain controller's pslist + netscan is materially larger. If interpret bundle exceeds ~180k tokens, costs spike and possibly the model context window. Watch the cost-print line on each run; if input >150k, investigate before continuing.
2. **/tmp space on sift-mcp.** Each dump is 2-5 GB. Six staged at once is ~20 GB. /tmp on Docker Desktop is overlay-backed with finite headroom. If `cp` fails with ENOSPC, prune older staged dumps before continuing.
3. **Profile detection on unknown-profile hosts.** mail, rd-01, rd-02, wkstn-01 need imageinfo before their dual run can use the right profile string. The right pattern is: stage to /tmp, run imageinfo on the staged copy (fast), then run the pipeline.
4. **Pipeline run lock.** Two simultaneous runs against the same case_id confused the run-NNN allocator earlier today. Run dual sweep serially per case, parallel across cases is fine.
5. **Defender-AI canary.** Each run mints a new canary token; INTERPRET halts if the LLM echoes it. Has not falsely triggered to date. Note in case it does.

## What was changed in the codebase tonight

| Change | Type | Status |
|---|---|---|
| Allowlist regression for volatility paths | NONE; existing allowlist stands | working as designed |
| `run_case.py --e01` from required to optional | code | shipped, dual-compatible |
| `_available_tools_spec(has_disk=True)` parameter added | code | shipped, dual-compatible |
| `_plan_system_prompt(e01_path: str | None)` signature | code | shipped, dual-compatible (the body is still disk-specific) |
| Memory-only PLAN prompt body | code | NOT DONE |
| Memory-only EXTRACT prompt body | code | NOT DONE |
| Document of memory channel risks (this file) | docs | shipped |

The two "NOT DONE" items are the only blocker between current state and shipping memory-only support for the 11 memory-only hosts.
