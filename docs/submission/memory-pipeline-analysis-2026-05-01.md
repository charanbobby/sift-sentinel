# Memory pipeline end-to-end failure-point analysis

Date: 2026-05-01. Triggered by the wkstn-01 dual-channel run failing within 3 minutes due to a stack of small bugs. Goal: map every place the memory pipeline can break, design a fast-fail probe per layer, and run them cheapest-first so we burn one probe to learn each thing instead of one full pipeline run.

## Failure points (in pipeline order)

| # | Layer | Failure mode | Probe (cheapest first) | Spend | Status |
|---|---|---|---|---|---|
| M1 | Volatility 2 install | vol.py missing in container | `docker exec sift-mcp vol.py --version` | $0 | PASS, Vol 2.6.1 present |
| M2 | Profile knowledge | We don't know the right Vol profile per host | grep `dataset_manifest.md` | $0 | PARTIAL, 3 of 7 hosts have known profile (wkstn-05, file, dc) |
| M3 | Profile detection | When unknown, can we detect it? | `vol.py imageinfo` | $0 | IN FLIGHT for wkstn-01 |
| M4 | MCP wrapper | volatility_run tool refuses bad args | direct MCP call with intentional bad args | $0 | not yet probed |
| M5 | PLAN with proper memory args | LLM emits correct arg keys / plugin allowlist | dump PLAN output with `--memory-profile` set | ~$0.07 (one Sonnet call) | not yet probed |
| M6 | Plan-coverage trim | volatility_run gets removed by R_17 plan-coverage gate | inspect plan + critic decisions on a real run | included in M5 | not yet probed |
| M7 | EXECUTE happy path | A volatility_run actually returns evidence | direct MCP call with valid profile + plugin | $0 | not yet probed |
| M8 | INTERPRET bundle size | Vol output blows the bundle past safe-cost cap | look at netscan/dlllist trims in `_build_interpret_bundle` | $0 (read code) | code path exists; needs runtime confirmation |
| M9 | INTERPRET memory rules | Prompt explains how to interpret pslist/cmdline/etc | grep `INTERPRET_SYSTEM_PROMPT` for memory section | $0 (read prompt) | not yet probed |
| M10 | Cost ceiling | Memory-channel run does NOT exceed reasonable spend | run-cost telemetry on the first end-to-end success | depends on M5–M9 | not yet probed |

## What we learned from the wkstn-01 dual-channel failure

The run hit two stacked failures simultaneously:

1. **My invocation error.** I forgot `--memory-profile`, so `MEMORY_PROFILE` stayed None and the PLAN prompt's `has_memory` flag was False. The pipeline never advertised `volatility_run` to the LLM in its tool spec.
2. **LLM hallucination despite (1).** The LLM emitted `volatility_run` plan steps anyway, with `memory_image` as the arg key (should be `image_path`), the disk image path as the value (should be the memory dump path), and the plugin `pstree` (not in the allowlist of `pslist`/`cmdline`/`netscan`/`dlllist`/`malfind`).

Failure (2) is the real concern. Even if (1) is fixed, the LLM apparently invents memory tool calls by pattern-matching from training data. The PLAN ToolPlan schema accepts any tool name string, so validation runs downstream during EXECUTE rather than at PLAN time. Worth a small schema tightening: reject tool names not in the case's tool spec at parse time.

## Known profile map (ground truth as of 2026-04-25)

| Host | Profile | Build | OS | Verified |
|---|---|---|---|---|
| base-wkstn-05 | `Win7SP1x64` | 7601 | Windows 7 SP1 x64 | kdbgscan + 5 plugins |
| base-file | `Win2012R2x64` | 9600.16452 winblue_gdr | Server 2012 R2 | kdbgscan + pslist |
| base-dc | `Win2016x64_14393` | 14393.2214 rs1_release | Server 2016 | kdbgscan + pslist |

Unknown profiles needing M3 detection before any LLM run:
- base-rd-01 (`base-rd01-memory.7z`)
- base-rd-02 (`base-rd-02-memory.7z`)
- base-wkstn-01 (`base-wkstn-01-mem.zip`, currently extracted to `base-wkstn-01-memory/base-wkstn-01-mem.img`)
- base-mail (extracted to `base-mail-memory/base-mail-memory.img`)
- 12 memory-only hosts (admin, elf, hunt, sp, rd-03/04/05, wkstn-02/03/04/06)

## Suggested run order once M3 returns the profile for wkstn-01

1. **Direct MCP `volatility_run` call with hand-crafted args** (M4 + M7). Use the profile we just detected, plugin `pslist`, target the wkstn-01 memory dump. Confirms the MCP wrapper works end-to-end with no LLM involvement. Free.
2. **PLAN-only call with `--memory-profile` set** (M5). Run just the PLAN node and dump the produced steps to confirm the LLM uses `image_path` and a plugin from the allowlist. About $0.07 in OpenRouter spend.
3. **Full pipeline pass on wkstn-01 dual-channel** (M10). About $0.30 to $0.50 expected if M1 to M9 passed.
4. **Detect profiles for the other 4 disk+memory hosts** (kdbgscan, free per host).
5. **Selectively run highest-value memory cases** based on what (3) revealed.

Total cost budget if all probes pass: about $0.70 to $1.00 to validate the memory pipeline end-to-end on wkstn-01. After that, each additional case is ~$0.30 to $0.50 depending on bundle size.

## Cost-print discipline (added 2026-05-01)

Every OpenRouter call from any script (pipeline, probe, ad-hoc) now uses `scripts/llm_cost.py`. PRE prints estimated input tokens before the call. POST prints actual input/output tokens and total cost from `usage.cost` (or rate-table fallback). Silent zero-cost is forbidden. This was the rule for the pipeline already; today we extended it to probes.
