---
created: 2026-05-09
case: openuni22-server (memory-only)
run: openuni22-server-001
status: real bug
---

## TL;DR

The run did not actually run as memory-only. The planner produced a 32-step disk-image plan against `/mnt/derived/openuni22-server.raw`, which is a **whole-disk image with a DOS/MBR partition table**, not a partition-extracted NTFS volume. Step 1 (`fsstat_e01`) and step 2 (`fls_list`) were invoked at sector 0, where there is no filesystem; both tools wrote no usable output, so fsstat returned `parse_error` and fls returned `status="empty"`. The placeholder resolver guard then correctly refused to chain `inode_by_name(...)` against an empty upstream, blocking 30 of the 32 steps. The "empty" classification is sound. The real bugs are upstream: (1) the staging step never partition-extracted `openuni22-server.raw` into a single-FS dump like the SRL-2018 `base-*.ntfs.dd` files, and (2) the executor invokes `fsstat` / `fls` without a partition offset, so it cannot succeed against any whole-disk image.

## What step 2 was

- Tool: `fls_list`
- Args: `{"e01_path": "/mnt/derived/openuni22-server.raw", "parent_inode": null, "recurse": false}`
- Purpose (from the plan): "List root directory entries to locate top-level folders (Windows, Users, inetpub, ProgramData, etc.)."
- Expected output: a populated `FlsResult.entries` list of root-level NTFS directory entries with `inode`, `filename_safe`, and `entry_type`. Step 3 (and steps 4, 5, 27, 31, 32) all reference it via placeholders such as `{{step:2.inode_by_name(Windows)}}`, `{{step:2.inode_by_name(Users)}}`, etc.

Note also that step 1 is `fsstat_e01` against the same `openuni22-server.raw` and came back with `tool_execution_status="parse_error"`, `fs_type="unknown"`, `block_size=0`. fsstat had no filesystem to read either, but step 1 has no downstream `depends_on=[1]` references, so its failure did not cascade. The cascade started at step 2.

## What step 2 actually returned

Verbatim from `04_execute_evidence.jsonl` (line 2):

```json
{
  "tool_call_id": "ac5f9a86-c2f4-4f8c-812a-8992afbea53e",
  "raw_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "raw_path": ".../openuni22-server/analysis/raw/ac5f9a86-c2f4-4f8c-812a-8992afbea53e.raw",
  "structured_fields": {"entries": []},
  "injection_flags": [],
  "expected_paths_covered": ["/mnt/derived/openuni22-server.raw"],
  "tool_execution_status": "empty",
  "issued_at": "2026-05-07T09:56:46.398847Z",
  "token_id": "5673ff13-7a2f-4a83-bbcc-db75eb69e14e"
}
```

Two pieces of forensic evidence:

1. `raw_sha256 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` is the SHA-256 of the empty string. fls produced literally zero bytes of stdout. The file at `raw_path` is a 0-byte file.
2. `structured_fields.entries = []` is the parser's faithful rendering of "no rows".

`expected_paths_covered` shows fls was pointed at `/mnt/derived/openuni22-server.raw`. There is no `-o <offset>` argument anywhere in the args dict.

## Why the resolver flagged it empty

Two layers cooperate, both correctly given their inputs.

**Parser layer** (`pipeline/mcp/parsers.py`):

```python
def parse_fls(stdout: bytes) -> tuple[FlsResult, str]:
    if not stdout:
        return FlsResult(entries=[]), "empty"
    ...
```

When `fls` writes nothing to stdout, the parser tags the record `status="empty"`. This is a deliberate distinction from `parse_error`: empty stdout from fls in normal operation is rare but legitimate (a directory with zero entries). The contrast with `parse_fsstat`, where the comment dated 2026-04-27 explicitly says empty stdout is a parse_error not empty (because fsstat always prints metadata on success), confirms this is by design.

**Resolver layer** (`pipeline/nodes.py`, around line 1368):

```python
upstream = evidence_by_step_id[step_n]
if upstream.tool_execution_status != "ok":
    raise ResolverError(
        f"upstream step {step_n} status="
        f"{upstream.tool_execution_status}; cannot chain"
    )
```

The resolver demands `tool_execution_status == "ok"` before it will run any extractor (`inode_by_name`, `nth_file_inode`). Both `empty` and `parse_error` block chaining. This is the right rule for `inode_by_name`, since picking an inode out of an empty list of entries is undefined.

The criterion is sound for memory-only volatility tools too. Volatility plugins like `pslist` always emit a header and at least System/PID 4 on a valid memory dump, so their parsers reserve `empty` only for a hand-picked allowlist (`_VOL_EMPTY_LEGITIMATE` in parsers.py). For fls specifically, an empty root directory is impossible on a real NTFS volume (there is always `$MFT`, `$LogFile`, `.`, etc.), so seeing `entries: []` for `parent_inode=null, recurse=false` is itself a strong signal that fls failed to find a filesystem at all, not that the filesystem is empty.

## Verdict: real bug or correct behavior

**Real bug, but the resolver and the parsers are not where the bug lives.**

The resolver did the right thing: refusing to chain `inode_by_name(Windows)` against `entries: []` is correct. Returning `status="empty"` from `parse_fls` on zero-byte stdout is correct. The Critic correctly escalated to human review on `R_15 LOW_CONFIDENCE_AUTO_ESCALATE`. The integrity ledger chain verified clean.

The bug has two components, both **upstream of the executor**:

1. **Image staging is incomplete for openuni22-server.** The file `/mnt/derived/openuni22-server.raw` is a 50 GB whole-disk image with a DOS partition table. Direct probe via `mmls` inside `sift-mcp` shows four entries (NTFS at sector 2048, NTFS at sector 206848, an Unknown 0x27 partition, and unallocated). `fsstat` against the whole image returns `Cannot determine file system type`; `fsstat -o 206848 /mnt/derived/openuni22-server.raw` returns a clean NTFS header for that case. The peer file `/mnt/derived/openuni22-server-cdrive.raw` (52.9 GB, dated 2026-05-07 22:43, which is *after* the 09:56 run) is a partition-extracted single-FS NTFS dump that fsstat parses correctly. So the partition extract was added later; the run on 2026-05-07 09:56 used the broken whole-disk file, exactly like SRL-2018 cases use `base-dc.ntfs.dd` rather than `base-dc.raw`.

2. **The executor's fsstat / fls invocations have no partition-offset support.** The schema for `fsstat_e01` and `fls_list` accepts only `e01_path` (and `parent_inode` / `recurse` for fls). There is no `partition_offset` arg. Whatever path the planner is given, the executor invokes the tool against byte 0. If the file happens to be a single-FS dump, that works; if it is a whole-disk image, both tools fail silently into `parse_error` / `empty`. There is no preflight check that proves the path is a single-FS dump before the LLM-priced INTERPRET stage runs.

Compounding this, the case is misnamed. The run log header says `case_id openuni22-server`, but the entire 32-step plan is disk tools (fls_list, fsstat_e01, icat_extract, regripper_run, scheduled_tasks_parse). There is no `volatility_run`. The contrast with the successful `srl-2018-base-rd-04-memonly-002` is stark: that run's plan is 5 volatility steps with `image_path: /tmp/base-rd-04-memory.img` and zero disk tools, and step 1 returns `tool_execution_status="ok"` with 80+ processes in `structured_fields.processes`. Either the openuni22-server case has no memory dump available (so the planner correctly fell back to disk) or `has_disk=True` was set when it should have been false. Per the project memory note "Machine coverage gaps: 6 source machines in HACKATHON-2026/ never run (Win Server 2022 OpenUni22, ...)" this looks like the disk-only branch.

## If real bug: 1-paragraph fix sketch

The fix is in two layers. **Staging:** the case-creation step that places `openuni22-server.raw` into `/mnt/derived/` should run `mmls`, identify the largest NTFS partition (here sector 206848 onward, ~49 GB), and either (a) extract that partition into `openuni22-server-cdrive.raw` and point the planner at *that* path (consistent with `base-dc.ntfs.dd` and the existing `openuni22-server-cdrive.raw` peer file), or (b) record the partition offset alongside the case so downstream tools can pass `-o`. Option (a) is more consistent with current pipeline conventions and removes the offset concern entirely. **Executor preflight:** before the planner runs, add a one-line `fsstat` smoke probe on the staged path; if it returns non-zero or empty stdout, fail the run with a clear `case_setup_error` *before* spending PLAN tokens on a 32-step plan that cannot succeed. The current behavior burns the full PLAN + INTERPRET LLM cost ($0.12 on this run) before discovering the image cannot be read at all. A 30-second `fsstat` probe at run start would have caught it.

## If correct behavior: not applicable

This was not a memory-only case running into a memory-only limitation. The plan is entirely disk-side and the resolver behaved correctly given the broken upstream. The fix belongs at staging and preflight, not in planner heuristics for memory-only cases. The earlier hypothesis in the run log line `Propagated attribute 'metadata.has_memory' value is not a string` suggests the runtime did treat this as a disk case (memory metadata dropped), which lines up with the all-disk plan. If the intent of this case was actually memory-only, then the secondary bug is that the case was never given a memory dump path and the planner had nothing but disk tools available, and `has_disk=True` was wrong.
