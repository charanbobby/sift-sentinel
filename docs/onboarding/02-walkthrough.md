# Onboarding walkthrough — one case, end-to-end

**Snapshot date:** 2026-04-19 post-Step-0 pipeline (pre-Slice-3 Phase C, pre-Slice-5).
**Case:** `dfirmadness-001-desktop` — DFIR Madness Case 001, DESKTOP image. Public CTF with a published answer key.
**Status:** ✅ clean run — TP=2 / FP=0 / FN=0 / Precision=1.00 / Recall=1.00 / Hallucinations=0.

This file walks through *one* pipeline run stage-by-stage, pointing at the actual on-disk artifacts each stage produced. It's a concrete companion to [architecture.md](../planning/architecture.md) — same flow, but with real inputs and outputs you can open.

**Why this case.** DFIR Madness Case 001 is a ~6-year-old public CTF with a [published answer key](https://dfirmadness.com/answers-to-szechuan-case-001/) and multiple community writeups ([Netresec](https://www.netresec.com/?page=Blog&month=2021-07&post=Walkthrough-of-DFIR-Madness-PCAP), [MimirCyber](https://mimircyber.com/answers-to-the-case-of-the-stolen-szechuan-sauce-case-001/)). You can independently verify our agent's findings against those references — it's the quickest way to build trust (or skepticism) about what the pipeline actually does.

**What's in this walkthrough that isn't in [`slice-2.5-ground-truth-dfirmadness.md`](../runbooks/slice-2.5-ground-truth-dfirmadness.md):** the ground-truth doc answers *"did we get the right answer?"* — this one answers *"what did the pipeline actually do at each stage?"*

---

## 0. Inputs

- **Evidence:** `/mnt/derived/dfirmadness-desktop.ntfs.dd` (14.4 GB raw NTFS partition).
- **Preprocessing note:** the source is a multi-segment E01 (`Desktop.E01, .E02 ...`). The SIFT toolchain's `fsstat`/`fls`/`icat` expect either a single E01 or a raw filesystem image — for a multi-segment E01 we pre-mount with `ewfmount` and `dd` out the NTFS partition into `/mnt/derived`. The MCP server's `_check_read_path` allowlist was extended to cover `/mnt/derived`. Recipe is in [`slice-2-runbook.md`](../runbooks/slice-2-runbook.md).
- **Investigation question (fixed for this pipeline):** *"Given a Windows disk image suspected of compromise, what persistence mechanisms did the attacker install?"*

---

## 1. EXTRACT — "what should we go look at?"

**Node:** `slice2.ipynb` C5. **Model:** `google/gemini-3.1-flash-lite-preview`. **Mode:** JSON schema-enforced.

Gemini takes the investigation question and emits **candidate artifact paths** — Windows forensic locations where persistence typically lives. No evidence touched yet; this is pure domain-knowledge enumeration.

Output (abridged from [`out/runs/dfirmadness-001-desktop/candidates.json`](../../experiments/slice-2-notebook/out/runs/dfirmadness-001-desktop/candidates.json)):

```json
{
  "candidates": [
    { "artifact_type": "registry_hive",     "path_hint": "HKLM\\Software\\...\\Run",            "priority": 1 },
    { "artifact_type": "registry_hive",     "path_hint": "HKCU\\Software\\...\\Run",            "priority": 1 },
    { "artifact_type": "scheduled_task_xml","path_hint": "C:\\Windows\\System32\\Tasks",        "priority": 1 },
    { "artifact_type": "service_config",    "path_hint": "HKLM\\System\\CurrentControlSet\\...","priority": 1 },
    ... 5 more at priority 2 / 3
  ]
}
```

9 candidate paths covering Run keys, Services, Winlogon, IFEO, AppInit, Shell Folders. **Think of this as the MITRE ATT&CK TA0003 lookup table** — the agent is narrowing from "any persistence" to the concrete hives + paths that could contain it.

---

## 2. PLAN — "here's the exact sequence of tool calls"

**Node:** `slice2.ipynb` C6. **Model:** `anthropic/claude-sonnet-4.6`. **Prompt caching:** on (stable system block cached; corrective-instruction block appended separately on retries).

Claude takes `candidates.json` + the MCP tool schemas + enumerated allowlisted RegRipper plugins, and emits a typed `ToolPlan` — an 18-step DAG with `depends_on` edges, tool args, and a per-step confidence.

Example from [`tool_plan.json`](../../experiments/slice-2-notebook/out/runs/dfirmadness-001-desktop/tool_plan.json) (abridged):

```json
{
  "steps": [
    { "step_id": 1,  "tool": "fsstat_e01",    "depends_on": [] },
    { "step_id": 2,  "tool": "fls_list",      "args": { "parent_inode": null },                                "depends_on": [] },
    { "step_id": 3,  "tool": "fls_list",      "args": { "parent_inode": "{step:2.inode_by_name(Windows)}" },   "depends_on": [2] },
    { "step_id": 6,  "tool": "icat_extract",  "args": { "inode": "{step:5.inode_by_name(SOFTWARE)}" },         "depends_on": [5] },
    { "step_id": 11, "tool": "regripper_run", "args": { "hive_path": ".../SOFTWARE", "plugin": "run" },        "depends_on": [6] },
    { "step_id": 17, "tool": "regripper_run", "args": { "hive_path": ".../SYSTEM", "plugin": "services" },     "depends_on": [7] },
    ... 12 more
  ],
  "expected_findings_range": [1, 5]
}
```

**Three things worth noticing:**

1. **Step-result interpolation.** `{step:5.inode_by_name(SOFTWARE)}` is a structured reference to a downstream-resolvable field from step 5's output. The executor resolves these at runtime — the LLM doesn't need to predict inode numbers.
2. **Structural invariants (enforced before the plan runs).** Every `regripper_run` step must have an `icat_extract` upstream in its `depends_on` chain. This is a pure-Python gate in C6 — malformed plans never reach EXECUTE. See [PLAN.md](../planning/PLAN.md) for the 2026-04-19 Key Decision row.
3. **`expected_findings_range: [1, 5]`.** The agent declares up-front how many persistence findings it expects — an anti-over-extraction guard. If INTERPRET later produces 12 findings, the Critic (R_08) flags it as scope drift.

---

## 3. Human gate (L1: Assisted Workflow)

Marker file [`tool_plan.APPROVED`](../../experiments/slice-2-notebook/out/runs/dfirmadness-001-desktop/tool_plan.APPROVED) is written by a human reviewer before EXECUTE runs. Today this is literally `touch tool_plan.APPROVED` after reading `tool_plan.json`; at L3 (Slice 6) it becomes a policy-file decision with auto-approval for low-risk plans.

*In your vocabulary: this is the "analyst reviews the SOAR playbook before it fires" checkpoint.*

---

## 4. EXECUTE — the MCP tool calls

**Node:** `slice2.ipynb` C8. **Transport:** MCP stdio over `docker exec` (Slice 5 swaps to HTTP/SSE).

LangGraph dispatches each plan step to the MCP server, resolving `{step:N.field}` references from the accumulated state. Every call is captured in [`raw_results.jsonl`](../../experiments/slice-2-notebook/out/runs/dfirmadness-001-desktop/raw_results.jsonl) with a `tool_call_id`.

The two calls that ultimately drove the findings:

| Step | Tool | What it did | Output shape |
|---|---|---|---|
| 11 | `regripper_run` (plugin=`run`) | Ran RegRipper's `run` plugin against the extracted SOFTWARE hive | Text dump of every `HKLM\...\Run` / `RunOnce` value |
| 17 | `regripper_run` (plugin=`services`) | Ran `services` plugin against the SYSTEM hive | Text dump of every service with ImagePath, Start type, Group |

Both returned structurally valid, non-empty output. All 18 steps executed cleanly; no errors, no retries needed on this case.

*In your vocabulary: this is the SOAR playbook firing its tool integrations and capturing the raw results into a case-bound evidence store.*

---

## 5. INTERPRET — "which of these findings are actually attacker persistence?"

**Node:** `slice2.ipynb` C9. **Model:** `anthropic/claude-sonnet-4.6`. **Prompt caching:** on.

Claude reads all 18 tool outputs and emits typed `Finding` objects. This is the stage that had the most engineering attention — **Step 0 prompt hardening (2026-04-19)** added a required `classification` field (`attacker_persistence` / `legitimate_responder_tool` / `legitimate_vendor_product` / `windows_default` / `unknown_suspicious`) plus explicit disambiguation rules + a masquerading counter-rule.

Result from [`findings.json`](../../experiments/slice-2-notebook/out/runs/dfirmadness-001-desktop/findings.json):

### Finding 1 — HKLM Run key `coreupdate`

```
mechanism: HKLM Run key — PowerShell stager with base64-encoded payload from registry
value:     %COMSPEC% /b /c start /b /min powershell -nop -w hidden -c
           "sleep 0; iex([System.Text.Encoding]::Unicode.GetString(
             [System.Convert]::FromBase64String(
               (Get-Item 'HKLM:Software\q9Z1bssi').GetValue('JqxNhWJA'))))"
classification: attacker_persistence
confidence:     high
evidence:       tool_call_id 79ab74b7-... (step 11, regripper_run/run on SOFTWARE)
```

**The `notes` field from this finding shows the disambiguation working** — this is the kind of reasoning artifact the Critic then checks:

> *"Value name 'coreupdate' mimics a legitimate update process, but the command launches a hidden, non-profiled PowerShell session that reads a base64-encoded payload from an obfuscated registry key (HKLM:Software\q9Z1bssi / JqxNhWJA) and executes it via IEX — a classic Metasploit/Cobalt Strike in-memory stager pattern. **Ruled out DFIR tools:** not matching any known responder tool signature. **Ruled out vendor products:** no McAfee/VMware/Defender/Symantec naming convention. **Ruled out Windows defaults:** no legitimate Windows component uses this obfuscated registry blob pattern."*

Those three "ruled out" clauses are the direct output of Step 0's prompt hardening — the equivalent of a disambiguation playbook in detection engineering. On `base-wkstn-05` (pre-Step-0) the agent classified F-Response and Mnemosyne as attacker persistence because it didn't have this disambiguation habit; post-Step-0 both were correctly suppressed.

### Finding 2 — Windows service `coreupdater`

```
mechanism: Windows service auto-start — suspicious exe in System32 masquerading as update service
value:     C:\Windows\System32\coreupdater.exe
classification: attacker_persistence
confidence:     high
evidence:       tool_call_id 0f7f45a6-... (step 17, regripper_run/services on SYSTEM)
output_excerpt: "Sat Sep 19 03:42:42 2020 Z
                   Name      = coreupdater
                   ImagePath = C:\Windows\System32\coreupdater.exe
                   Type      = Own_Process
                   Start     = Auto Start"
```

Same disambiguation discipline — ruled out DFIR tools, ruled out vendor products (not McAfee/VMware/Defender/Google/Adobe), ruled out Windows defaults (not in the `Perf*` / `RPC*` / `TCP-IP` / storage driver families).

**ATT&CK mapping.** Both findings get `attack_id` + `attack_name` + `attack_tactic_id` auto-populated by a Pydantic `model_validator` from the `category` field — the LLM's output on those fields is *discarded*. Finding 1 → T1547.001 (Registry Run Keys / Startup Folder). Finding 2 → T1543.003 (Windows Service). Both under TA0003 Persistence.

---

## 6. CRITIC — the detection engineering gate

**Node:** `slice2.ipynb` C10. **Rules active at the time of this run:** 11 (R_01–R_11).

Deterministic Python — no LLM call. Every rule runs against the `Finding` list; any failure produces a structured error + correction template that gets threaded back into the next PLAN / INTERPRET attempt.

On this run, **all 11 rules passed.** The file [`findings.SUCCESS`](../../experiments/slice-2-notebook/out/runs/dfirmadness-001-desktop/findings.SUCCESS) is the marker written when the Critic clears. Examples of what ran and passed on this case:

| Rule | What it checks | Outcome on this run |
|---|---|---|
| R_02 | Schema valid (Pydantic) | ✅ — both findings parse |
| R_05 | Every `output_excerpt` appears verbatim in `tool_calls.jsonl` | ✅ — both excerpts grep-match |
| R_07 | Tool-category consistency (registry findings cite registry tools) | ✅ — both cite RegRipper |
| R_08 | Finding count within `expected_findings_range` | ✅ — 2 is within [1, 5] |
| R_09 | Every finding has a non-null `classification` | ✅ — both `attacker_persistence` |
| R_11 | Masquerading reasoning present when `category=service` or `registry_run_key` | ✅ — `notes` field contains the required disambiguation clauses |

**Honesty note on what this run does NOT show.** The Critic had **11 rules at run time**. Two more landed the next day (2026-04-20) in Slice 3 Phase C:

- **R_12 — Evidence-of-absence vs absence-of-evidence** (minimum-viable version): gates `findings: []` results on the collection tools actually having run cleanly.
- **R_13 — Temporal consistency** (stub only): will cross-reference agent-claimed timestamps against hive LastWrite data once the dual-channel structured metadata lands in Slice 5.

Re-running this case against the 13-rule Critic is a natural regression-baseline task — it's exactly the shape of work the Slice 6 Reference Dataset annotation will produce at scale.

---

## 7. Scoring

`score.py` reads [`findings.json`](../../experiments/slice-2-notebook/out/runs/dfirmadness-001-desktop/findings.json) + [`ground_truth.json`](../../experiments/slice-2-notebook/out/runs/dfirmadness-001-desktop/ground_truth.json) and emits [`scorecard.json`](../../experiments/slice-2-notebook/out/runs/dfirmadness-001-desktop/scorecard.json):

```json
{
  "counts": { "TP": 2, "FP": 0, "FN": 0, "UNCLEAR": 0 },
  "precision": 1.00,
  "recall":    1.00,
  "hallucination_count": 0,
  "verdicts": [
    { "index": 0, "summary": "HKLM Run key 'coreupdate' — PowerShell stager ...",  "verdict": "TP" },
    { "index": 1, "summary": "Windows auto-start service 'coreupdater' ...",        "verdict": "TP" }
  ]
}
```

**Hallucination count.** Separate from FP. A finding is a "hallucination" if its `output_excerpt` doesn't appear anywhere in `tool_calls.jsonl` — i.e., the LLM made up a quote. On this run: 0. This metric is what R_05 enforces structurally; `score.py` recomputes it as an independent verification pass.

---

## 8. Independent verification against external sources

From [`slice-2.5-ground-truth-dfirmadness.md`](../runbooks/slice-2.5-ground-truth-dfirmadness.md):

| Finding | Cross-reference |
|---|---|
| HKLM Run key `coreupdate` | Answer key names `coreupdater` registry key as persistence on DESKTOP. Stager command line matches classic post-exploitation pattern. |
| Service `coreupdater` → `C:\Windows\System32\coreupdater.exe` | Answer key explicitly names service `coreupdater` with timestamp `02:42:42 on DESKTOP-SDN1RPT`. Agent's extracted LastWrite `Sat Sep 19 03:42:42 2020 Z` matches with 1-hour TZ offset. |

The timestamp match with 1-hour TZ offset is the kind of convergent evidence that makes this a genuinely clean baseline rather than an artifact-lucky run.

---

## 9. What this walkthrough illustrates (and what it doesn't)

**Illustrates well:**

- ✅ The full pipeline topology: EXTRACT → PLAN → gate → EXECUTE → INTERPRET → CRITIC.
- ✅ Prompt caching + Step 0 disambiguation producing structurally clean findings.
- ✅ The detection-engineering shape of the Critic.
- ✅ ATT&CK auto-mapping from `category` via Pydantic validator.
- ✅ The happy path — no retry needed.

**Does NOT illustrate (future work):**

- ⬜ **Self-correction retry loop.** Because the Critic passed on first attempt, you don't see the `re_plan` → debounce → plan-hash dedup → retry path in action. Look at `slice2.ipynb` C14 synthetic scenarios for that.
- ⬜ **Dual-channel evidence handler** (Slice 5). The 2 findings above both cite `output_excerpt` strings that today come straight from `stdout` — post-Slice-5 they'll come from server-side structured extraction, and raw bytes will go to the ledger untouched.
- ⬜ **Capability tokens.** This run used no token enforcement; the MCP server trusted the plan. Slice 5 adds the `(case_id, tools, paths, plan_digest, expiry)` check.
- ⬜ **Linear hash chain.** `plan_digest` is recorded in `findings.json` but not yet chained to prior runs or stored in a separate ledger. Slice 6.
- ⬜ **R_12 + R_13.** See §6 above — landed the day after this run.
- ⬜ **Hadi3 negative case.** The real Critic stress test is a no-persistence image; this case is a **positive** baseline.

**If you want to see all of the above in action, Slice 5 + Slice 6 runs will produce the walkthrough evidence — worth a re-run on this same case once those land (regression baseline).**

---

## 10. How to reproduce

The full reproduction recipe is in [`slice-2-runbook.md`](../runbooks/slice-2-runbook.md). At a high level:

1. Bring up the SIFT container ([`slice-1-docker-runbook.md`](../runbooks/slice-1-docker-runbook.md)).
2. Stage the DFIR Madness E01 under `HACKATHON-2026/dfirmadness-desktop/`.
3. Pre-mount the multi-segment E01 → raw NTFS: `ewfmount` → `dd` into `/mnt/derived`.
4. Open `slice2.ipynb`, set the case id to `dfirmadness-001-desktop`, run C1–C11.
5. When C6 outputs `tool_plan.json`, review it. `touch tool_plan.APPROVED` to proceed.
6. C8 executes the plan; C9 INTERPRETS; C10 runs the Critic.
7. `score.py` reads the output and produces `scorecard.json`.

Expect ~21 seconds wall-clock for steps 4–7 on a warmed-cache run (the two Claude calls dominate; tool execution is fast on a 14 GB NTFS image).

---

**Next recommended reading:** [`docs/planning/architecture-detailed.md`](../planning/architecture-detailed.md) §7 — the full Critic rule catalog (R_01–R_13, what each catches, where it fires). Once you've seen the rule set and this walkthrough, the Slice 5 runbook ([`slice-5-runbook.md`](../runbooks/slice-5-runbook.md)) reads as concrete engineering work rather than a concept.
