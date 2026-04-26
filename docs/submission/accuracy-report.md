# Accuracy Report — Find Evil (SANS Hackathon 2026)

**Status:** updated 2026-04-26 with first dual-channel (disk + memory) run on `srl-2018-wkstn-05` (run-005). Sections marked **TODO** still await data the system has not yet collected (ablation rows 2 + 4, regression-gate re-runs against the patched R_05 code, ground-truth annotation of the new memory-channel findings).

This document is the named "Accuracy Report" deliverable required by `docs/reference/hackathon/rules.md` §4 #5. It is intended to be read by a human reviewer (the SANS judge) who has not run our pipeline. Sections are written plain English first, with details after.

---

## 1. Executive summary

**Plain English (one paragraph):** We built an autonomous AI agent that examines a Windows disk image (and now also a Windows memory dump) and tells you what an attacker did to maintain access to the machine, plus what that attacker is *currently doing* if a memory snapshot is available. Top-level claim: on three machines where we have an official answer key, the agent gets every malicious disk-side item right and never invents anything that isn't there. On three more machines without an answer key, an independent human review found every finding the agent surfaced was sensible, every citation it gave pointed at a real piece of evidence, and the system stayed quiet when there was nothing to report. With the memory channel turned on, the agent additionally surfaced four runtime findings on one workstation (process injection in three system processes plus a likely command-and-control beacon); these need a human to review and grade against ground truth, but every claim cites real evidence from the memory dump. The system has multiple defensive layers built in to catch its own mistakes; this report quantifies how much each layer contributes.

**Headline numbers (filled from current runs):**

| Metric | Value | Source |
|---|---|---|
| Cases with full ground truth | 3 | `dfirmadness-001-desktop`, `srl-2018-base-dc`, `srl-2018-wkstn-05` |
| Disk-side true positives across GT cases | 4 | 2 + 0 + 2 |
| Disk-side false positives across GT cases | 0 | All 3 GT cases |
| Disk-side false negatives across GT cases | 0 | All 3 GT cases |
| Disk-side precision (where defined) | 1.00 | `dfirmadness`, `wkstn-05` (`base-dc` is a negative-control case) |
| Disk-side recall (where defined) | 1.00 | Same |
| Memory-channel findings surfaced (first dual-channel run) | 4 | `srl-2018-wkstn-05` run-005: 3× process_injection, 1× c2_beacon |
| Hallucinations across 7 runs (6 disk-only + 1 dual-channel) | 0 | No fabricated findings observed by human review |
| Critic-layer events across 7 runs | 13 | 10 R_05 (pre-fix normalize bug, since fixed); 2 INJECTION_QUARANTINE (defense fired correctly); 1 R_12 (false-trigger on memory-class finding, since narrowed) |

**TODO**: re-run the 6 disk-only baselines under patched R_05 / R_12 / executor code; the 10 R_05 false-escalations and the 1 R_12 false-trigger should both drop to zero, and the headline "fraction of runs auto-committed" number becomes meaningful.

**TODO**: annotate the 4 memory-channel findings from `srl-2018-wkstn-05` run-005 against an authoritative source (probably the SRL writeup if available, otherwise human DFIR judgment). Until annotated, the memory-channel claims appear in this report as "surfaced + plausible to human review" rather than as scored TPs.

---

## 2. Methodology

### 2.1 What the system does (plain English)

The agent is given a Windows hard-drive image (a single file containing a copy of a real disk) and optionally a memory dump. It runs a small fixed set of forensic tools — five for disk, five more for memory — pulls structured data out of each tool's output, and then writes a short report listing every persistence mechanism it believes an attacker installed. A human is asked to approve the plan of which tools to run before any of them execute, and is asked to approve or escalate the final findings before they are committed.

### 2.2 Reference dataset

| Case | Image source | Has full ground truth? | Used for |
|---|---|---|---|
| `dfirmadness-001-desktop` | DFIR Madness Case 001 (public) | Yes (published answer key) | Precision/recall |
| `srl-2018-base-dc` | SRL 2018 dataset, Windows DC | Yes (re-annotated 2026-04-24) | Negative control |
| `srl-2018-wkstn-05` | SRL 2018 dataset, workstation | Yes (re-annotated 2026-04-19) | Precision/recall + memory-channel target |
| `srl-2018-base-file` | SRL 2018, Windows file server | No | Sampled review |
| `srl-2018-base-rd-02` | SRL 2018, Windows RDP host | No | Sampled review |
| `srl-2018-dmz-ftp` | SRL 2018, DMZ FTP server | No | Sampled review |

### 2.3 Ground-truth protocol

For each GT case, every finding the agent produced was assigned one of `TP`, `FP`, `TN`, or `FN` against an authoritative answer key (DFIR Madness published key for `dfirmadness`; first-principles re-annotation by the project owner for the SRL cases, cross-referenced against community write-ups where available). False negatives were collected by independently enumerating known persistence mechanisms in each image and noting any the agent missed. Annotations are stored alongside each case at `out/runs/<case>/ground_truth.json`.

### 2.4 Sampled-review protocol (for non-GT cases)

For each of the 3 SRL cases without ground truth, a reviewer (the project owner with Claude Opus 4.7) reviewed every finding produced (each case had ≤3) plus 2 randomly-selected evidence records (Python `random.sample(range(N), 2)` after `random.seed(20260426)`). Each finding was scored "plausible / suspicious / known wrong"; cited tool_call_ids were verified to resolve in the evidence file; excerpts were spot-checked against the underlying structured fields. Per-case write-ups live at `out/runs/<case>/sampled_review.md`; aggregate at [`sampled-review-aggregate.md`](sampled-review-aggregate.md).

### 2.5 Ablation design

To measure how much each defensive layer contributes to overall accuracy, we ran four configurations of the same pipeline against the same case set:

| Row | Configuration | Status |
|---|---|---|
| 1 | Slice 2.5 baseline (single-channel free text, no Critic) | Implicit — Slice 2.5 outputs preserved |
| 2 | Dual-channel + injection scanner, **capability-token verification disabled** | Code prep ✅ on branch `ablation/row-2-no-cap-tokens` (commit `8f084a1`); runs **TODO** |
| 3 | Full Slice 5 (dual-channel + injection scanner + capability tokens + Critic) | Implicit — current outputs |
| 4 | Full Slice 5 with `classification` field **removed** from `Finding` schema | Code prep ✅ on branch `ablation/row-4-no-classification` (commit `12d2dd9`); runs **TODO** |

### 2.6 Tool + model stack

| Component | Choice | Notes |
|---|---|---|
| Disk-side MCP tools | `fsstat_e01`, `fls_list`, `icat_extract`, `regripper_run`, `scheduled_tasks_parse` | Sleuthkit + RegRipper |
| Memory-side MCP tool | `volatility_run` (5 plugins: `pslist`, `cmdline`, `netscan`, `dlllist`, `malfind`) | Volatility 2.6.1 |
| EXTRACT model | Gemini 3 Flash Preview | Cheap structured-output extractor |
| PLAN model | Claude Sonnet 4.6 | Plan synthesis |
| INTERPRET model | Claude Sonnet 4.6 | Finding analysis |
| Orchestrator | LangGraph state machine | EXTRACT → PLAN → human approve → EXECUTE → INTERPRET → CRITIC → human review / commit |

---

## 3. Per-case results

### 3.1 `dfirmadness-001-desktop`

**Plain English:** Public DFIR Madness Case 001. Two persistence mechanisms exist (a PowerShell stager in a registry Run key, and an attacker service called `coreupdater`). The agent found both, named both correctly, gave high-confidence verdicts, and made up nothing.

| Metric | Value |
|---|---|
| TP | 2 |
| FP | 0 |
| FN | 0 |
| Precision | 1.00 |
| Recall | 1.00 |
| Hallucinations | 0 |
| Critic terminal | (TODO — re-confirm under patched R_05) |

### 3.2 `srl-2018-base-dc` (negative control)

**Plain English:** A Windows domain controller with no attacker persistence on it. The right answer is "I don't see anything." The agent stayed silent (the DFIR responder tools that *were* on the host — F-Response, Mnemosyne — were correctly identified as legitimate and excluded). The Critic correctly noted that one of the registry-parsing steps returned a `parse_error`, so the "I don't see anything" claim couldn't be 100%-certified by the system itself; this was escalated to human review and the human confirmed there really was nothing there. This is the correct end-state.

| Metric | Value |
|---|---|
| TN | 1 |
| FP | 0 |
| FN | 0 |
| Precision | n/a (no positives to predict) |
| Recall | n/a |
| Hallucinations | 0 |
| Critic terminal | `human_review` (R_12 ABSENCE_UNSUBSTANTIATED on Winlogon parse_error) |

### 3.3 `srl-2018-wkstn-05`

**Plain English:** A Windows workstation from the SRL 2018 dataset with two known attacker mechanisms (a fake service named `PerfMon` and a Metasploit-style named-pipe service called `tbbd05`). The agent found both. The earlier version of the system (before our prompt-hardening work) was confused by the F-Response and Mnemosyne DFIR tools that were also present and called them attacker tools; that's been fixed and the post-fix run is clean. Run-005 (2026-04-26) is the first end-to-end run with both the disk and memory channels active; in addition to the two scored disk-side TPs, the system surfaced four memory-channel findings (see "Memory-channel findings" below) which await ground-truth annotation before they can be scored.

**Disk-side scoring (vs ground truth):**

| Metric | Value |
|---|---|
| TP | 2 |
| FP | 0 |
| FN | 0 |
| Precision | 1.00 |
| Recall | 1.00 |
| Hallucinations | 0 |
| Critic terminal | `human_review` (1× R_12 ABSENCE_UNSUBSTANTIATED on iteration 0; resolved by re-plan, see Section 5) |

**Memory-channel findings (run-005, dual-channel, plain English):** With the memory dump fed in alongside the disk image, the agent additionally surfaced four runtime findings. None have been graded against an authoritative key yet (the SRL 2018 writeup material the project has on hand is disk-focused), so these are reported as "surfaced + plausible to human review" rather than scored TPs. Every claim cites real evidence from the Volatility output.

| # | Mechanism | Target | Confidence | MITRE | Key evidence (citations are tool_call_ids) |
|---|---|---|---|---|---|
| 1 | `process_injection` | `powershell.exe` PIDs 4328, 4064, 3920 (parented by `WmiPrvSE.exe` PID 2676) | high | T1055 / TA0005 | RWX VadS regions in all three (`malfind`); WMI-spawned PowerShell parent chain (`pslist`); each spawns a 32-bit `-s -NoLogo -NoProfile` child (`cmdline`); together this is the three-pillar corroboration the rules require for a high-confidence injection call |
| 2 | `process_injection` | `rundll32.exe` PID 7100 | medium | T1055 / TA0005 | Parent PID 7148 missing from `pslist` (orphan parent); bare `rundll32.exe` command line with no DLL argument (`cmdline`); ~2.5 MB RWX VadS region (`malfind`); anomalous on every axis but not tied to a live network connection, hence medium |
| 3 | `process_injection` | `explorer.exe` PID 5284 | medium | T1055 / TA0005 | Parent PID 6444 missing from `pslist`; RWX VadS region containing a recognizable x64 indirect-syscall trampoline pattern (`41 BA xx 00 00 00 48 B8 [addr] FF E0`) consistent with framework-injected stubs (Cobalt Strike BOF / Donut style); medium because no direct PID→connection link in `netscan` |
| 4 | `c2_beacon` | `172.16.4.10:8080` from workstation `172.16.7.15` | medium | T1071 / TA0011 | Five TCP records to the same destination/port in `CLOSE_WAIT`/`CLOSED` with `pid=-1` (owning process gone); incrementing ephemeral source ports (53233, 54367, 55697, 56999, 57160, 57161), a repeat-callback pattern; corroborated temporally by the WMI→PowerShell chain in finding #1 |

The three `process_injection` findings and the `c2_beacon` finding all use `category="NOT_FOUND"` because the memory-class mechanisms aren't part of the disk-side persistence taxonomy; the `classification` field carries the actual mechanism label and the `attack_tactic_id` carries the correct MITRE tactic (TA0005 / TA0011 rather than TA0003 Persistence). This dual-key arrangement is what the R_12 narrowing fix protects against false-firing on (see Section 5).

**TODO**: annotate the 4 memory-channel findings against an authoritative source (likely a NotebookLM brief over the SRL 2018 writeup material plus DFIR judgment from the project owner); until then the precision/recall numbers above remain disk-side-only.

### 3.4 `srl-2018-base-file` (sampled review only)

**Plain English:** Windows file server. No official answer key. The agent surfaced a single high-confidence finding: a service called "Microsoft Advanced API 64" that mimics a real Microsoft service name but lives in a non-standard path. Independent human review judged this plausible: real Microsoft services don't install under `Program Files (x86)\Microsoft Advanced API 64`, and the missing display name is a known masquerading tell.

| Metric | Value |
|---|---|
| Findings surfaced | 1 |
| Sampled-plausible | 1/1 |
| Citations resolved | 1/1 |
| Random evidence records clean | 2/2 |
| Critic terminal | `human_review` (R_05 normalize-bug artifact, since fixed) |

Full write-up: [`out/runs/srl-2018-base-file/sampled_review.md`](../../experiments/slice-2-notebook/out/runs/srl-2018-base-file/sampled_review.md).

### 3.5 `srl-2018-base-rd-02` (sampled review only)

**Plain English:** Same masquerading service appeared on this host as on `srl-2018-base-file` — the same attacker toolkit deployed across two machines. The agent additionally found two entries (a registry Run key and a service) for an unknown vendor "Lincoln/LARIAT" (which is in fact MIT Lincoln Laboratory's LARIAT cyber-range tool — could be legitimate, could be repurposed by an attacker), and it correctly refused to commit a verdict, marking both as "needs more information." Good honest behavior. The system's injection-pattern scanner also caught a registry-binary blob that contained a literal MITRE technique ID embedded in its bytes and quarantined it from the analysis LLM — defense layer firing exactly as designed.

| Metric | Value |
|---|---|
| Findings surfaced | 3 |
| Sampled-plausible | 3/3 |
| Citations resolved | 3/3 |
| Random evidence records clean | 2/2 |
| Critic terminal | `human_review` (R_05 normalize-bug + 1 INJECTION_QUARANTINE event — defense correct) |

Full write-up: [`out/runs/srl-2018-base-rd-02/sampled_review.md`](../../experiments/slice-2-notebook/out/runs/srl-2018-base-rd-02/sampled_review.md).

### 3.6 `srl-2018-dmz-ftp` (sampled review only)

**Plain English:** A DMZ FTP server. The agent surfaced two genuinely-ambiguous findings (a `PSEXESVC` service residue, which could be from PsExec being used by an attacker for lateral movement *or* by an incident responder for triage; and an `Image File Execution Options` entry whose interpretation depends on a child key name the tool we used did not expose). Both were correctly marked as "needs more information." The reviewer's plain-English judgment: the agent drew the line in exactly the right place — neither falsely accusing nor whitewashing.

| Metric | Value |
|---|---|
| Findings surfaced | 2 |
| Sampled-plausible | 2/2 |
| Citations resolved | 2/2 |
| Random evidence records clean | 2/2 |
| Critic terminal | `human_review` (R_05 normalize-bug artifact) |

Full write-up: [`out/runs/srl-2018-dmz-ftp/sampled_review.md`](../../experiments/slice-2-notebook/out/runs/srl-2018-dmz-ftp/sampled_review.md).

---

## 4. Ablation table

**TODO** — fill once rows 2 and 4 have been run on all staged cases. Skeleton:

| Row | Configuration | `dfirmadness-001-desktop` | `srl-2018-base-dc` | `srl-2018-wkstn-05` | `srl-2018-base-file` | `srl-2018-base-rd-02` | `srl-2018-dmz-ftp` | Adversarial demo (canary) |
|---|---|---|---|---|---|---|---|---|
| 1 | 2.5 baseline | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| 2 | dual-channel only | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| 3 | full Slice 5 (current) | P=1.00 R=1.00 | TN | P=1.00 R=1.00 | (no GT) | (no GT) | (no GT) | TODO |
| 4 | full minus `classification` | TODO | TODO | TODO | TODO | TODO | TODO | TODO |

Cells will report `precision/recall/quarantine%`. "Quarantine%" is the fraction of evidence records the injection scanner suppressed before they reached the analysis LLM — a measure of how much the dual-channel layer is doing.

---

## 5. Hallucinated-claim log

**Plain English:** Across all seven pipeline runs (six disk-only + one dual-channel) the system produced a total of 13 Critic-layer events. None of them were actual hallucinations. 10 were a known false-positive in the R_05 (`EXCERPT_HALLUCINATION`) rule's whitespace/quote normalization, since fixed in commit `90d4ffd`. 2 were `INJECTION_QUARANTINE` events where the dual-channel injection scanner correctly suppressed evidence records containing prompt-injection-style content from reaching the analysis LLM (i.e., defense fired as designed, not a critic disagreement at all). 1 was an R_12 (`ABSENCE_UNSUBSTANTIATED`) false-trigger on the dual-channel run: the rule treated a `process_injection` memory finding as an absence claim because the finding uses `category="NOT_FOUND"` for tactic-tagging purposes, even though the finding cited multiple pieces of real Volatility evidence; the rule has since been narrowed (see Section 5.5) to skip findings whose `evidence` array is non-empty.

| Failure code | Count across 7 runs | Real hallucination? | Notes |
|---|---|---|---|
| `R_05 EXCERPT_HALLUCINATION` | 10 | No | Pre-fix normalize bug — over-strict on whitespace/quote drift; cited excerpts were all real text from structured fields. Fix in commit `90d4ffd`. |
| `INJECTION_QUARANTINE` | 2 | No (defense layer firing) | Dual-channel injection scanner suppressed evidence records containing prompt-injection-style content (one confirmed on `srl-2018-base-rd-02` from a registry blob containing literal `T1033`) before they reached the analysis LLM |
| `R_12 ABSENCE_UNSUBSTANTIATED` | 1 | No | Pre-fix R_12 fired on `srl-2018-wkstn-05` run-005 iteration 0 against a `process_injection` finding because the rule keyed on `category="NOT_FOUND"` alone; the finding had 8 cited evidence records. The retry succeeded and the run committed cleanly on iteration 1. Rule now narrowed in commit `12fcfd9` to skip findings whose `evidence` array is non-empty. |
| **Real hallucinations confirmed by human review** | **0** | — | — |

**TODO**: re-run all 6 disk-only baselines under patched R_05 + R_12 + executor code; the 10 R_05 false-escalations and the 1 R_12 false-trigger should both drop to zero, and the headline "0 confirmed hallucinations" claim then sits on top of a clean Critic ledger rather than a noisy one.

### 5.5 Defense hardening discovered during testing

**Plain English:** Every accuracy-report number above describes the system's behaviour on real data. Running it against real data also surfaced several genuine defects across the executor, the Critic, and the cost-reporting layer (plus a missing test-coverage gap), all of which were fixed during the report-writing pass rather than papered over. They are documented here because the SANS rubric values "system catches its own mistakes" as a first-class quality, and the fixes are part of the system the judge will run.

| Fix ID | Defect | Where it surfaced | Fix | Commit |
|---|---|---|---|---|
| **P0 (Fix A)** | EXECUTE node `break`'d on the first failed step, killing every downstream step in the plan even when only one branch was upstream-blocked | Staged runs where a single `parse_error` (e.g. Winlogon registry hive on `base-dc`) would have terminated otherwise-independent volatility / scheduled-task branches | New `_is_blocked_by_upstream(step, blocked_step_ids)` helper; the `ResolverError` branch now `continue`s instead of `break`s, so failures propagate transitively only along true `depends_on` chains. (Extended in P4.) Six unit tests in `tests/test_nodes_executor.py` pin the helper's behavior. | `9b04de0` |
| **P0 (Fix B)** | `reissue_token_node` re-issued capability tokens with disk-only `allowed_paths`, blocking any memory-image step that ran in a later iteration | Dual-channel `srl-2018-wkstn-05` run when the orchestrator re-planned after an R_12 trigger; the second-iteration memory step would have been denied by the MCP path-allowlist check | Reissue path now appends `MEMORY_IMAGE_PATH` to `allowed_paths` when the env var is set, matching the initial-issue grant. End-to-end probe confirmed real `pslist` returns 87 processes through the reissued token. | `9b04de0` |
| **P1** | LLM cost estimates were derived from a hand-maintained `_OR_RATES` rate table per model; missing or stale entries silently produced "rate unknown" lines, and the table was a known drift surface that already caused one cost-quote incident ($0.08 estimated vs $2.68 actual) | Slice 6 step 5 follow-up audit | All three LLM call sites now pass `extra_body={"usage": {"include": True}}`; cost printer reads `usage.cost` + `usage.cost_details` directly from OpenRouter's response, removing the local rate table entirely. Probed against all three production models (PLAN/INTERPRET on Sonnet 4.6, EXTRACT on Gemini 3 Flash Preview); all return populated cost data. | `f626f37` |
| **P3** | R_12 (`ABSENCE_UNSUBSTANTIATED`) treated every `category=NOT_FOUND` + high-confidence finding as an absence claim, even when the finding cited concrete evidence; so memory-class findings (which use `category="NOT_FOUND"` for tactic-tagging but always cite real Volatility evidence) tripped the rule and triggered an expensive INTERPRET re-plan on every dual-channel run that also had any disk-side `parse_error` | First dual-channel run on `srl-2018-wkstn-05` (run-005 iteration 0): a real `process_injection` finding with 8 cited evidence records was retried because of an unrelated `scheduled_tasks_parse` parse_error elsewhere in the run | Discriminator added: R_12 now returns `None` when `finding.evidence` is non-empty; absence claims (e.g. the negative-control "no persistence on this DC") still fire correctly because they cite no evidence. New `test_R_12_skips_memory_class_findings_with_evidence` in `tests/test_critic.py` covers a `process_injection` finding with category=NOT_FOUND + cited malfind evidence + an unrelated parse_error. Saves ~$0.05–0.10 per memory-channel run hitting any disk-side parse_error. | `12fcfd9` |
| **P4** | The skip-vs-halt asymmetry in P0 only covered `ResolverError`; non-continuable `tool_execution_status` values (timeout, `path_not_allowed` capability denial, etc.) still `break`'d the executor and killed independent subgraphs | Slice 6 step 5 follow-up audit (no live incident; caught by reading the executor in light of the P0 fix) | Both failure paths now use the same blocked-set + `continue` pattern, with `_CONTINUABLE_STATUSES` repurposed to gate downstream Critic rules' evidence-substantiveness checks rather than the loop's break decision. Memory-channel volatility steps with `depends_on=[]` now survive disk-side failures and vice versa. | `7c42e4c` |
| **P5** | No unit coverage for any of the 5 Volatility plugin parsers in `pipeline/parsers/volatility.py` despite the memory channel's 5-MCP-tool dependency on them | Slice 6 step 5 follow-up audit | 18-test file `tests/test_volatility_parsers.py` covering all 5 plugin parsers + dispatch + helpers, with real-data fixtures captured from a live wkstn-05 run; documented one dead code path (the parser's "unknown plugin" branch is unreachable because `VolatilityResult.plugin_name` is a Pydantic Literal, so `ValidationError` raises before the parser runs). Pytest count moved from 260 to 278. | `6be3fac` |

The R_12 narrowing (P3) is the most consequential of these for accuracy claims: without it, every memory-class finding (process_injection, c2_beacon, attacker_persistence_ai_assisted_runtime) would fire R_12 on every run, retry once, and only commit on iteration 1. The system would still arrive at the right answer, but its own ledger would look noisier than it is. With the fix, the Critic ledger reflects only real disagreements.

---

## 6. Known limitations

- **Windows-only.** The current MCP tool set covers NTFS disk images and Win7/Win2012/Win2016 memory profiles. Linux disk images and other Windows profiles (Win11, Server 2022) require either Volatility 3 or additional Vol2 profile coverage; both are out of scope for the SRL-2018 envelope this submission targets.
- **Five MCP disk tools, five MCP memory plugins.** This is the deliberate scope ceiling chosen at Slice 2 Step 0. Real responders use a wider toolkit; the system is architected so additional MCP tools can be added behind the same capability-token + injection-scanner discipline, but doing so is future work.
- **Recall blind spot on non-GT cases.** The sampled-review protocol can confirm plausibility of findings the agent *did* surface, but cannot detect findings the agent *missed*. The 6/6 plausibility number on the 3 SRL cases without ground truth is therefore not a recall claim.
- **Container boundary, not OS boundary.** A maliciously-crafted evidence file that exploited a Sleuthkit, RegRipper, or Volatility parser bug to escape the parser process would land inside the `sift-mcp` container, not on the host. The container is the trust boundary the orchestrator depends on; we have not red-teamed against parser escapes. This is documented as an extension point.
- **No live-system response.** This system reads dead disk and memory images; it does not interact with running hosts. Hot triage on a live machine is a separate problem.

---

## 7. Extension points

- **Stronger sandboxing.** Replace the `sift-mcp` Docker container with a seccomp-bpf hardened container, an eBPF-supervised process tree, or a microVM (Firecracker / Kata) to give a real adversarial-bypass story rather than the current "trust the container" posture.
- **Volatility 3.** Adds Win11 and Server 2022 memory coverage; Vol2 is sufficient for the SRL-2018 envelope and is what we shipped, but a production deployment would need both.
- **Linux disk profile.** A separate MCP tool family (`debugfs`, `xfs_db`, journald scanners) would extend the disk side to Linux images.
- **Real adversarial E01 builder.** The current adversarial demo is a canary-trip integration test. A genuine `make_adversarial_e01.py` tool that synthesizes a poisoned image with controlled persistence + counter-forensics would make the adversarial story stronger; explicitly deferred to Slice 6.5.
- **Cross-host correlation.** The same masquerading service was detected on two different SRL hosts (`base-file` and `base-rd-02`), but no logic surfaces this overlap automatically — a human reading both reports caught it. A cross-case correlator would be a natural Slice 7.

---

## 8. References

- Per-case sampled reviews: [`out/runs/<case>/sampled_review.md`](../../experiments/slice-2-notebook/out/runs/) for the 3 non-GT SRL cases
- Sampled-review aggregate: [`sampled-review-aggregate.md`](sampled-review-aggregate.md)
- Slice 6 runbook (process documentation): [`docs/runbooks/slice-6-runbook.md`](../runbooks/slice-6-runbook.md)
- Architecture: [`docs/planning/architecture.md`](../planning/architecture.md), [`docs/planning/architecture.html`](../planning/architecture.html)
- Threat-landscape research feeding the AI-assisted-attacker scope: [`docs/research/ai-assisted-threat-landscape-2026.md`](../research/ai-assisted-threat-landscape-2026.md)
