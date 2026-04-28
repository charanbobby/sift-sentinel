# Design decisions

**Last updated:** 2026-04-27
**Scope:** the architectural choices that shaped this pipeline, the alternatives we considered, and the trade-offs we accepted. Read this alongside [`architecture.md`](../planning/architecture.md) (which shows what the system looks like) and [`known-limitations.md`](known-limitations.md) (which shows what it cannot yet do).

This document is structured one decision per section. Each section names the decision, the alternatives we did not pick, why we chose what we chose, and where the choice lives in code. The first decision is the bundle-trim trade-off because it is also the one we tested most rigorously against ourselves.

---

## 1. Bundle-trim trade-off (we tested our own assumption)

**Decision.** The pipeline's analysis-LLM bundle does not include the full output of every forensic tool. Volatility's `dlllist` plugin in particular is filtered to keep only DLL entries for processes the upstream layers have already flagged. The bundle builder also strips Volatility's `netscan` to drop listening sockets when a long table threatens to dominate the bundle, and it strips navigation-only steps (directory listings, extraction confirmations) from the analysis prompt entirely.

**Alternative we did not pick.** Send everything to the LLM and let the model decide what is relevant. This is the default behavior in most agent frameworks. It is also what produced a 519 KB single-tool bundle on a Domain Controller in late April 2026, roughly a 10x token spike on top of the disk-only baseline. A previous instance of the same class of bug (the `fls_list` directory-listing bloat earlier in April) cost real money before it was caught.

**Why we chose to trim.** Two reasons. First, navigation tool output is staging information for the executor, not analytical content for the LLM. Sending it is paying tokens for context the model cannot do anything useful with. Second, on large hosts the unfiltered output drowns the legitimate signal; the LLM has to sift through thousands of clean-process DLL paths to find the few that matter, and our observation is that it sifts less reliably as the noise rises.

**The honest test.** We did not want to ship a trim guard on faith. We added an `ABLATION_NO_DLLLIST_TRIM=1` environment flag to the bundle builder in [`pipeline/nodes.py`](../../experiments/slice-2-notebook/pipeline/nodes.py) and re-ran the same case (wkstn-05) with the trim disabled. With trim on, the run produced 6 specific findings that auto-committed at SUCCESS. With trim off, it produced 5 less specific findings that escalated to HUMAN_REVIEW. One data point is not a benchmark, but it is the opposite of "trim cost us coverage." See `known-limitations.md` section 2 for the per-finding breakdown.

**Where it lives in code.** [`pipeline/nodes.py`](../../experiments/slice-2-notebook/pipeline/nodes.py) bundle builder, with a documented `_VOL_EMPTY_LEGITIMATE` parser-side classification and per-plugin trim hooks.

**What we accept.** A future case where the relevant DLL is loaded by a process upstream did not flag would be missed by this filter. We do not have such a case in the bounded Reference Dataset; if one arose, the conservative fix would be to also include children of flagged PIDs in the keep set.

---

## 2. Parser status codes as the silent-failure boundary, not Critic rules

**Decision.** When a forensic tool returns empty stdout, the parser classifies that as `parse_error` if the tool is guaranteed to print on success, and as `empty` only when empty is a real legitimate clean-host signal. The Critic layer trusts the status code and does not introspect the stdout itself.

**Alternative we did not pick.** Write Critic rules with embedded knowledge of every tool's expected output shape ("if Volatility pslist returns no rows, escalate; if Volatility malfind returns no rows, accept"). This puts tool-specific knowledge in the Critic, which is supposed to be tool-agnostic.

**Why we chose the parser boundary.** Parsers already know the tool's output format intimately, by definition. That is what they are for. Asking the Critic to re-derive the same knowledge is duplicative and brittle. A new tool added later only needs its parser to classify empty correctly; no Critic rule needs to grow.

**The incident that forced the decision.** Across 6 demo runs in late April 2026, the RegRipper plugin `winlogon_tln` was returning empty stdout on the SOFTWARE hive. The parser at the time was returning status `ok` for that case, treating empty as legitimate. Critic rules R_06 (Negative-Result-Metadata) and R_12 (Evidence-of-Absence) only escalate on `parse_error`, so the silent failure was invisible. Five parsers were touched in the fix; the table is in `known-limitations.md` section 1.

**Where it lives in code.** [`pipeline/mcp/parsers.py`](../../experiments/slice-2-notebook/pipeline/mcp/parsers.py), with `parse_volatility` holding the per-plugin classification in `_VOL_EMPTY_LEGITIMATE`.

**What we accept.** A tool that prints something benign on every invocation regardless of whether it actually examined the target would still slip past this boundary. RegRipper does this in some of its "has no values" / "not found" code paths; we rely on those phrases being a real signal of "plugin ran, target was empty" rather than a fallback the plugin emits on error.

---

## 3. Decode-then-scan injection guard (recalibrated 2026-04-27)

**Decision.** The injection scanner's `INJ_BASE64_LONG` rule decodes the base64 blob (UTF-8 first, then UTF-16-LE for PowerShell `-EncodedCommand` style payloads) and only quarantines if the decoded text contains imperative-ignore patterns or role markers. A long base64 string by itself is no longer enough to quarantine.

**Alternative we did not pick.** Treat any long base64 string as quarantine-worthy. This was the original rule. It worked in the sense that it would not miss a base64-wrapped injection, but it had a high false-positive rate on perfectly normal pre-LLM-era attacker base64 (PowerShell `-EncodedCommand` stagers, packed binary blobs in registry values). On the SRL-2018 corpus the original rule was firing on real evidence the analyst would want the LLM to see.

**Why we chose decode-then-scan.** A PowerShell stager from 2018 is not a prompt injection. The thing that makes prompt injection prompt injection is the directive content, not the encoding. Decoding lets us reach the directive, scan for it, and only fire when both conditions hold (long base64 plus imperative content).

**Where it lives in code.** [`pipeline/mcp/injection_scanner.py`](../../experiments/slice-2-notebook/pipeline/mcp/injection_scanner.py), with 6 hand-crafted scenarios covering UTF-8 plaintext, UTF-16-LE PowerShell, and pre-LLM-era stagers as negative cases.

**What we accept.** Nested encoding (base64 of gzip of injection text) will not decode through this scanner and will be missed. This is the layer-5 case in the synthetic adversary-AI workstation design and is documented as an acknowledged gap in `known-limitations.md` section 4. We chose not to chase deeper decoding because each layer adds false-positive surface (legitimate compressed binaries in registry blobs).

---

## 4. Dual-channel evidence boundary (preserve raw, quarantine parsed)

**Decision.** Every MCP tool emits two channels for each call: the raw subprocess bytes (persisted to disk for the integrity ledger, never sent to the LLM), and a parsed Pydantic structured object (sent to the LLM). When the injection scanner flags a parsed field, the parsed object is quarantined and stripped from the LLM bundle; the raw bytes stay on disk untouched. Forensic integrity is preserved (we never silently mutate evidence) and the LLM context is safe (the quarantined fields do not enter the prompt).

**Alternative we did not pick.** Redact the offending bytes in place before passing to the LLM. This was the original Slice 5 design. We rejected it after a round-3 critique pointed out that silently mutating evidence is itself a forensic-integrity violation; a defender who alters the disk image cannot later prove what the original disk contained.

**Why we chose preserve-and-quarantine.** Two layers, two responsibilities. The raw channel preserves the evidence chain; the parsed channel provides the LLM with content the scanner has cleared. When the scanner fails the parsed channel, the LLM loses the parsed content but the raw channel is still intact for human review or replay.

**Where it lives in code.** [`pipeline/mcp/`](../../experiments/slice-2-notebook/pipeline/mcp/) (parsers + injection scanner), [`pipeline/nodes.py`](../../experiments/slice-2-notebook/pipeline/nodes.py) bundle builder filter step.

**What we accept.** A determined attacker who could plant injection content the scanner does not match (novel directive phrasing, language we did not template, indirect reference chains) would still pass content through the parsed channel. The synthetic adversary-AI workstation is the validation rig for measuring how often this happens.

---

## 5. Capability tokens are application-layer routing, not a cryptographic boundary

**Decision.** Capability tokens carry `(case_id, allowed_tools, allowed_paths, plan_digest, expires_at)` and are HMAC-verified by the MCP server before any tool runs. The Docker network boundary (the agent container has no Docker socket, no shell access into the MCP container, no host filesystem mount) is the load-bearing security boundary. Tokens are application-layer least-privilege.

**Alternative we did not pick.** Frame tokens as the security boundary against adversarial prompt injection. A round-3 reviewer flagged this as overclaim: an LLM that has been jailbroken and asked to call MCP tools with reasonable parameters will still pass token validation, because the parameters are plausible. The token is not what stops the attack; the dual-channel handler (decision 4) is.

**Why we chose application-layer framing.** Honesty in the submission narrative. A judging panel will read "capability tokens" + "mounted Docker socket" side by side and clock the gap immediately. The Slice 5 transport swap removed the Docker socket so the framing matches the architecture: tokens scope what the agent can ask the MCP server to do, the network boundary scopes what the agent can do at all.

**Where it lives in code.** [`pipeline/mcp/tokens.py`](../../experiments/slice-2-notebook/pipeline/mcp/tokens.py) for HMAC mint and verify; the MCP server's `_enforce_capability` checks the token before any subprocess runs.

**What we accept.** An attacker who could read the HMAC key from inside the agent container could mint tokens that pass verification. The HMAC key is not exposed beyond the agent process; if the agent process is compromised at OS level the token model is moot anyway.

---

## 6. Autonomy as a deliberate climb, not a single posture

**Decision.** The submission ships at L2 (Guarded Execution, agent self-corrects via the deterministic Critic + bounded retry budget) with L3 (Exception-Based Autonomy, agent runs end-to-end and only Low-confidence findings or Critic-fail-fast events pause for human review) as the headline goal on a bounded Reference Dataset. The demo narrative sells the climb from L1 to L3 as a deliberate transfer of control as compensating controls landed.

**Alternative we did not pick.** Headline a fourth, more aspirational autonomy level (post-deployment Forensic Auditor) for narrative impact. A round-3 critique flagged this as dilution; the autonomy levels should reflect what we actually shipped, not a wish-list.

**Why we chose to scope to L3.** Forensics has irreversible-harm blast radius. Wrong conclusions carry legal weight. A Workflow Agent posture with permanent human checkpoints is a deliberate engineering choice for forensic integrity; it is not a capability gap we are trying to close. The L3 ceiling matches our compensating controls (confidence rubric, integrity ledger, Critic disagreement log) and does not promise more than the controls support.

**Where it lives in code.** Posture is enforced in [`pipeline/graph.py`](../../experiments/slice-2-notebook/pipeline/graph.py) graph topology (the human-review terminal, the bounded retry budget) and [`pipeline/critic.py`](../../experiments/slice-2-notebook/pipeline/critic.py) R_15 LOW_CONFIDENCE_AUTO_ESCALATE rule.

**What we accept.** L3 on out-of-distribution attacker behavior is unmeasured. The Reference Dataset is bounded by design. A reviewer reading the accuracy report should treat the headline numbers as in-distribution claims, not a generalization promise.

---

## 7. MemorySaver only, no external database for the public ship

**Decision.** The open-source release uses LangGraph's `MemorySaver` exclusively. No SqliteSaver, no PostgresSaver, no external database dependency. State is in-memory for the duration of the run; the integrity ledger is the durable artifact.

**Alternative we did not pick.** Ship with a SqliteSaver default for state durability across crashes. We rejected it because every database dependency adds setup friction for a judge running the try-it-out instructions on a clean machine.

**Why we chose memory-only.** "Try-it-out" is a required submission component. The fastest way to lose usability points is a brittle reproduction path. A judge with Docker and Python installed should be able to clone the repo, run one compose command, and exercise the pipeline. Adding a database step adds a class of "but my Postgres won't connect" failures we cannot debug from a distance.

**Where it lives in code.** [`pipeline/graph.py`](../../experiments/slice-2-notebook/pipeline/graph.py) `build_graph` defaults `checkpointer=MemorySaver()`.

**What we accept.** A run that crashes mid-pipeline cannot be resumed from where it left off. The integrity ledger captures everything that happened up to the crash, so post-mortem reconstruction is possible, but the agent itself starts over.

---

## 8. Append-only hash-chained integrity ledger

**Decision.** Every notable event in a run (plan accepted, tool call recorded, finding emitted, critic disagreement raised, human decision applied) appends one entry to a per-run JSONL ledger. Each entry includes the SHA-256 of the previous entry's signature block so the ledger forms a linear hash chain. Tampering with a historical entry invalidates every subsequent entry's hash.

**Alternative we did not pick.** Store evidence hashes alongside the case folder without a chain. NIST SP 800-86 framing on this is direct: hash records should be stored separately and protected against practitioner tampering. A plain append-only file is a trust assumption; a hash chain is a cryptographic guarantee.

**Why we chose the chain.** A few extra lines of Python in the ledger writer for non-repudiation that a security-aware reviewer will recognize on sight. The submission's claim is "audit trail," and an audit trail that the same process can rewrite undetectably is not really one.

**Where it lives in code.** [`pipeline/ledger.py`](../../experiments/slice-2-notebook/pipeline/ledger.py); the verifier walks the chain on replay.

**What we accept.** The ledger is per-run, not cross-run. A reviewer comparing two runs on the same case has to verify each chain independently. A cross-run integrity story (the same evidence file produces consistent hashes across runs) is implicit in the per-call `raw_sha256` but not explicitly asserted by a top-level claim.

---

## How these decisions hang together

The pipeline has four security-relevant boundaries. Reading top to bottom:

1. **The Docker network boundary.** The agent container has no Docker socket, no host filesystem mount, no forensic tools. Its only egress is HTTP to the MCP server.
2. **The MCP server's capability check.** Every tool call is HMAC-verified against the run's capability token before any subprocess starts.
3. **The dual-channel handler.** Raw bytes go to the integrity ledger; parsed bytes go through the injection scanner before reaching the LLM bundle.
4. **The Critic layer.** Every finding is evaluated against deterministic rules (R_01 through R_15) before it is committed; failures route to human review.

Decisions 4 and 5 above are about the third boundary. Decision 8 is about the audit trail that lets a reviewer verify what happened across all four. Decisions 1, 2, and 3 are about not letting the LLM bundle become a foot-gun.

The single thread tying everything together: the LLM is not trusted to police itself. Every layer above is a control the LLM cannot turn off, a check the LLM cannot rewrite, or a hash the LLM cannot tamper with after the fact.
