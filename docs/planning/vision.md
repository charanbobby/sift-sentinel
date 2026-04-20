# Vision — Find Evil Hackathon (SANS, due 2026-06-15)

**Last updated:** 2026-04-20

One page. Read this before opening PLAN.md, runbooks, or notebooks. If a decision can't be justified against this page, revisit the decision.

---

## One-line vision

**An MCP-native forensic agent that produces tamper-evident findings on real Windows disk images — scoped narrowly, measured rigorously, and architecturally defensible against adversarial evidence.**

## The 30-second pitch (submission abstract — draft)

*An MCP-native forensic agent that investigates persistence on real Windows disk images. Every finding is produced by a human-approved plan, executed under a dual-channel MCP boundary that quarantines adversarial evidence content from the agent's reasoning, gated by a deterministic self-correction critic, and linked by a per-excerpt sha256 hash chain to its originating evidence. Validated end-to-end on two positive DFIR CTF cases (precision 1.00, zero hallucinated evidence); a third case — a **published no-persistence scenario (Hadi3)** — is in preparation specifically to stress-test the critic against LLM positive-finding bias. Memory forensics and cross-platform evidence are documented extension points, not unfinished work.*

Every claim in that paragraph is a slice deliverable with an artifact behind it.

---

## What we're building (architecture at a glance)

```
                 ┌──────────────┐
  E01 image ───▶│   EXTRACT    │  cheap LLM — enumerate candidate artifact paths
                 └──────┬───────┘
                        ▼
                 ┌──────────────┐
                 │    PLAN      │  quality LLM — produce tool-call sequence
                 └──────┬───────┘
                        ▼
                  [HUMAN GATE]    ← L1 today; shifts to conditional under L2/L3
                        ▼
                 ┌──────────────┐
                 │   EXECUTE    │  MCP server runs each tool under a
                 └──────┬───────┘  CAPABILITY TOKEN scoped to this plan
                        │              ↑ NEW (Slice 5)
                        │          Tool output passes through
                        │          INJECTION SCANNER before reaching LLM
                        │              ↑ NEW (Slice 5)
                        ▼
                 ┌──────────────┐
                 │  INTERPRET   │  quality LLM — synthesize Findings,
                 └──────┬───────┘  classify every finding against DFIR taxonomy
                        ▼                  ↑ Step 0 (Slice 3 Phase A — shipped)
                 ┌──────────────┐
                 │   CRITIC     │  11 deterministic rules, self-correction
                 └──────┬───────┘  instruction per rule, audit log
                        │              ↑ Slice 3 Phase B
                        ▼
                 findings.json + plan_digest + sha256 chain of custody
                                               ↑ Slice 6
```

**Investigation question (committed):** *"Given a Windows disk image suspected of compromise, what persistence mechanisms did the attacker install?"*

**Investigation question (stretch):** *"When and how did the attacker first execute code on this host?"* — only if Slices 3/5/6 ship on time.

## The tools we use and the ones we don't

**In scope (current MCP toolset):** `fsstat_e01`, `fls_list`, `icat_extract`, `regripper_run`. NTFS + Registry only.

**Out of scope by deliberate choice:** memory forensics (Volatility), network forensics (PCAPs, DNS, NetFlow), cloud logs, non-Windows filesystems, event log parsing (`.evtx`), Prefetch/Shimcache/Amcache, browser artifacts, scheduled-task XML parsing. All documented as extension points.

Full scope reference: [`docs/learning/dfir-investigation-scope.md`](../learning/dfir-investigation-scope.md).

---

## Why narrow-deep and not broad

**Field size:** ~2000 hackathon participants. **Reference submission:** Protocol SIFT / Valhuntir (9-server MCP platform) — *the example template judges have already seen*. A Valhuntir-shaped broad submission is indistinguishable from a large fraction of the field.

**Four differentiation axes:**

| Axis | Our position | Why |
|---|---|---|
| Breadth | **Minimal** | Competing here = chasing Valhuntir. Lose. |
| Depth | **Maximize** | Eval rigor is rare at hackathon scale. |
| Novelty | **Maximize** | Dual-channel evidence handling at the MCP boundary (adversarial-injection defense) + per-plan capability scoping (least-privilege logical routing) + linear-hash-chained replayable provenance (per-excerpt hash referencing the previous ledger entry) are rarely built in MCP work. *Chain-of-custody hashing itself is standard DFIR practice, and the public Valhuntir example already includes hash/HMAC-based provenance features — our differentiator is granularity and cryptographic non-repudiation, not the underlying concept. Capability tokens in our stdio transport are application-layer routing, not a cryptographic boundary against adversarial prompt-injection; that defense lives in the dual-channel handler.* |
| Autonomy posture | **Climb explicitly** | L1 → L2 → L3 documented in `docs/planning/autonomy-dial.md`; most entries don't address autonomy at all. |

Full reasoning: [`docs/learning/hackathon-winning-strategy.md`](../learning/hackathon-winning-strategy.md).

---

## Slices that ship the vision (the three that matter most)

### Slice 3 — Self-correcting Critic

**What:** 11 deterministic rules + per-rule self-correction instruction templates + bounded retry + escalation + audit log.

**What it proves:** the agent's findings pass through a code-level gate, not a prompt. Disagreements are structured, retryable, and logged. Catches fabricated excerpts, tool-category mismatches, scope gaps, and classification omissions.

**Status:** Phase A (Step 0 — INTERPRET prompt hardening + `classification` field) shipped 2026-04-19. Phase B (R_01–R_11 implementation in C10–C14) is the next build.

### Slice 5 — Dual-channel MCP boundary + capability scoping

**What:** (a) **dual-channel evidence handling at the MCP boundary** — raw tool bytes preserved and hashed (the forensic record is never mutated); agent receives only server-side-extracted structured fields; content that matches injection patterns is **quarantined** from the LLM context and escalated for human review. (b) **Per-plan capability tokens** scoped to `(case_id, allowed_tools, allowed_paths, expires_at, plan_digest)` — enforced server-side at the tool-routing layer.

**What it proves:** (a) adversarial strings in evidence (attacker-authored filenames, registry values, document content) cannot influence the LLM's reasoning; the evidence is still fully preserved for forensic review. (b) A malformed or out-of-scope tool request is refused at the application layer before it runs.

**Scope caveat on capability tokens:** in our stdio transport (agent orchestrator and MCP server run in the same container under the same UID), tokens are *application-layer least-privilege routing*, not a cryptographic boundary against adversarial-prompt-injection bypass. The actual adversarial defense is the dual-channel handler — it keeps injection content out of the LLM context in the first place. The submission narrative is careful to draw this line.

**Why it's the biggest novelty hook:** most hackathon submissions handle prompt injection at the prompt level, if at all. Doing it at the evidence boundary — raw bytes preserved for forensic integrity, structured extracts substituted into the agent context — is distinctive.

### Slice 6 — Observability + linear-hash-chained provenance + confidence rubric

**What:** (a) sha256 of every stdout excerpt, linked to `plan_digest`, written to a **linear hash chain** stored in an **append-only integrity ledger separate from the case folder** — each ledger entry embeds the SHA-256 of the previous entry's signature block, so tampering any historical byte invalidates every subsequent hash (NIST SP 800-86 aligned; defeats the self-attestation failure mode where the same process writes evidence *and* the hashes that attest to it); (b) re-verifiable replay (`verify_chain_of_custody.py` re-runs months later, walks the chain, and passes or fails loudly); (c) routing rubric — High + all-rules-pass → auto-commit, Low / requires_disambiguation / Critic-escalate → HOLD for human review.

**What it proves:** findings carry tamper-evident, reproducibly verifiable provenance — gated by calibrated confidence. This is the "L3 autonomy" enabler.

*Scope caveat on language:* Protocol SIFT itself is explicitly experimental per SANS (not validated for evidentiary reliability or courtroom admissibility). We describe these mechanisms as **replayable auditability for a research workflow**, not as proxies for legal admissibility. The submission is careful to preserve that distinction.

---

## What success looks like (committed definition)

At submission (2026-06-15):

1. End-to-end pipeline runs against **≥3 public DFIR CTF images**, produces a `findings.json` per case in under 60 seconds.
2. `score.py` reports **precision ≥ 0.95, recall ≥ 0.90, hallucinations = 0** across all validated cases.
3. **Seeded-failure demo**: in the demo video, we intentionally inject a fabricated `output_excerpt` and show R_05 escalating to human review — *with the audit entry written before the find-out*.
4. **Chain-of-custody re-verification**: replay the linear hash chain against an archived case folder; every entry validates against the previous entry's signature. Tampering any byte in any historical entry causes the chain to fail loudly from that point onward.
5. **Adversarial-evidence demo**: we drop a crafted filename with injection text onto a test E01, show the dual-channel handler quarantining it from the LLM context (raw bytes still preserved and hashed), R_10 escalating the corresponding finding.
6. **Negative-case discipline**: on Hadi3 (published no-persistence scenario) the pipeline returns `findings: []` with zero hallucinations. Any sycophantic over-classification is caught by the Critic and retracted via bounded retry. This is the empirical proof that the Critic isn't rubber-stamping LLM positive-finding bias.
7. **The 30-second pitch at the top of this file** is still accurate — every claim has an artifact.

Stretch (if above all ship by 2026-05-31):

8. Pipeline runs against the same images for the **second investigation question** ("when/how did they first execute code?") — demonstrates architectural generalization.

---

## What we will NOT do

- **Add memory, network, or cross-platform evidence.** Extension points, not gaps.
- **Build a "broad" multi-stage attack-chain agent.** That's a Valhuntir clone route.
- **Add investigation questions beyond Q1 (+ optional Q2 stretch).** Scope-lock.
- **Ship Slice 7 (full-stack UI) unless Slices 3/5/6 are green by 2026-05-24.** Audit trail is the more impressive piece in a high-stakes domain.
- **Commit to more than 2 Langfuse probes or >1 model swap per slice.** Measurement discipline.

---

## Tripwires — when to cut scope

Reversal paths are pre-decided so scope creep has a stop condition:

| Trigger | Action |
|---|---|
| Slice 3 Phase B (Critic) not green by 2026-05-01 | Drop Q2 stretch entirely. Reduce Slice 5 to *just* capability tokens (defer injection scanner). |
| Slice 5 capability tokens blocked or >2-week overrun | Drop injection scanner. Keep capability tokens as the only Slice 5 deliverable. |
| Slice 6 chain-of-custody hits implementation wall | Ship observability + rubric only. Document chain-of-custody as an extension point. |
| Eval precision drops after Slice 5 changes | Halt Slice 5 merge. Restore Slice 2.5 pipeline. No shipping until fixed. |
| Slice 7 (UI) touched before 2026-05-24 | Stop. Work on Slice 8 (demo + submission) instead. |

---

## Where to go from here

- `PLAN.md` → the slice table + current status.
- `docs/runbooks/slice-3-runbook.md` → Slice 3 build spec with R_01–R_11, Step 4a correction templates.
- `docs/runbooks/slice-2-runbook.md` → Slice 2 pipeline (end-to-end green).
- `docs/learning/dfir-investigation-scope.md` → full DFIR map.
- `docs/learning/hackathon-winning-strategy.md` → full positioning analysis with tripwires.
- `SKILL.md` → phase-based workflow distilled from prior projects.

**If this vision changes, edit this file first** — then propagate to PLAN.md, runbooks, and slice decisions. The vision is upstream of everything else.
