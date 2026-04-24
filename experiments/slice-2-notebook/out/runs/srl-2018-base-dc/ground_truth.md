# Ground Truth — srl-2018-base-dc

**Annotated by:** charan.bobby  
**Date:** 2026-04-24  
**Pipeline run:** Slice 5 + Tier-1 AI-adversary stack (Gemini 2.5 Flash extract, Sonnet 4.6 plan/interpret, full Critic suite)

---

## Investigative question

> Given a Windows disk image suspected of compromise, what persistence mechanisms did the attacker install?

---

## Answer (ground truth)

**None.** This is a Windows domain controller from the SRL 2018 dataset with no attacker-installed persistence mechanisms. It serves as the negative-control baseline in the Slice 6 reference dataset.

---

## What the agent found

| # | Finding | Category | Classification | GT Verdict |
|---|---------|----------|----------------|------------|
| 0 | F-Response Subject service (`subject_srv.exe`) | service | legitimate_responder_tool | **TN** — correctly excluded |
| 1 | NOT_FOUND — no attacker persistence | NOT_FOUND | legitimate_windows_default | **TN** — correct absence claim |

**Scorecard:** TP=0, FP=0, FN=0. Precision=N/A (no positive predictions), Recall=N/A (no true positives to find).

---

## Detailed finding review

### Finding 0 — F-Response Subject service

The agent identified a Windows service named "F-Response Subject" with:
- ImagePath: `C:\windows\subject_srv.exe -s "base-hunt.shieldbase.lan:5682"`
- Display name: "F-Response Subject"

The agent correctly classified this as `legitimate_responder_tool`. The identification is accurate: F-Response is a well-known remote forensic acquisition product. The key signatures are:
1. Binary name `subject_srv.exe` — the F-Response subject-side agent
2. Hostname `base-hunt.shieldbase.lan` — matches F-Response examiner naming (`*-hunt.*`)
3. High non-standard port 5682 — F-Response default subject port

**GT verdict: TN** — the agent did not claim attacker_persistence. The finding documents a real artifact with correct classification.

### Finding 1 — NOT_FOUND

The agent examined all standard Windows persistence channels:
- HKLM and HKCU Run/RunOnce/RunOnceEx keys — only VMware Tools and McAfee Agent (both vendor products)
- IFEO (Image File Execution Options) — clean
- AppInit_DLLs — blank, LoadAppInit_DLLs=0
- Services — only Windows components, VMware drivers, McAfee services, F-Response (classified above), Mnemosyne DFIR driver
- Scheduled tasks — no XML artifacts returned
- Winlogon Userinit/Shell/Notify — parse_error on regripper `winlogon` plugin (step 10 limitation)

**GT verdict: TN** — the absence claim is correct. The Winlogon parse_error is a regripper plugin limitation, not an adversarial blind spot. No persistence exists in the Winlogon channel on this image.

---

## Critic behavior

The Critic correctly escalated to `human_review` via **R_12 (ABSENCE_UNSUBSTANTIATED)**: the Winlogon step returned `parse_error`, so the evidence-of-absence chain has a gap. This is the Critic functioning as designed — it is appropriately conservative about high-confidence NOT_FOUND claims when any tool in the run did not return `ok`.

Human reviewer confirms: the parse_error reflects a regripper limitation on this image's Winlogon hive structure, not a missed attacker artifact. The NOT_FOUND verdict stands.

The R_12 escalation is a **true positive flag** (correctly identifying the coverage gap) even though the underlying absence claim is factually correct. This is the right trade-off: the Critic should flag gaps; the human reviewer resolves them.

---

## False negatives

None identified. Full evidence reviewed across 19 tool calls covering all standard Windows persistence vectors.

---

## Notes for Accuracy Report

This case is the **negative-control baseline** for the Slice 6 reference dataset. It pairs with `srl-2018-wkstn-05` (2 TPs, 0 FPs) to give the precision/recall measurement a true-negative counterpart.

Key data point: the Mnemosyne kernel driver (`C:\windows\Mnemosyne.sys`) was present in the services output but not surfaced as a finding — the INTERPRET LLM correctly recognized it as a memory-acquisition DFIR tool alongside F-Response. Neither generated a false positive.

The R_12 escalation pattern documented here is expected on any image where one regripper plugin returns `parse_error`. The sampled-audit protocol should include a check for this: is the parse_error on a high-value channel (Winlogon, AppInit_DLLs) or a low-value one? For base-dc, Winlogon returned standard values on every other case — the parse_error is a known regripper quirk, not a gap in coverage.
