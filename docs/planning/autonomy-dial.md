# Autonomy Dial — DFIR Framing

**Source:** NotebookLM response synthesizing training material (DFIR course notes in `training/`) plus forensic-integrity priors.
**Captured:** 2026-04-19
**Referenced from:** [PLAN.md § Autonomy Posture](PLAN.md)

This document records the DFIR-grounded rationale for the autonomy climb in our slice plan. It exists so the hackathon submission has a citable justification for *why* the agent is Workflow-first and how it progresses toward higher autonomy as compensating controls land.

---

Transitioning your **Find Evil** agent from a workflow posture toward higher autonomy requires balancing the "Teammate" mindset of 2026 with the rigorous requirements of forensic integrity. In high-stakes domains like DFIR, where incorrect conclusions constitute **irreversible harm**, you must carefully manage the **agency-control tradeoff**.

### 1. Automation vs. Human Gate Decisions
In a persistence investigation, decisions are categorized by their "blast radius" and legal weight:
*   **Safe to Automate (End-to-End):** Mechanical data collection steps, such as running `fsstat` to gather file system metadata, executing `fls` to list directories, or triggering `regripper` on known hive paths. These are **low-stakes technical extractions** where the primary risk is latency or token cost, not legal validity.
*   **MUST Retain Human Gate:** The **Final Conclusion** (e.g., naming a specific user as the threat actor) and the **Verification of Intent**. Because AI lacks **explainability** and can suffer from **bias reinforcement**, any finding destined for a legal affidavit or court testimony must be human-verified to maintain the **chain of custody** and evidentiary standards.

### 2. Error Categories Caught by Human Checkpoints
Human oversight acts as a critical filter for the following AI-specific operational issues:
*   **Hallucinated IOCs:** LLMs may produce false indicators of compromise with extreme confidence.
*   **Context Rot / "Lost in the Middle":** If a `regripper` output is massive, the model may reliably perform on only **60-70% of the context length**, potentially ignoring a persistence key located in the middle of the tool output.
*   **Misread Timestamp Skew:** Autonomous loops often struggle with **non-deterministic logic** like clock drift or UTC-to-local conversions, which a human expert identifies instantly through domain intuition.
*   **Sycophancy:** A purely autonomous agent might over-align with its initial (incorrect) hypothesis, ignoring contradictory evidence found later in the investigation.

### 3. Defensible Compensating Controls
Before removing a human gate, the architecture must implement these **deterministic and architectural guardrails**:
*   **Deterministic Rule-Based Critic:** A Python-based validator that checks objective truths (e.g., "Does this registry path actually exist in the raw tool output?") before the finding is even considered [Artifact 1].
*   **Bounded Retry Budget:** Concrete limits (e.g., **max 2 retries per finding**) to prevent compounding failures or infinite loops that inflate costs [Artifact 2].
*   **Chain-of-Custody Logging:** Every tool call must be recorded with a **sha256 hash** of the full stdout and linked back to a **plan_digest** to ensure the investigation is fully reconstructible [Artifact 3].
*   **Confidence Thresholds:** Using a "High/Medium/Low" rubric to automatically escalate any low-confidence finding to a human reviewer [47, Artifact 3].

### 4. DFIR Precedents and Standards
The sources indicate that while the industry is moving toward **Vertical AI** that understands specific industry nuances (like legal or forensic workflows), human-reviewed output remains the **de facto requirement** for high-stakes decisions. Current standards emphasize **Smarter Teammates** that handle the "ambiguous tasks" of investigation but still require human-in-the-loop design for **regulatory compliance** and safety. Truly autonomous analysis is generally accepted only for **triage and initial scoping**, not for final forensic attribution.

### 5. The Autonomy "Dial" Postures
Realistic intermediate postures between a Workflow Agent and a fully Autonomous Agent:

1.  **Assisted Workflow (Current Posture):** Human approval is required after the **PLAN** and before the final **COMMIT**. The agent never takes an unvetted action.
2.  **Guarded Execution:** The human approves the initial **PLAN**, but the agent is permitted to **self-correct** using the Critic and re-execute tools autonomously if a deterministic rule (like a path mismatch) fails [91, Artifact 1].
3.  **Exception-Based Autonomy:** The agent runs end-to-end autonomously but **pauses for human review** only if the Critic detects a "Fail-fast" error (like an excerpt hallucination) or if the final finding's confidence is "Low" [49, Artifact 2].
4.  **Forensic Auditor Posture:** The agent is fully autonomous for the investigation, but the "Human-in-the-loop" shifts to an **Audit role**, reviewing a sampled **Reference Dataset** of the agent's findings post-deployment to calibrate its behavior over time.
