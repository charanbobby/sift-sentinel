"""Deterministic Critic — rule bodies, orchestrator, retry policy, edge router.

Extracted from slice2.ipynb cells C10/C11/C12 at Slice 5 Step 1 (dependency-leaf
after pipeline.schemas). Pure Python; no I/O — Slice 5 Step 7c removed the
`get_full_stdout()` disk reader: under the dual-channel boundary the Critic
only ever sees server-parsed `structured_fields`, and every rule operates
against the exact JSON text the LLM was shown (see `CriticContext.
agent_visible_text`). Audit-log writing (`append_critic_disagreement`) lives
in `pipeline.nodes`, not here.

Exports via `__all__`:
  - `CriticContext` — runtime read-only view the rules operate on.
  - `CATEGORY_REQUIRED_TOOLS` — category -> required tool allowlist.
  - `R_01 .. R_13` — rule callables, signature `(Finding, CriticContext) -> RuleFailure | None`.
  - `CRITIC_RULES` — ordered list of the 13 rule callables.
  - `ESCALATE_CODES` — FailureCodes that force `severity=escalate` with no retry.
  - `critic_evaluate(finding, ctx, idx) -> CritiqueResult` — orchestrator.
  - `PER_FINDING_RETRY_LIMIT`, `TOKEN_CEILING_PER_INVESTIGATION`,
    `total_roundtrip_limit(plan)` — retry-budget knobs.
  - `NEW_INSTRUCTION_TEMPLATES`, `RETRY_BRANCH`, `build_new_instruction(...)`,
    `critic_edge(state)` — retry router.
  - `build_resolution(critique, finding, ctx) -> dict` — assembles the audit-
    log resolution payload (moved from notebook C13 at Step 7c).

Slice 5 Step 7c rule adaptations:
  - `R_01`: `ctx.tool_calls` renamed to `ctx.evidence` (EvidenceRecord dict).
  - `R_03`, `R_08`: `tool` field sourced from `ctx.tool_for(tool_call_id)`
    because `EvidenceRecord` doesn't carry the tool name (server-side, only
    the plan knows which tool was dispatched).
  - `R_05`: "excerpt literally in raw stdout" → "excerpt literally in the
    structured_fields JSON the LLM saw" (see `ctx.agent_visible_text`).
  - `R_06`, `R_09`, `R_12`: `exit_code != 0` → `tool_execution_status != "ok"`.
  - `R_10`: `injection_flagged` → `any(flag.severity in {"warn","quarantine"}
    for flag in ev.injection_flags)`.

R_13 is still a stub; Step 10+ wires it once the scorecard needs it.
R_06 is minimum-viable — still uses `tool_execution_status` rather than the
`expected_paths_covered` surface that Slice 5 added. Bumping it to consume
that surface is a ~30-line follow-up; deferred to keep 7c scope tight.
"""
from __future__ import annotations

import json
import re

from pipeline.schemas import (
    CritiqueResult,
    EvidenceRecord,
    Finding,
    PersistenceCategory,
    PlannedStep,
    RuleFailure,
    ToolPlan,
)


# ---- Category -> required tool allowlist ----
# Used by R_03, R_06, R_08, and several new-instruction templates.
CATEGORY_REQUIRED_TOOLS: dict[PersistenceCategory, set[str]] = {
    "registry_run_key":   {"regripper_run"},
    "service":            {"regripper_run"},
    "scheduled_task":     {"fls_list", "icat_extract"},
    "ifeo_debugger":      {"regripper_run"},
    "appinit_dll":        {"regripper_run"},
    "logon_script":       {"regripper_run"},
    # NOT_FOUND handled separately by R_06 — needs ALL tools to have run successfully
}


class CriticContext:
    """Stateless read-only view the Critic operates on.

    Slice-5 shape:
      Receives:  the approved tool plan + the list of EvidenceRecords produced
                 by `execute_node` (channel-B structured_fields only — raw
                 bytes never reach the orchestrator under the dual-channel
                 boundary).
      Does NOT receive: Interpret LLM output, chain-of-thought, prior Findings.

    Since `EvidenceRecord` doesn't carry the tool name or the plan step_id
    (the server only returns what it parsed), the constructor builds a
    `tool_call_id → PlannedStep` side-car via positional correlation:
    `state.evidence[i]` was produced by `state.tool_plan.steps[i]`. That
    holds because `execute_node` iterates the plan in topological step_id
    order and halts on first failure — `state.evidence` is always a prefix
    of `state.tool_plan.steps`. If Slice 6+ parallelizes execution the
    correlation needs to move into state as an explicit mapping; until then,
    positional is correct and simple.
    """

    def __init__(self, tool_plan: ToolPlan, evidence: list[EvidenceRecord]):
        self.tool_plan = tool_plan
        self.evidence: dict[str, EvidenceRecord] = {
            ev.tool_call_id: ev for ev in evidence
        }
        self._plan_step_by_tcid: dict[str, PlannedStep] = {}
        for i, ev in enumerate(evidence):
            if i < len(tool_plan.steps):
                self._plan_step_by_tcid[ev.tool_call_id] = tool_plan.steps[i]
        # agent_visible_text is the JSON the INTERPRET bundle-builder embeds
        # under `structured_fields` for each step. R_05 checks that cited
        # output_excerpts are literal substrings of this text — it's the
        # "what did the model actually see?" reference the rule needs.
        self._sf_text_cache: dict[str, str] = {}

    def tool_for(self, tool_call_id: str) -> str | None:
        """Return the tool name that produced this tool_call_id, per the
        approved plan. `None` if the id isn't in the run — R_01 is the
        dedicated catch for that case, so callers can treat None as 'skip'."""
        step = self._plan_step_by_tcid.get(tool_call_id)
        return step.tool if step else None

    def agent_visible_text(self, tool_call_id: str) -> str:
        """JSON-serialized `structured_fields` for one step, in the same
        format `_build_interpret_bundle` renders (pretty, indent=2). This is
        the exact text the model saw; R_05's substring check must match it
        byte-for-byte or the rule would flag a correctly-quoted excerpt.
        Cached per-tcid because the serialization cost is nontrivial on a
        large RegRipper result."""
        if tool_call_id in self._sf_text_cache:
            return self._sf_text_cache[tool_call_id]
        ev = self.evidence.get(tool_call_id)
        if ev is None:
            txt = ""
        else:
            # Match _build_interpret_bundle's outer `json.dumps(bundle, indent=2)`:
            # the bundle wraps structured_fields unchanged under a dict key, so
            # the model ultimately sees them re-serialized at indent=2 as part
            # of the bundle. Producing the same rendering here makes R_05's
            # substring check agree with what the LLM was actually shown.
            txt = json.dumps(ev.structured_fields, indent=2, sort_keys=False)
        self._sf_text_cache[tool_call_id] = txt
        return txt


# ---- Helpers used by multiple rules ----
_PATH_SEP_RE = re.compile(r"[\\/]")
_WS_RE = re.compile(r"\s+")


def _path_tokens(s: str) -> set[str]:
    """Split a path-like string into components; drop tokens shorter than 3 chars."""
    if not s:
        return set()
    return {t for t in _PATH_SEP_RE.split(s) if len(t) >= 3}


def _normalize_for_match(s: str) -> str:
    r"""Format-tolerant normalization for R_05 substring comparison.

    Three systematic ways the LLM's `output_excerpt` diverges from the
    JSON-pretty `structured_fields` haystack while still being faithful to
    the underlying values:

      1. **Backslash runs.** Haystack stores Windows paths as `\\` (one layer
         of JSON escape) or `\\\\` (when the originating tool already
         JSON-escaped — `value_data_safe` from RegRipper does this for named
         pipes). The LLM normalizes inconsistently. Collapsing any run of
         backslashes to a single one handles N-layer encoding uniformly.
      2. **Quote escapes.** Embedded literal `"` characters appear as `\"`
         in JSON-pretty form; the LLM tends to drop the escape.
      3. **Whitespace.** json.dumps(..., indent=2) places `,\n  ` between
         fields; the LLM joins them onto one line with `, `. Even when the
         values are byte-perfect, the separators differ.

    Applied to both needle and haystack. Idempotent.

    Trade-off: this can let through a fabricated excerpt that happens to
    share a normalized substring with real evidence (e.g. injecting extra
    backslashes or whitespace). R_01 (cite-an-unknown-tool) and R_02
    (path-tokens-not-in-evidence) are the upstream catches for true
    fabrication; R_05 is the quote-fidelity layer.
    """
    s = re.sub(r"\\+", r"\\", s)   # collapse any run of `\` to one `\`
    s = s.replace('\\"', '"')      # unescape JSON quote escapes
    s = _WS_RE.sub(" ", s)         # collapse whitespace runs
    return s.strip()


# ---- Rule implementations (R_01 — R_13) ----

def R_01(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Did the agent cite evidence that actually exists in the run log?"""
    for ev in finding.evidence:
        if ev.tool_call_id not in ctx.evidence:
            return RuleFailure(rule_id="R_01", code="EVID_UNRESOLVED",
                               detail=f"evidence.tool_call_id={ev.tool_call_id!r} not in run evidence")
    return None


def R_02(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """When the finding claims a path/name, do components of it appear in quoted evidence?"""
    if finding.category == "NOT_FOUND":
        return None  # mechanism/value are empty markers ('none', ''); R_12 owns NOT_FOUND integrity
    candidates = _path_tokens(finding.mechanism or "") | _path_tokens(finding.value or "")
    if not candidates:
        return None  # no path-like content → R_02 doesn't apply
    joined = " ".join(ev.output_excerpt for ev in finding.evidence)
    if not joined:
        return RuleFailure(rule_id="R_02", code="PATH_INCONSISTENCY",
                           detail="no output_excerpt to check against")
    if any(tok in joined for tok in candidates):
        return None
    return RuleFailure(rule_id="R_02", code="PATH_INCONSISTENCY",
                       detail=f"none of path-tokens {sorted(candidates)[:5]} appear in joined output_excerpts")


def R_03(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Was the finding produced by a tool that can actually see this kind of thing?"""
    if finding.category == "NOT_FOUND":
        return None  # R_06 handles NOT_FOUND scope
    required = CATEGORY_REQUIRED_TOOLS.get(finding.category, set())
    if not required:
        return None
    cited_tools = {
        t for ev in finding.evidence
        if (t := ctx.tool_for(ev.tool_call_id)) is not None
    }
    if cited_tools & required:
        return None
    return RuleFailure(rule_id="R_03", code="TOOL_MISMATCH",
                       detail=f"category={finding.category} requires one of {sorted(required)}; "
                              f"finding cites {sorted(cited_tools)}")


def R_04(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Is the claimed registry path formatted like a real registry path?
    Scoped to registry_run_key: for service/ifeo/appinit/logon, the mechanism
    is typically a descriptive label, not the registry path itself."""
    if finding.category != "registry_run_key":
        return None
    m = (finding.mechanism or "").strip()
    if m.startswith(("HKLM", "HKCU", "HKU", "HKEY_")):
        return None
    return RuleFailure(rule_id="R_04", code="INVALID_REG_PATH",
                       detail=f"registry_run_key mechanism={m!r} does not start with HKLM/HKCU/HKEY_")


def R_05(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Is the quoted evidence actually present in the tool's structured_fields
    byte-for-byte?  ESCALATE (not retry) — excerpt fabrication is the most
    serious integrity failure.

    Slice 5 semantic change: under the dual-channel boundary the model never
    sees raw stdout. R_05 now checks whether the cited `output_excerpt` is a
    literal substring of the JSON-serialized `structured_fields` the model
    was actually shown (via `_build_interpret_bundle`). The match must agree
    byte-for-byte with that rendering — `ctx.agent_visible_text` produces
    exactly that form.
    """
    if finding.category == "NOT_FOUND":
        return None  # NOT_FOUND evidence cites coverage documentation; excerpt exactness is not a positive-claim check
    for ev in finding.evidence:
        if ev.tool_call_id not in ctx.evidence:
            continue  # R_01 handles
        needle = ev.output_excerpt or ""
        if not needle:
            continue  # empty excerpt is R_07 territory
        haystack = ctx.agent_visible_text(ev.tool_call_id)
        # Format-tolerant check: the LLM's output_excerpt may unescape JSON
        # backslashes and re-flow whitespace even when faithfully reproducing
        # the value. _normalize_for_match collapses both differences.
        if _normalize_for_match(needle) in _normalize_for_match(haystack):
            continue
        return RuleFailure(
            rule_id="R_05", code="EXCERPT_HALLUCINATION",
            detail=f"output_excerpt not found in structured_fields for "
                   f"tool_call_id={ev.tool_call_id!r}",
        )
    return None


def R_06(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """If 'nothing found,' did we actually look everywhere we should have?"""
    if finding.category != "NOT_FOUND" or finding.confidence != "high":
        return None
    required_union = set().union(*CATEGORY_REQUIRED_TOOLS.values())
    tools_run_ok = {
        ctx.tool_for(tcid)
        for tcid, ev in ctx.evidence.items()
        if ev.tool_execution_status == "ok" and ctx.tool_for(tcid) is not None
    }
    missing = required_union - tools_run_ok
    if missing:
        return RuleFailure(rule_id="R_06", code="SCOPE_INCOMPLETE",
                           detail=f"NOT_FOUND at high confidence but tools not successfully run: {sorted(missing)}")
    return None


def R_07(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Did the agent leave required fields blank?"""
    if finding.category == "NOT_FOUND":
        return None  # NOT_FOUND legitimately has empty mechanism/value
    if not (finding.mechanism or "").strip():
        return RuleFailure(rule_id="R_07", code="EMPTY_FINDING_DATA", detail="mechanism is empty")
    if not (finding.value or "").strip():
        return RuleFailure(rule_id="R_07", code="EMPTY_FINDING_DATA", detail="value is empty")
    return None


def R_08(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Is the confidence level justified by evidence from a primary tool?"""
    if finding.confidence != "high" or finding.category == "NOT_FOUND":
        return None
    required = CATEGORY_REQUIRED_TOOLS.get(finding.category, set())
    if not required:
        return None
    cited_primary = any(
        ctx.tool_for(ev.tool_call_id) in required
        for ev in finding.evidence
    )
    if cited_primary:
        return None
    return RuleFailure(rule_id="R_08", code="CONF_OVERSTATED",
                       detail=f"high-confidence {finding.category} finding does not cite a primary "
                              f"tool ({sorted(required)}); downgrade to medium")


def R_09(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Did every cited tool call actually succeed?

    Slice 5: FailureCode name still says EXIT_NONZERO for audit-log stability,
    but the underlying signal is `tool_execution_status`. `capability_denied`
    triggers the same failure — a denied call produced no evidence, so citing
    it is structurally equivalent to citing an exit_code!=0 subprocess."""
    if finding.category == "NOT_FOUND":
        return None  # NOT_FOUND cites tools to document coverage (including gaps); R_12 owns that check
    for ev_ref in finding.evidence:
        rec = ctx.evidence.get(ev_ref.tool_call_id)
        if rec is None:
            continue  # R_01 handles
        if rec.tool_execution_status != "ok":
            return RuleFailure(
                rule_id="R_09", code="EVIDENCE_TOOL_EXIT_NONZERO",
                detail=f"evidence cites tool_call_id={ev_ref.tool_call_id!r} "
                       f"with tool_execution_status={rec.tool_execution_status}",
            )
    return None


def R_10(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Was any cited evidence flagged by the injection scanner?

    - quarantine-severity → INJECTION_QUARANTINE (mandatory escalate; Step 8
      upstream filter in _build_interpret_bundle means the model should never
      cite quarantined evidence, but R_10 is the late-gate if it somehow does)
    - warn-severity → INJECTION_FLAGGED_EVIDENCE (escalate; lower-confidence
      flag that may indicate adversarial content but is not a hard quarantine)
    - info-severity → no-op (logged in EvidenceRecord; not actionable here)
    """
    for ev_ref in finding.evidence:
        rec = ctx.evidence.get(ev_ref.tool_call_id)
        if rec is None:
            continue  # R_01 handles
        quarantine_flags = [f for f in rec.injection_flags if f.severity == "quarantine"]
        if quarantine_flags:
            pids = [f.pattern_id for f in quarantine_flags]
            return RuleFailure(
                rule_id="R_10", code="INJECTION_QUARANTINE",
                detail=f"evidence tool_call_id={ev_ref.tool_call_id!r} carries "
                       f"quarantine-severity injection flag(s) {pids} — "
                       f"structured_fields should have been stripped upstream (Step 8)",
            )
        warn_flags = [f for f in rec.injection_flags if f.severity == "warn"]
        if warn_flags:
            pids = [f.pattern_id for f in warn_flags]
            return RuleFailure(
                rule_id="R_10", code="INJECTION_FLAGGED_EVIDENCE",
                detail=f"evidence tool_call_id={ev_ref.tool_call_id!r} carries "
                       f"warn-severity injection flag(s) {pids}",
            )
    return None


_ATTACKER_CLASSIFICATIONS = {
    "attacker_persistence",
    "attacker_persistence_ai_assisted",  # Slice 6 Step 3b — same rule-out discipline applies
}


def R_11(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Did the agent declare what kind of thing this finding is, with rationale?
    Missing classification is caught upstream by Pydantic (classification is required).
    Here we additionally check: any attacker_persistence* classification at high
    confidence must contain ruled-out-alternatives language in notes. Applies
    to `attacker_persistence_ai_assisted` too — benign AI tooling exists
    (Copilot, enterprise ChatGPT daemons, dev workstations); the rule-out
    discipline is especially important there."""
    if not finding.classification:
        return RuleFailure(rule_id="R_11", code="CLASSIFICATION_MISSING",
                           detail="classification field is empty")
    if finding.classification in _ATTACKER_CLASSIFICATIONS and finding.confidence == "high":
        notes_lc = (finding.notes or "").lower()
        # catches 'ruled out', 'ruling out', 'rules out', 'ruled-out'
        if "rul" not in notes_lc:
            return RuleFailure(rule_id="R_11", code="CLASSIFICATION_MISSING",
                               detail=f"{finding.classification} at high confidence must explicitly rule out benign alternatives in notes")
    return None


def R_12(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Evidence-of-Absence: a high-confidence NOT_FOUND claim is only defensible
    if every tool in the run completed cleanly. Additive over R_06 — R_06 checks
    the category-required tool set; R_12 checks the whole run.

    Slice 5 (post-7c): `tool_execution_status != "ok"` is the trustworthy
    failure signal — includes `capability_denied`, `timeout`,
    `permission_denied`, and `parse_error`. `empty` counts as ok for this
    rule (a tool ran cleanly and legitimately returned nothing; that IS
    substantiating evidence of absence).

    Slice 6 Step 5 P3 narrowing (2026-04-26): memory-class classifications
    (process_injection, c2_beacon) reuse `category="NOT_FOUND"` so the
    tactic-override path in `Finding._tag_attack` can pin them to TA0005 /
    TA0011 instead of the default TA0003 Persistence. They are NOT absence
    claims — they cite real evidence (malfind hits, netscan rows, pslist
    parent-child entries). The discriminator is `finding.evidence`: a true
    absence claim cites nothing, while a memory-class positive finding
    cites the malfind/netscan/pslist tool_call_ids it rests on. Skipping
    R_12 when evidence is present prevents an unrelated disk-tool
    `parse_error` from triggering an expensive INTERPRET re-plan on a
    well-grounded memory finding (observed live in srl-2018-wkstn-05
    run-005, where a `scheduled_tasks_parse` parse_error forced a re-plan
    on a process_injection finding with 3 cited memory evidence records).
    """
    if finding.category != "NOT_FOUND" or finding.confidence != "high":
        return None
    # Memory-class findings cite evidence; plain absence claims do not.
    if finding.evidence:
        return None
    failed = [
        (tcid, rec) for tcid, rec in ctx.evidence.items()
        if rec.tool_execution_status not in ("ok", "empty")
    ]
    if not failed:
        return None
    failed_summary = [
        (ctx.tool_for(tcid) or "unknown", tcid, rec.tool_execution_status)
        for tcid, rec in failed[:5]
    ]
    return RuleFailure(rule_id="R_12", code="ABSENCE_UNSUBSTANTIATED",
                       detail=f"NOT_FOUND at high confidence but {len(failed)} tool call(s) "
                              f"did not return ok-status in this run: {failed_summary}")


def R_13(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Temporal Consistency — STUB (pre-Slice-5).

    SLICE_5_TODO: once RegripperResult surfaces `hive_lastwrite` as a structured
    datetime, verify that a high-confidence attacker_persistence finding's
    claimed timestamp falls within (earliest_lastwrite, latest_lastwrite) for
    the cited hive. A regex over stdout_excerpt was evaluated 2026-04-20 and
    rejected: timestamp format variance (ISO 8601 vs RegRipper native
    'Sat Sep 19 03:42:42 2020' vs Unix epoch vs FILETIME) makes the regex
    either FP-prone or brittle. Returns None unconditionally until the
    structured metadata lands in Slice 5."""
    return None


# ---- R_16 AI-assisted anchor check (Slice 6 Step 3b) ----
# Concrete forensic artifacts that indicate AI-assisted attacker activity per
# 2025-2026 threat intel (PROMPTFLUX, PromptSteal, QuietVault, PromptLock;
# see docs/research/ai-assisted-threat-landscape-2026.md). Anchor-based
# rather than stylometric detection to avoid the known high-FPR problem with
# "was this code LLM-written?" classifiers on legitimate Copilot/Cursor users.
# Case-sensitive — env-var names + SDK imports appear literally in real
# artifacts; lowercasing would false-match decorative mentions in narrative text.
AI_ASSIST_ANCHORS: tuple[str, ...] = (
    # LLM API endpoints — direct C2 / runtime callout, strongest signal
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api-inference.huggingface.co",
    # SDK imports in scripted persistence / service binaries
    "import openai", "from openai",
    "import anthropic", "from anthropic",
    "import langchain", "from langchain",
    "import langgraph", "from langgraph",
    "google.generativeai",
    "import transformers", "from transformers",
    "huggingface_hub",
    "llama_index",
    "import ollama",
    # API-key env var names — attacker-planted credentials
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "HUGGINGFACE_HUB_TOKEN",
    "HF_TOKEN",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
)


def _contains_ai_anchor(text: str) -> bool:
    """Case-sensitive substring check — any AI-assist anchor in `text`."""
    if not text:
        return False
    return any(anchor in text for anchor in AI_ASSIST_ANCHORS)


_AI_ANCHOR_REQUIRED_CLASSIFICATIONS: frozenset[str] = frozenset({
    "attacker_persistence_ai_assisted",          # Slice 6 Step 3b — disk artifacts
    "attacker_persistence_ai_assisted_runtime",  # Slice 6 Step 3b.6 — memory artifacts (same anchor discipline per INTERPRET prompt)
})


def R_16(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """AI-assisted anchor check (Slice 6 Step 3b + 3b.6).

    When a finding is classified as `attacker_persistence_ai_assisted` (disk
    channel) or `attacker_persistence_ai_assisted_runtime` (memory channel),
    the supporting evidence must contain at least one concrete anchor — an
    LLM API endpoint URL, an AI-SDK import line, or a known AI API-key env
    var name. Forces grounding in recoverable forensic artifacts rather than
    stylometric guessing. Routes to `re_interpret`: the model either finds
    the anchor in a different excerpt or downgrades classification to plain
    `attacker_persistence`.

    Both classifications share the same anchor list because the artifact
    surface is the same — what differs is where it was observed (dormant on
    disk vs loaded/connected at runtime). The INTERPRET prompt at the
    `attacker_persistence_ai_assisted_runtime` site reads "same anchor
    discipline as `attacker_persistence_ai_assisted`"; R_16 honors that.

    Scope is narrow by design: the rule is a no-op for every other
    classification so it doesn't second-guess findings where the anchor
    concept doesn't apply."""
    if finding.classification not in _AI_ANCHOR_REQUIRED_CLASSIFICATIONS:
        return None
    joined = " ".join(ev.output_excerpt for ev in finding.evidence)
    if _contains_ai_anchor(joined):
        return None
    return RuleFailure(
        rule_id="R_16",
        code="AI_ASSIST_ANCHOR_MISSING",
        detail=(f"classification={finding.classification} but no concrete "
                f"AI-artifact anchor (LLM endpoint URL / AI-SDK import / "
                f"AI API-key env var) found in cited output_excerpts"),
    )


def R_15(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Low-confidence auto-escalation (Slice 6 Step 3).

    The L3 rubric in `pipeline.schemas.CONFIDENCE_RUBRIC` defines `low` as
    'weak or ambiguous signal — insufficient to commit'. R_15 enforces the
    routing: any finding emitted at confidence=low escalates to
    human_review rather than committing silently. Pairs with R_08
    (CONF_OVERSTATED) which catches the opposite pathology — high-confidence
    findings without primary-tool backing.

    Applies uniformly across categories. A NOT_FOUND@low is anomalous (Hard
    Rule 4 in INTERPRET_SYSTEM_PROMPT says NOT_FOUND should be high-confidence),
    but a hedged absence claim equally deserves human adjudication, so R_15
    fires there too. R_14 is reserved for citation-gate activation."""
    if finding.confidence != "low":
        return None
    return RuleFailure(
        rule_id="R_15",
        code="LOW_CONFIDENCE_AUTO_ESCALATE",
        detail=(f"finding category={finding.category}, "
                f"classification={finding.classification} emitted at "
                f"confidence=low — auto-escalating per L3 rubric"),
    )


# Rule registry + escalate-only failure codes
# Order mirrors the rule-id numbering. R_14 is reserved for citation-gate
# activation (mechanism lives below as parse_evidence_citations); R_15 was the
# next unreserved slot for low-confidence auto-escalation.
CRITIC_RULES = [R_01, R_02, R_03, R_04, R_05, R_06, R_07, R_08, R_09, R_10, R_11, R_12, R_13, R_15, R_16]
ESCALATE_CODES = {
    "EXCERPT_HALLUCINATION",
    "INJECTION_FLAGGED_EVIDENCE",
    "INJECTION_QUARANTINE",      # Step 8: quarantine-severity injection flag
    "TEMPORAL_INCONSISTENT",
    "CANARY_LEAK",               # interpret_node boundary-leak tripwire
    "UNCITED_CLAIM",             # R_14 mechanism landed 2026-04-24; activation deferred
    "LOW_CONFIDENCE_AUTO_ESCALATE",  # R_15 — Slice 6 Step 3 L3 rubric enforcement
}


# ============================================================================
# Citation gate (R_14 mechanism) — Tier-1 AI-adversary add-on, 2026-04-24.
#
# Landing the mechanism (parser + validator + FailureCode) WITHOUT wiring the
# rule into CRITIC_RULES yet. Activation is a separate step that requires an
# end-to-end pipeline run proving the INTERPRET LLM reliably emits the
# `[ev:<tool_call_id>]` citation format now specified in INTERPRET_SYSTEM_PROMPT.
# Same opt-in-until-verified discipline the canary tripwire followed.
#
# The rule will sit alongside R_11: R_11 checks that `notes` rules out benign
# alternatives for high-confidence attacker_persistence; R_14 checks that
# those rule-out claims carry inline `[ev:<id>]` citations pointing to real
# tool_call_ids in the bundle. Together they prevent free-text hallucination.
# ============================================================================

_EVIDENCE_CITATION_RE = re.compile(r"\[ev:([A-Za-z0-9_\-]+)\]")


class CitationCheckResult:
    """Result of parsing + validating citations in a Finding's free-text field.

    Attributes:
        cited_ids      — tool_call_ids in document order; duplicates preserved.
        distinct_cited — set of unique IDs cited.
        invalid_ids    — distinct IDs that are NOT in the run's bundle
                         (candidates for UNCITED_CLAIM with detail="cites unknown id").
        has_citations  — True if any `[ev:<id>]` marker was present.
    """
    __slots__ = ("cited_ids", "distinct_cited", "invalid_ids", "has_citations")

    def __init__(
        self,
        cited_ids: list[str],
        distinct_cited: set[str],
        invalid_ids: set[str],
        has_citations: bool,
    ):
        self.cited_ids = cited_ids
        self.distinct_cited = distinct_cited
        self.invalid_ids = invalid_ids
        self.has_citations = has_citations

    def __repr__(self) -> str:  # pragma: no cover — debugging aid
        return (
            f"CitationCheckResult(cited_ids={self.cited_ids!r}, "
            f"distinct_cited={sorted(self.distinct_cited)!r}, "
            f"invalid_ids={sorted(self.invalid_ids)!r}, "
            f"has_citations={self.has_citations})"
        )


def parse_evidence_citations(text: str) -> list[str]:
    """Extract cited tool_call_ids from free text (typically `Finding.notes`).

    Returns the list of IDs in document order; duplicates preserved so the
    caller can see which excerpts were cited multiple times vs. once. Empty
    list if `text` is empty or has no `[ev:<id>]` markers.

    Format is strict: `[ev:<tool_call_id>]` with no internal whitespace.
    Malformed markers (`[ev: tc-0]`, `[ev tc-0]`) are ignored — the strictness
    is intentional so ambiguous free text never resolves to a false citation.
    """
    if not text:
        return []
    return _EVIDENCE_CITATION_RE.findall(text)


def validate_finding_citations(
    notes: str, available_tool_call_ids: set[str]
) -> CitationCheckResult:
    """Parse `notes` and cross-check cited IDs against the bundle's tool_call_ids.

    Pure validation — reports what it found. Policy ("attacker_persistence at
    high confidence MUST carry a citation", etc.) lives in the caller (future
    R_14), not here.
    """
    cited = parse_evidence_citations(notes)
    distinct = set(cited)
    invalid = distinct - available_tool_call_ids
    return CitationCheckResult(
        cited_ids=cited,
        distinct_cited=distinct,
        invalid_ids=invalid,
        has_citations=bool(cited),
    )


# ---- Orchestrator (from C11) ----

def critic_evaluate(finding: Finding, ctx: CriticContext, finding_index: int) -> CritiqueResult:
    """Evaluate one Finding against all 13 rules. Returns CritiqueResult with severity."""
    passed: list = []
    failed: list = []
    for rule in CRITIC_RULES:
        result = rule(finding, ctx)
        if result is None:
            passed.append(rule.__name__)
        else:
            failed.append(result)

    if not failed:
        severity = "pass"
    elif any(f.code in ESCALATE_CODES for f in failed):
        severity = "escalate"
    else:
        severity = "retry"

    return CritiqueResult(
        finding_index=finding_index,
        rules_passed=passed,
        rules_failed=failed,
        is_llm_judgment=False,
        severity=severity,
    )


# ---- Retry policy + new_instruction templates (from C12) ----

PER_FINDING_RETRY_LIMIT = 2
TOKEN_CEILING_PER_INVESTIGATION = 200_000   # input + output combined; pin to USD after Slice 6 cost tracking


def total_roundtrip_limit(plan: ToolPlan) -> int:
    """Scale the round-trip ceiling with the already-approved plan size.
    min(2 * n_steps, 15) keeps short plans cheap while allowing long ones room to retry."""
    return min(2 * len(plan.steps), 15)


# Per-rule new_instruction templates — callables that render a targeted correction
# message. R_05 / R_10 / R_13 have no templates; they force severity=escalate.

def _ni_R_01(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    valid = list(ctx.evidence.keys())
    sample = valid[:8]
    tail = '' if len(valid) <= 8 else f' (and {len(valid) - 8} more)'
    return (f"Finding {idx} cites a tool_call_id that does not exist in this run's evidence. "
            f"Re-produce this finding using only tool_call_ids present in: {sample}{tail}.")


def _ni_R_02(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    return (f"Finding {idx}.mechanism={finding.mechanism!r} and value={finding.value!r} reference a path/name "
            f"whose components do not appear in the cited output_excerpts. Re-quote the exact substring "
            f"from the tool output that supports the mechanism, or downgrade the finding if no supporting "
            f"evidence exists.")


def _ni_R_03(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    required = sorted(CATEGORY_REQUIRED_TOOLS.get(finding.category, set()))
    cited = sorted({
        t for ev in finding.evidence
        if (t := ctx.tool_for(ev.tool_call_id)) is not None
    })
    return (f"Category={finding.category} requires evidence from one of {required} but the plan only ran "
            f"{cited}. Extend the plan to include the missing tool(s) against the canonical path for this category.")


def _ni_R_04(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    return (f"Finding {idx} claims category=registry_run_key but mechanism={finding.mechanism!r} does not begin "
            f"with HKLM, HKCU, HKU, or HKEY_. Re-format the mechanism as a proper registry key path, or change "
            f"the category if the value is not actually a registry path.")


def _ni_R_06(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    union = set().union(*CATEGORY_REQUIRED_TOOLS.values())
    ran_ok = {
        ctx.tool_for(tcid)
        for tcid, rec in ctx.evidence.items()
        if rec.tool_execution_status == "ok" and ctx.tool_for(tcid) is not None
    }
    missing = sorted(union - ran_ok)
    return (f"Claim of NOT_FOUND at high confidence is not supported: tools {missing} have no successful "
            f"calls in this run. Re-plan to run {missing} against their canonical paths, or downgrade "
            f"confidence to medium.")


def _ni_R_07(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    return (f"Finding {idx} has empty {failure.detail.split()[0]}. Either populate it from the cited evidence, "
            f"or remove the finding if the evidence doesn't actually support a non-NOT_FOUND claim.")


def _ni_R_08(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    required = sorted(CATEGORY_REQUIRED_TOOLS.get(finding.category, set()))
    return (f"Finding {idx} claims high confidence but none of its evidence cites a primary tool for "
            f"category={finding.category} (primary tools: {required}). Either downgrade to medium confidence, "
            f"or add evidence from a primary tool.")


def _ni_R_09(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    failed_pairs = [
        (ev.tool_call_id, ctx.evidence[ev.tool_call_id].tool_execution_status)
        for ev in finding.evidence
        if ev.tool_call_id in ctx.evidence
        and ctx.evidence[ev.tool_call_id].tool_execution_status != "ok"
    ]
    return (f"Finding {idx} cites tool calls whose tool_execution_status is not 'ok': "
            f"{failed_pairs}. A non-ok call produced no trustworthy evidence. Re-produce "
            f"the finding using only ok-status calls, or remove if no successful evidence exists.")


def _ni_R_11(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    return (f"Finding {idx} is missing the required classification field, or claims attacker_persistence "
            f"without ruling out benign alternatives in notes. Re-interpret with the disambiguation rules: "
            f"rule out (a) DFIR/IR responder tools (F-Response, Mnemosyne, Volatility, KAPE, Velociraptor, "
            f"Sysmon, WinPMEM, Redline), (b) commercial security/IT products (McAfee, VMware, Windows "
            f"Defender, CrowdStrike), (c) Windows defaults (Perf* services, RPC family, TCP/IP stack). Set "
            f"classification to one of: attacker_persistence, legitimate_responder_tool, "
            f"legitimate_vendor_product, legitimate_windows_default, requires_disambiguation. For "
            f"attacker_persistence, notes must explicitly list the benign hypotheses ruled out.")


def _ni_R_12(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    failed = [
        (ctx.tool_for(tcid) or "unknown", tcid, rec.tool_execution_status)
        for tcid, rec in ctx.evidence.items()
        if rec.tool_execution_status not in ("ok", "empty")
    ]
    return (f"Finding {idx} claims NOT_FOUND at high confidence, but {len(failed)} tool call(s) "
            f"in this run did not return ok-status: {failed}. An evidence-of-absence claim requires "
            f"every tool in the run to have completed successfully. Re-plan to re-run the failed "
            f"tools against their canonical paths, or downgrade the claim's confidence to medium.")


def _ni_R_16(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    return (f"Finding {idx} is classified as attacker_persistence_ai_assisted but no "
            f"concrete AI-artifact anchor appears in the cited output_excerpts. "
            f"Either (a) re-cite an excerpt that contains an LLM API endpoint URL "
            f"(api.openai.com, api.anthropic.com, generativelanguage.googleapis.com, "
            f"api-inference.huggingface.co), an AI-SDK import (import openai, "
            f"import anthropic, import langchain, google.generativeai, huggingface_hub), "
            f"or an AI API-key env var name (OPENAI_API_KEY, ANTHROPIC_API_KEY, "
            f"HUGGINGFACE_HUB_TOKEN, HF_TOKEN, GOOGLE_API_KEY, GEMINI_API_KEY) that "
            f"substantiates the AI-assisted classification; or (b) downgrade "
            f"classification to attacker_persistence (no AI specialization) if no "
            f"such anchor exists.")


NEW_INSTRUCTION_TEMPLATES: dict[str, callable] = {
    "EVID_UNRESOLVED":           _ni_R_01,
    "PATH_INCONSISTENCY":        _ni_R_02,
    "TOOL_MISMATCH":             _ni_R_03,
    "INVALID_REG_PATH":          _ni_R_04,
    "SCOPE_INCOMPLETE":          _ni_R_06,
    "EMPTY_FINDING_DATA":        _ni_R_07,
    "CONF_OVERSTATED":           _ni_R_08,
    "EVIDENCE_TOOL_EXIT_NONZERO":_ni_R_09,
    "CLASSIFICATION_MISSING":    _ni_R_11,
    "ABSENCE_UNSUBSTANTIATED":   _ni_R_12,
    "AI_ASSIST_ANCHOR_MISSING":  _ni_R_16,
    # EXCERPT_HALLUCINATION, INJECTION_FLAGGED_EVIDENCE, TEMPORAL_INCONSISTENT escalate — no correction
}


# Which branch a given code routes to when it's a retry (not escalate)
RETRY_BRANCH: dict[str, str] = {
    "EVID_UNRESOLVED":           "re_interpret",
    "PATH_INCONSISTENCY":        "re_interpret",
    "TOOL_MISMATCH":             "re_plan",       # missing tool = plan-level gap
    "INVALID_REG_PATH":          "re_interpret",
    "SCOPE_INCOMPLETE":          "re_plan",       # missing scope = plan-level gap
    "EMPTY_FINDING_DATA":        "re_interpret",
    "CONF_OVERSTATED":           "re_interpret",
    "EVIDENCE_TOOL_EXIT_NONZERO":"re_interpret",
    "CLASSIFICATION_MISSING":    "re_interpret",
    "ABSENCE_UNSUBSTANTIATED":   "re_plan",       # re-run failed tools
    "AI_ASSIST_ANCHOR_MISSING":  "re_interpret",  # model re-cites anchor or downgrades classification
}


def build_new_instruction(failure: RuleFailure, finding: Finding,
                          ctx: CriticContext, finding_index: int) -> str:
    """Render the correction message injected into the upstream LLM call on retry."""
    template = NEW_INSTRUCTION_TEMPLATES.get(failure.code)
    if template:
        return template(failure, finding, ctx, finding_index)
    # No template — shouldn't happen for retryable codes, but safe fallback:
    return f"Finding {finding_index} failed {failure.rule_id} ({failure.code}): {failure.detail}"


def critic_edge(state) -> str:
    """LangGraph branch selector: decide next transition based on Critic results
    + retry/token budget. Expects state attributes: critique_results, iteration,
    attempts_per_finding, tokens_used, tool_plan.
    Returns one of: commit | re_interpret | re_plan | escalate."""
    tokens = getattr(state, "tokens_used", 0)
    iteration = getattr(state, "iteration", 0)
    results = getattr(state, "critique_results", [])
    attempts = getattr(state, "attempts_per_finding", {})

    if tokens > TOKEN_CEILING_PER_INVESTIGATION:
        return "escalate"
    if state.tool_plan and iteration >= total_roundtrip_limit(state.tool_plan):
        return "escalate"
    if any(c.severity == "escalate" for c in results):
        return "escalate"
    retrying = [c for c in results if c.severity == "retry"]
    if not retrying:
        return "commit"
    # Any finding past its per-finding budget → escalate
    if any(attempts.get(c.finding_index, 0) >= PER_FINDING_RETRY_LIMIT for c in retrying):
        return "escalate"
    # First retry → re_interpret; second → re_plan. Per-rule override:
    # if any retrying rule specifically needs re_plan (SCOPE/TOOL), prefer re_plan.
    needs_replan = any(RETRY_BRANCH.get(rf.code) == "re_plan"
                       for c in retrying for rf in c.rules_failed)
    if needs_replan and iteration >= 1:
        return "re_plan"
    return "re_interpret" if iteration == 0 else "re_plan"


# ---- Resolution builder (moved from notebook C13 at Slice 5 Step 7c) ----

def build_resolution(
    critique: CritiqueResult, finding: Finding, ctx: CriticContext,
) -> dict:
    """Assemble the `resolution` payload that the audit-log JSONL entry carries
    alongside every Critic disagreement. Three shapes:

      - `pass`      → {"action": "commit", "strategy": None, "new_instruction": None}
      - `escalate`  → {"action": "escalate", "strategy": "human_review", "new_instruction": None}
      - `retry`     → {"action": "retry", "strategy": "re_interpret|re_plan",
                       "new_instruction": <combined correction text>}

    `strategy` for retries uses the per-rule `RETRY_BRANCH` table: if any of
    the retryable failures prefers `re_plan` (missing scope / tool), that wins
    over `re_interpret`. `new_instruction` is the join of `build_new_instruction`
    calls for every retryable rule failure — the LLM sees them all in one pass,
    matching the C13 contract.
    """
    if critique.severity == "pass":
        return {"action": "commit", "strategy": None, "new_instruction": None}
    if critique.severity == "escalate":
        return {
            "action": "escalate", "strategy": "human_review",
            "new_instruction": None,
        }
    # retry — combine corrections across all retryable failures
    retryable = [rf for rf in critique.rules_failed if rf.code not in ESCALATE_CODES]
    if not retryable:
        return {
            "action": "escalate", "strategy": "human_review",
            "new_instruction": None,
        }
    instructions = [
        build_new_instruction(rf, finding, ctx, critique.finding_index)
        for rf in retryable
    ]
    strategy = (
        "re_plan"
        if any(RETRY_BRANCH.get(rf.code) == "re_plan" for rf in retryable)
        else "re_interpret"
    )
    return {
        "action": "retry", "strategy": strategy,
        "new_instruction": "\n\n".join(instructions),
    }


__all__ = [
    # Context + helpers
    "CriticContext",
    "CATEGORY_REQUIRED_TOOLS",
    # Rules + registry
    "R_01", "R_02", "R_03", "R_04", "R_05", "R_06", "R_07",
    "R_08", "R_09", "R_10", "R_11", "R_12", "R_13",
    "R_15", "R_16",  # Slice 6 Step 3 + 3b
    "AI_ASSIST_ANCHORS",  # exposed so tests can assert coverage
    "CRITIC_RULES", "ESCALATE_CODES",
    # Orchestrator
    "critic_evaluate",
    # Retry policy
    "PER_FINDING_RETRY_LIMIT", "TOKEN_CEILING_PER_INVESTIGATION",
    "total_roundtrip_limit",
    # Retry router
    "NEW_INSTRUCTION_TEMPLATES", "RETRY_BRANCH",
    "build_new_instruction", "critic_edge",
    # Resolution builder (moved from C13 at Step 7c)
    "build_resolution",
]
