"""Deterministic Critic — rule bodies, orchestrator, retry policy, edge router.

Extracted from slice2.ipynb cells C10/C11/C12 at Slice 5 Step 1 (dependency-leaf
after pipeline.schemas). Pure Python; no I/O beyond reading persisted stdout
files via `CriticContext.get_full_stdout()`.

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

R_13 is a stub pending Slice 5's `hive_lastwrite` structured field.
R_06 is minimum-viable pending Slice 5's `expected_paths_covered` per tool.
"""
from pathlib import Path
import re

from pipeline.schemas import (
    CritiqueResult,
    Finding,
    PersistenceCategory,
    RawResult,
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

    Receives:  the approved tool plan + the raw tool-call results.
    Does NOT receive: Interpret LLM output, chain-of-thought, prior Findings.
    """
    def __init__(self, tool_plan: ToolPlan, raw_results: list[RawResult]):
        self.tool_plan = tool_plan
        self.tool_calls: dict[str, RawResult] = {r.tool_call_id: r for r in raw_results}
        self._stdout_cache: dict[str, bytes] = {}

    def get_full_stdout(self, tool_call_id: str) -> bytes:
        """Read the full persisted stdout for a tool call (not just the 64KB excerpt).
        Used by R_05 when the cited excerpt might be past the excerpt cap.
        Missing file → empty bytes; R_05 treats 'not found in stdout' as a fail."""
        if tool_call_id in self._stdout_cache:
            return self._stdout_cache[tool_call_id]
        r = self.tool_calls.get(tool_call_id)
        if r is None:
            self._stdout_cache[tool_call_id] = b""
            return b""
        try:
            data = Path(r.stdout_path).read_bytes()
        except (FileNotFoundError, OSError, PermissionError):
            data = b""
        self._stdout_cache[tool_call_id] = data
        return data


# ---- Helpers used by multiple rules ----
_PATH_SEP_RE = re.compile(r"[\\/]")


def _path_tokens(s: str) -> set[str]:
    """Split a path-like string into components; drop tokens shorter than 3 chars."""
    if not s:
        return set()
    return {t for t in _PATH_SEP_RE.split(s) if len(t) >= 3}


# ---- Rule implementations (R_01 — R_13) ----

def R_01(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Did the agent cite evidence that actually exists in the run log?"""
    for ev in finding.evidence:
        if ev.tool_call_id not in ctx.tool_calls:
            return RuleFailure(rule_id="R_01", code="EVID_UNRESOLVED",
                               detail=f"evidence.tool_call_id={ev.tool_call_id!r} not in raw_results")
    return None


def R_02(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """When the finding claims a path/name, do components of it appear in quoted evidence?"""
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
    cited_tools = {ctx.tool_calls[ev.tool_call_id].tool
                   for ev in finding.evidence if ev.tool_call_id in ctx.tool_calls}
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
    """Is the quoted evidence actually present in the tool's output byte-for-byte?
    ESCALATE (not retry) — excerpt fabrication is the most serious integrity failure."""
    for ev in finding.evidence:
        rr = ctx.tool_calls.get(ev.tool_call_id)
        if rr is None:
            continue  # R_01 handles
        needle = ev.output_excerpt or ""
        if not needle:
            continue  # empty excerpt is R_07 territory
        if needle in rr.stdout_excerpt:
            continue  # fast path: found in the 64KB excerpt
        # fall back to the full persisted stdout (for excerpts past the 64KB cap)
        haystack = ctx.get_full_stdout(ev.tool_call_id)
        if needle.encode("utf-8", errors="replace") in haystack:
            continue
        return RuleFailure(rule_id="R_05", code="EXCERPT_HALLUCINATION",
                           detail=f"output_excerpt bytes not found in stdout for tool_call_id={ev.tool_call_id!r}")
    return None


def R_06(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """If 'nothing found,' did we actually look everywhere we should have?"""
    if finding.category != "NOT_FOUND" or finding.confidence != "high":
        return None
    required_union = set().union(*CATEGORY_REQUIRED_TOOLS.values())
    tools_run_ok = {r.tool for r in ctx.tool_calls.values() if r.exit_code == 0}
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
        ctx.tool_calls[ev.tool_call_id].tool in required
        for ev in finding.evidence if ev.tool_call_id in ctx.tool_calls
    )
    if cited_primary:
        return None
    return RuleFailure(rule_id="R_08", code="CONF_OVERSTATED",
                       detail=f"high-confidence {finding.category} finding does not cite a primary "
                              f"tool ({sorted(required)}); downgrade to medium")


def R_09(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Did every cited tool call actually succeed?"""
    for ev in finding.evidence:
        rr = ctx.tool_calls.get(ev.tool_call_id)
        if rr is None:
            continue  # R_01 handles
        if rr.exit_code != 0:
            return RuleFailure(rule_id="R_09", code="EVIDENCE_TOOL_EXIT_NONZERO",
                               detail=f"evidence cites tool_call_id={ev.tool_call_id!r} with exit_code={rr.exit_code}")
    return None


def R_10(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Was any cited evidence flagged by the injection scanner? ESCALATE on any fire.
    RawResult.injection_flagged defaults to False until Slice 5 scanner ships."""
    for ev in finding.evidence:
        rr = ctx.tool_calls.get(ev.tool_call_id)
        if rr is None:
            continue
        if getattr(rr, "injection_flagged", False):
            return RuleFailure(rule_id="R_10", code="INJECTION_FLAGGED_EVIDENCE",
                               detail=f"evidence tool_call_id={ev.tool_call_id!r} was flagged by the injection scanner")
    return None


def R_11(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Did the agent declare what kind of thing this finding is, with rationale?
    Missing classification is caught upstream by Pydantic (classification is required).
    Here we additionally check: attacker_persistence at high confidence must contain
    ruled-out-alternatives language in notes."""
    if not finding.classification:
        return RuleFailure(rule_id="R_11", code="CLASSIFICATION_MISSING",
                           detail="classification field is empty")
    if finding.classification == "attacker_persistence" and finding.confidence == "high":
        notes_lc = (finding.notes or "").lower()
        # catches 'ruled out', 'ruling out', 'rules out', 'ruled-out'
        if "rul" not in notes_lc:
            return RuleFailure(rule_id="R_11", code="CLASSIFICATION_MISSING",
                               detail="attacker_persistence at high confidence must explicitly rule out benign alternatives in notes")
    return None


def R_12(finding: Finding, ctx: CriticContext) -> RuleFailure | None:
    """Evidence-of-Absence: a high-confidence NOT_FOUND claim is only defensible
    if every tool in the run completed cleanly. Additive over R_06 — R_06 checks
    the category-required tool set; R_12 checks the whole run.

    Slice 5 target: check `tool_execution_status == "ok"` via structured metadata
    (see docs/runbooks/slice-5-runbook.md). Pre-Slice-5 proxy: exit_code != 0."""
    if finding.category != "NOT_FOUND" or finding.confidence != "high":
        return None
    failed = [r for r in ctx.tool_calls.values() if r.exit_code != 0]
    if not failed:
        return None
    failed_summary = [(r.tool, r.tool_call_id, r.exit_code) for r in failed[:5]]
    return RuleFailure(rule_id="R_12", code="ABSENCE_UNSUBSTANTIATED",
                       detail=f"NOT_FOUND at high confidence but {len(failed)} tool call(s) failed in this run: {failed_summary}")


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


# Rule registry + escalate-only failure codes
CRITIC_RULES = [R_01, R_02, R_03, R_04, R_05, R_06, R_07, R_08, R_09, R_10, R_11, R_12, R_13]
ESCALATE_CODES = {"EXCERPT_HALLUCINATION", "INJECTION_FLAGGED_EVIDENCE", "TEMPORAL_INCONSISTENT"}


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
    valid = list(ctx.tool_calls.keys())
    sample = valid[:8]
    tail = '' if len(valid) <= 8 else f' (and {len(valid) - 8} more)'
    return (f"Finding {idx} cites a tool_call_id that does not exist in this run's raw_results. "
            f"Re-produce this finding using only tool_call_ids present in: {sample}{tail}.")


def _ni_R_02(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    return (f"Finding {idx}.mechanism={finding.mechanism!r} and value={finding.value!r} reference a path/name "
            f"whose components do not appear in the cited output_excerpts. Re-quote the exact substring "
            f"from the tool output that supports the mechanism, or downgrade the finding if no supporting "
            f"evidence exists.")


def _ni_R_03(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    required = sorted(CATEGORY_REQUIRED_TOOLS.get(finding.category, set()))
    cited = sorted({ctx.tool_calls[ev.tool_call_id].tool
                    for ev in finding.evidence if ev.tool_call_id in ctx.tool_calls})
    return (f"Category={finding.category} requires evidence from one of {required} but the plan only ran "
            f"{cited}. Extend the plan to include the missing tool(s) against the canonical path for this category.")


def _ni_R_04(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    return (f"Finding {idx} claims category=registry_run_key but mechanism={finding.mechanism!r} does not begin "
            f"with HKLM, HKCU, HKU, or HKEY_. Re-format the mechanism as a proper registry key path, or change "
            f"the category if the value is not actually a registry path.")


def _ni_R_06(failure: RuleFailure, finding: Finding, ctx: CriticContext, idx: int) -> str:
    union = set().union(*CATEGORY_REQUIRED_TOOLS.values())
    ran_ok = {r.tool for r in ctx.tool_calls.values() if r.exit_code == 0}
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
    failed_tcids = [ev.tool_call_id for ev in finding.evidence
                    if ev.tool_call_id in ctx.tool_calls and ctx.tool_calls[ev.tool_call_id].exit_code != 0]
    return (f"Finding {idx} cites tool calls with exit_code != 0: {failed_tcids}. Failed tool output is not "
            f"evidence. Re-produce the finding using only exit_code=0 calls, or remove if no successful "
            f"evidence exists.")


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
    failed = [(r.tool, r.tool_call_id, r.exit_code)
              for r in ctx.tool_calls.values() if r.exit_code != 0]
    return (f"Finding {idx} claims NOT_FOUND at high confidence, but {len(failed)} tool call(s) "
            f"in this run failed: {failed}. An evidence-of-absence claim requires every tool in "
            f"the run to have completed successfully. Re-plan to re-run the failed tools against "
            f"their canonical paths, or downgrade the claim's confidence to medium.")


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


__all__ = [
    # Context + helpers
    "CriticContext",
    "CATEGORY_REQUIRED_TOOLS",
    # Rules + registry
    "R_01", "R_02", "R_03", "R_04", "R_05", "R_06", "R_07",
    "R_08", "R_09", "R_10", "R_11", "R_12", "R_13",
    "CRITIC_RULES", "ESCALATE_CODES",
    # Orchestrator
    "critic_evaluate",
    # Retry policy
    "PER_FINDING_RETRY_LIMIT", "TOKEN_CEILING_PER_INVESTIGATION",
    "total_roundtrip_limit",
    # Retry router
    "NEW_INSTRUCTION_TEMPLATES", "RETRY_BRANCH",
    "build_new_instruction", "critic_edge",
]
