"""Cost-print helpers for OpenRouter calls.

Use BEFORE and AFTER every chat.completions.create() to surface real-time spend.
Pattern matches pipeline/nodes.py _llm_cost_pre / _llm_cost_post but works for
any caller (probe scripts, ad-hoc Python, notebooks).

Usage:
    from llm_cost import cost_pre, cost_post

    cost_pre("phase-label", model, messages)
    response = client.chat.completions.create(..., extra_body={"usage":{"include":True}})
    cost_post("phase-label", model, response.usage)

Or with raw urllib + OpenRouter REST:
    cost_pre("phase-label", model, messages)
    body = {..., "usage": {"include": True}}  # ask OR for cost in response
    out = json.loads(urllib.request.urlopen(...).read())
    cost_post("phase-label", model, out.get("usage", {}))
"""
from __future__ import annotations
import json
from typing import Any

# OpenRouter pricing (USD per 1M tokens). Keep in sync with provider pricing.
# Used as fallback when OpenRouter does NOT return usage.cost (e.g. caller did
# not include extra_body usage:include:true). Authoritative number is always
# usage.cost when present.
_OR_RATES: dict[str, dict[str, float]] = {
    "anthropic/claude-sonnet-4-6":   {"in":  3.00, "out": 15.00},
    "anthropic/claude-sonnet-4-5":   {"in":  3.00, "out": 15.00},
    "anthropic/claude-haiku-4-5":    {"in":  1.00, "out":  5.00},
    "anthropic/claude-opus-4-7":     {"in": 15.00, "out": 75.00},
    "anthropic/claude-opus-4-6":     {"in": 15.00, "out": 75.00},
    "google/gemini-3-flash-preview": {"in":  0.50, "out":  3.00},
    "google/gemini-2-5-flash":       {"in":  0.30, "out":  2.50},
}


def cost_pre(label: str, model: str, messages: list) -> None:
    """Print pre-call estimate. Tokens only, no dollar guess (rates drift)."""
    text = json.dumps(messages)
    est_tokens = len(text) // 4
    print(f"  [{label}] PRE  model={model}  est_input~{est_tokens:,} tok", flush=True)


def cost_post(label: str, model: str, usage: Any) -> None:
    """Print actual cost. Reads usage.cost (preferred) or falls back to rates.

    `usage` can be a dict (from raw HTTP response) or an SDK object with
    .prompt_tokens / .completion_tokens / .cost attributes.
    """
    if isinstance(usage, dict):
        pt = int(usage.get("prompt_tokens") or 0)
        ct = int(usage.get("completion_tokens") or 0)
        cost = usage.get("cost")
    else:
        pt = int(getattr(usage, "prompt_tokens", 0) or 0)
        ct = int(getattr(usage, "completion_tokens", 0) or 0)
        cost = getattr(usage, "cost", None)

    if cost is not None:
        print(
            f"  [{label}] POST model={model}\n"
            f"           input={pt:,} tok  output={ct:,} tok  "
            f"total=${float(cost):.5f}",
            flush=True,
        )
        return

    rates = _OR_RATES.get(model)
    if rates is None:
        print(
            f"  [{label}] POST model={model}  input={pt:,} tok  output={ct:,} tok  "
            f"total=$? (rate unknown; add {model!r} to scripts/llm_cost.py _OR_RATES)",
            flush=True,
        )
        return

    in_cost = pt / 1_000_000 * rates["in"]
    out_cost = ct / 1_000_000 * rates["out"]
    total = in_cost + out_cost
    print(
        f"  [{label}] POST model={model}\n"
        f"           input={pt:,} tok (${in_cost:.5f})  "
        f"output={ct:,} tok (${out_cost:.5f})  "
        f"total=${total:.5f} (rate-table fallback)",
        flush=True,
    )
