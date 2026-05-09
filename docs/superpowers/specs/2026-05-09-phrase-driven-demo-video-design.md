---
created: 2026-05-09
status: approved
supersedes: docs/superpowers/specs/2026-05-09-demo-video-script-design.md (production flow + beat structure stay; voice-to-visual pattern changes)
deliverable: 5-minute screencast for SANS Find Evil hackathon
---

# Phrase-driven demo video: voice-to-visual pattern

## TL;DR

The previous design treated each beat as a single Playwright scene that ran for N seconds with a single voiceover paragraph. Result: the narrator talked about specific architectural pieces (capability tokens, INJECTION_QUARANTINE, integrity ledger) while the screen just slow-scrolled past everything. Charan caught it on the first review and named the problem: voice-to-visual pattern matching must be highly regulated. This spec replaces the per-beat model with a per-phrase model. Every 5 to 10 word claim in the voiceover is its own unit, with its own duration and its own target DOM selector. When the phrase fires, an outlined-box annotation draws around the named element. Captions, voice generation, and scene timing all derive from the same PHRASES list so nothing can drift. The production flow (visuals first, voice last, Phase D.5 review gate) stays unchanged.

## What changes vs the prior spec

- Add a top-level `PHRASES` list as the single source of truth for the entire video.
- Each phrase entry: `{beat, text, duration_s, target_selector | None, annotation}`.
- `captions.py` becomes a thin wrapper that builds the SRT from PHRASES (each phrase = one SRT cue at its computed cumulative start).
- `voice_gen.py` concatenates phrases per beat into the ElevenLabs API call body.
- Scene scripts become phrase iterators: walk the PHRASES for that beat, highlight the target selector if any, sleep the phrase duration, unhighlight, next.
- Add a generic `highlight()` helper in scenes that draws an outlined box around a target element via `page.evaluate`.

## What stays unchanged

- Five beats: open, architecture, case walkthrough, loop closing, outro. Same total budget (300s).
- Production phases A through F. Phase D.5 review gate before voice. Voice last.
- Docker image (`demo-video:latest`).
- Burned-in captions (PlayResX/PlayResY pinned to 1920x1080, Fontsize 22, bottom edge).
- Cross-host evidence beat in the case walkthrough (rd-02-dual + base-file).
- Live promote of the apt28 rule in the loop-closing beat.

## PHRASES data shape

```python
# scripts/demo_video/phrases.py (NEW)

# Each phrase is one (text, duration_s, target_selector) plus the beat it
# belongs to. Phrases inside a beat fire in order; their durations sum to
# the beat's total duration. Selectors are passed to page.evaluate; None
# means no annotation, just a stable hold on the current frame.
#
# Selector syntax: standard CSS selector OR :contains() text-match. The
# `highlight()` helper in scenes/_helpers.py supports both via JS.
#
# Annotation type: 'box' for outlined box (default). Other types (arrow,
# label) reserved for future use; default is box.

PHRASES = [
    # ── beat1_open (15s, 3 phrases) ────────────────────────────────────
    {"beat": "beat1_open", "text": "Last night, an AI agent I built found a fake Microsoft service hiding on a real Windows server.", "duration_s": 6.0, "selector": None},
    {"beat": "beat1_open", "text": "Then it caught itself making a mistake on the next finding.", "duration_s": 4.5, "selector": None},
    {"beat": "beat1_open", "text": "Then it drafted a rule so it gets the next case right. Here is how.", "duration_s": 4.5, "selector": None},

    # ── beat2_architecture (45s, 9 phrases) ────────────────────────────
    {"beat": "beat2_architecture", "text": "Sentinel runs the autonomous incident response loop", "duration_s": 4.5, "selector": "h2:has-text('Five trust controls')"},
    {"beat": "beat2_architecture", "text": "with three architectural guardrails, not just prompt promises.", "duration_s": 4.5, "selector": None},
    {"beat": "beat2_architecture", "text": "First: every tool call crosses a capability-token boundary at the MCP server,", "duration_s": 6.0, "selector": "h3:has-text('Execution boundary')"},
    {"beat": "beat2_architecture", "text": "scoped to the case ID and the allowed paths.", "duration_s": 4.0, "selector": "h2:has-text('Execution boundary deep dive')"},
    {"beat": "beat2_architecture", "text": "Second: an injection scanner sits in the Critic", "duration_s": 5.0, "selector": "h3:has-text('Defender AI integrity')"},
    {"beat": "beat2_architecture", "text": "and quarantines tool output that looks adversarial.", "duration_s": 4.5, "selector": "h2:has-text('Defender AI integrity deep dive')"},
    {"beat": "beat2_architecture", "text": "Third: every step of every run is hash-chained into an integrity ledger,", "duration_s": 5.5, "selector": "h2:has-text('Integrity deep dive')"},
    {"beat": "beat2_architecture", "text": "so a finding can be traced back to the exact tool execution that produced it.", "duration_s": 5.5, "selector": ".external-ledger"},
    {"beat": "beat2_architecture", "text": "The critic and the learn nodes are where the autonomy lives.", "duration_s": 5.5, "selector": "h3:has-text('Deterministic checks')"},

    # ── beat3_case (180s, ~30 phrases across 4 sub-beats) ──────────────
    # 3a findings overview (30s, 6 phrases) - viewer landing + load run
    {"beat": "beat3_case", "text": "The case: a Windows server from a 2018 enterprise compromise.", "duration_s": 5.0, "selector": ".case-header:has-text('srl-2018-base-rd-02-dual')"},
    {"beat": "beat3_case", "text": "The agent ran in dual-channel mode,", "duration_s": 3.5, "selector": ".channel-pill.channel-dual"},
    {"beat": "beat3_case", "text": "looking at both the disk image and a memory snapshot in the same run.", "duration_s": 5.0, "selector": None},
    {"beat": "beat3_case", "text": "The first finding is a Windows service called Microsoft Advanced API thirty-two,", "duration_s": 6.0, "selector": ".finding.cls-attacker_persistence:nth-of-type(1) .finding-mech"},
    {"beat": "beat3_case", "text": "set to auto-start, running a binary called msadvapi2_32.exe out of Program Files.", "duration_s": 6.0, "selector": ".finding.cls-attacker_persistence:nth-of-type(1) .finding-value"},
    {"beat": "beat3_case", "text": "That product does not exist. The agent flagged it with high confidence.", "duration_s": 4.5, "selector": ".finding.cls-attacker_persistence:nth-of-type(1) .finding-meta-row"},

    # 3b audit trail (45s, 8 phrases) - .finding-evidence-row + Evidence tab
    {"beat": "beat3_case", "text": "Every finding is a citation.", "duration_s": 3.0, "selector": ".finding.cls-attacker_persistence:nth-of-type(1) .finding-evidence-row"},
    {"beat": "beat3_case", "text": "Click the citation and you reach the actual tool output that produced it.", "duration_s": 5.5, "selector": "[data-tab='evidence']"},
    {"beat": "beat3_case", "text": "Here is the RegRipper services dump where the service was registered.", "duration_s": 5.5, "selector": ".evidence-record:nth-of-type(1)"},
    {"beat": "beat3_case", "text": "ImagePath, type, start mode, all there.", "duration_s": 4.0, "selector": None},
    {"beat": "beat3_case", "text": "Click the second citation, and you are in the memory-side pslist.", "duration_s": 5.5, "selector": ".evidence-record:nth-of-type(2)"},
    {"beat": "beat3_case", "text": "The same binary is running right now at PID 2292.", "duration_s": 4.5, "selector": None},
    {"beat": "beat3_case", "text": "Disk says it should be running. Memory confirms it is running.", "duration_s": 5.5, "selector": None},
    {"beat": "beat3_case", "text": "That is what dual-channel means here.", "duration_s": 4.0, "selector": ".channel-pill.channel-dual"},
    # 4 phrases x ~3s = 12s slack, plus 1 phrase = 33s, leaves room
    {"beat": "beat3_case", "text": "Both services installed within eighteen seconds on May eighth, 2018.", "duration_s": 5.5, "selector": None},
    {"beat": "beat3_case", "text": "One attacker installation event, not two unrelated services.", "duration_s": 4.0, "selector": None},

    # 3c critic disagreement (60s, 8 phrases) - Pipeline tab + critic events
    {"beat": "beat3_case", "text": "Now the self-correction.", "duration_s": 3.0, "selector": "[data-tab='pipeline']"},
    {"beat": "beat3_case", "text": "While the agent was producing findings,", "duration_s": 3.5, "selector": None},
    {"beat": "beat3_case", "text": "the critic noticed something in one of the tool outputs.", "duration_s": 5.0, "selector": ".pipeline-event:has-text('critic')"},
    {"beat": "beat3_case", "text": "A byte sequence in the raw registry hive contained the substring T1033,", "duration_s": 6.5, "selector": ".pipeline-event:has-text('INJECTION_QUARANTINE')"},
    {"beat": "beat3_case", "text": "matching a pattern the injection scanner uses to detect adversarial prompt content.", "duration_s": 6.5, "selector": ".pipeline-event:has-text('INJ_ATTCK_EMIT')"},
    {"beat": "beat3_case", "text": "It was random binary noise, not a real injection.", "duration_s": 4.5, "selector": None},
    {"beat": "beat3_case", "text": "But the agent did not silently dismiss it.", "duration_s": 4.0, "selector": None},
    {"beat": "beat3_case", "text": "It quarantined the tool output, escalated to human review,", "duration_s": 5.5, "selector": ".pipeline-event:has-text('escalate')"},
    {"beat": "beat3_case", "text": "and refused to act on findings that depended on it.", "duration_s": 4.5, "selector": None},
    {"beat": "beat3_case", "text": "Three findings escalated. None silently approved.", "duration_s": 4.5, "selector": None},
    {"beat": "beat3_case", "text": "That is what auditable autonomy looks like.", "duration_s": 4.0, "selector": None},
    # 11 phrases ~51s + 9s slack = 60s

    # 3d cross-host (45s, 7 phrases) - load file server + msadvapi2 finding
    {"beat": "beat3_case", "text": "One more thing.", "duration_s": 2.0, "selector": ".case-header:has-text('srl-2018-base-file')"},
    {"beat": "beat3_case", "text": "The agent ran on the file server in the same network,", "duration_s": 5.0, "selector": ".case-header:has-text('srl-2018-base-file') .case-header-name"},
    {"beat": "beat3_case", "text": "in a separate session, with no shared state.", "duration_s": 4.0, "selector": None},
    {"beat": "beat3_case", "text": "It found the same msadvapi2 kit.", "duration_s": 4.0, "selector": ".finding.cls-attacker_persistence:has-text('msadvapi2')"},
    {"beat": "beat3_case", "text": "Same fake Microsoft naming pattern, same paired thirty-two and sixty-four bit service.", "duration_s": 7.0, "selector": ".finding.cls-attacker_persistence:has-text('msadvapi2') .finding-value"},
    {"beat": "beat3_case", "text": "That cross-host signal was not engineered. The agent reached it independently on each host.", "duration_s": 8.0, "selector": None},
    {"beat": "beat3_case", "text": "The corroboration emerges from the data, not from a heuristic.", "duration_s": 5.0, "selector": None},
    # 7 phrases ~35s + 10s slack = 45s

    # ── beat4_loop (45s, 8 phrases) ────────────────────────────────────
    {"beat": "beat4_loop", "text": "And the loop closes here.", "duration_s": 3.0, "selector": "#section-rules h2"},
    {"beat": "beat4_loop", "text": "Every night, the cron at 22:30 UTC runs the agent against fresh threat intel.", "duration_s": 6.5, "selector": "#widget-input"},
    {"beat": "beat4_loop", "text": "When it misses something, a drafter agent synthesizes a candidate rule.", "duration_s": 6.0, "selector": "#widget-queued"},
    {"beat": "beat4_loop", "text": "Today, twelve rules are waiting.", "duration_s": 3.5, "selector": "#widget-queued #w-queued-num"},
    {"beat": "beat4_loop", "text": "I read one, decide it is safe, click approve.", "duration_s": 5.0, "selector": "#rule-card-apt28_cve_2026_32202_lnk_spoofing_task-c99bf8f051"},
    {"beat": "beat4_loop", "text": "The rule is now in the live agent's rule store.", "duration_s": 5.0, "selector": "#widget-live"},
    {"beat": "beat4_loop", "text": "Tomorrow night's run picks it up automatically.", "duration_s": 5.0, "selector": None},
    {"beat": "beat4_loop", "text": "This is not a demo, this is the production system.", "duration_s": 5.0, "selector": None},
    {"beat": "beat4_loop", "text": "The whole loop runs on the same dashboard you are watching.", "duration_s": 6.0, "selector": None},
    # 9 phrases ~45s

    # ── beat5_outro (15s, 4 phrases) ───────────────────────────────────
    {"beat": "beat5_outro", "text": "Sift Sentinel.", "duration_s": 2.0, "selector": ".name"},
    {"beat": "beat5_outro", "text": "Live at sentinel.sshub.dev.", "duration_s": 3.5, "selector": ".row:nth-of-type(1) .v"},
    {"beat": "beat5_outro", "text": "Code on GitHub at github.com/charanbobby/sift-sentinel.", "duration_s": 5.5, "selector": ".row:nth-of-type(2) .v"},
    {"beat": "beat5_outro", "text": "Built by Charan Bobby for the SANS Find Evil hackathon. Thanks for watching.", "duration_s": 4.0, "selector": ".row:nth-of-type(3) .v"},
]
```

## Highlight helper (scenes/_helpers.py)

```python
"""Shared helpers for per-phrase Playwright scenes."""
from __future__ import annotations

from playwright.async_api import Page


HIGHLIGHT_COLOR = "#60a5fa"  # blue, matches dashboard accent
HIGHLIGHT_WIDTH_PX = 3
HIGHLIGHT_OUTLINE_OFFSET_PX = 4


async def highlight(page: Page, selector: str) -> bool:
    """Draw an outlined box around the first element matching `selector`.
    Returns True if an element was found and styled, False otherwise.

    Selector syntax: standard CSS plus ":has-text('substring')". The
    has-text variant is resolved by walking text nodes (Playwright's own
    `:has-text` is not supported in `page.evaluate` directly).
    """
    return await page.evaluate(
        """({sel, color, width, offset}) => {
            const findEl = (s) => {
                const m = s.match(/^(.*?):has-text\\('(.+?)'\\)(.*)$/);
                if (!m) return document.querySelector(s);
                const [_, base, text, after] = m;
                const candidates = base ? document.querySelectorAll(base) : document.querySelectorAll('*');
                for (const el of candidates) {
                    if ((el.textContent || '').includes(text)) {
                        if (after) {
                            // try to apply remaining selector chain inside
                            const child = el.querySelector(after.replace(/^\\s+/, ''));
                            if (child) return child;
                        } else {
                            return el;
                        }
                    }
                }
                return null;
            };
            const el = findEl(sel);
            if (!el) return false;
            el.scrollIntoView({behavior: 'smooth', block: 'center'});
            el.dataset._origCss = el.style.cssText;
            el.style.outline = `${width}px solid ${color}`;
            el.style.outlineOffset = `${offset}px`;
            el.style.borderRadius = '4px';
            el.style.transition = 'outline 0.2s ease-in';
            return true;
        }""",
        {"sel": selector, "color": HIGHLIGHT_COLOR, "width": HIGHLIGHT_WIDTH_PX, "offset": HIGHLIGHT_OUTLINE_OFFSET_PX},
    )


async def unhighlight(page: Page, selector: str) -> None:
    """Remove the outline from a previously highlighted element. Safe to
    call even if the highlight did not land (no-op).
    """
    await page.evaluate(
        """(sel) => {
            const findEl = (s) => {
                const m = s.match(/^(.*?):has-text\\('(.+?)'\\)(.*)$/);
                if (!m) return document.querySelector(s);
                const [_, base, text, after] = m;
                const candidates = base ? document.querySelectorAll(base) : document.querySelectorAll('*');
                for (const el of candidates) {
                    if ((el.textContent || '').includes(text)) {
                        if (after) {
                            const child = el.querySelector(after.replace(/^\\s+/, ''));
                            if (child) return child;
                        } else {
                            return el;
                        }
                    }
                }
                return null;
            };
            const el = findEl(sel);
            if (!el) return;
            const orig = el.dataset._origCss;
            if (orig !== undefined) {
                el.style.cssText = orig;
                delete el.dataset._origCss;
            } else {
                el.style.outline = '';
                el.style.outlineOffset = '';
            }
        }""",
        selector,
    )
```

## Scene script pattern

Each scene becomes a phrase iterator:

```python
# scripts/demo_video/scenes/beat2_architecture.py (REWRITE)
import asyncio
from playwright.async_api import Page
from ..config import SITE_URL
from ..phrases import PHRASES
from ._helpers import highlight, unhighlight


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/site/architecture.html")
    await page.wait_for_load_state("domcontentloaded")
    await asyncio.sleep(0.5)
    for phrase in [p for p in PHRASES if p["beat"] == "beat2_architecture"]:
        if phrase["selector"]:
            await highlight(page, phrase["selector"])
        await asyncio.sleep(phrase["duration_s"])
        if phrase["selector"]:
            await unhighlight(page, phrase["selector"])
```

The same pattern in `beat1_open.py`, `beat3_case.py`, `beat4_loop.py`, `beat5_outro.py`. Each scene only differs by:
1. Initial `goto` target.
2. SPA setup steps (e.g. beat 3 calls `toggleCase` + `loadRun` between phrases at certain points; beat 4 clicks Approve at a certain phrase).

For SPA-state-changing phrases, the scene script intercepts the iteration to inject the action AT the phrase boundary. Pattern for beat 3:

```python
async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/viewer/")
    await page.wait_for_load_state("domcontentloaded")
    await page.wait_for_function("() => typeof toggleCase === 'function'")

    for phrase in [p for p in PHRASES if p["beat"] == "beat3_case"]:
        # SPA state intercepts BEFORE highlighting
        if phrase["text"].startswith("The case:"):
            await page.evaluate("toggleCase('srl-2018-base-rd-02-dual')")
            await asyncio.sleep(0.5)
            await page.evaluate("loadRun('srl-2018-base-rd-02-dual', 'srl-2018-base-rd-02-dual-002')")
            await page.wait_for_function("() => document.querySelectorAll('.finding').length >= 2")
        elif phrase["text"].startswith("Click the citation"):
            await page.evaluate("document.querySelector('[data-tab=\"evidence\"]')?.click()")
            await asyncio.sleep(0.4)
        elif phrase["text"].startswith("Now the self-correction"):
            await page.evaluate("document.querySelector('[data-tab=\"pipeline\"]')?.click()")
            await asyncio.sleep(0.4)
        elif phrase["text"].startswith("One more thing"):
            await page.evaluate("toggleCase('srl-2018-base-file')")
            await asyncio.sleep(0.5)
            await page.evaluate("loadRun('srl-2018-base-file', 'srl-2018-base-file-005')")
            await page.wait_for_function("() => document.querySelectorAll('.finding').length >= 1", timeout=10000)

        if phrase["selector"]:
            await highlight(page, phrase["selector"])
        await asyncio.sleep(phrase["duration_s"])
        if phrase["selector"]:
            await unhighlight(page, phrase["selector"])
```

For beat 4, intercept at the Approve phrase to call `openApproveModal` + `confirmPromote`.

## Captions module rewrite

```python
# scripts/demo_video/captions.py (REWRITE)
from .phrases import PHRASES

# Beat order for SRT timing.
BEAT_ORDER = ["beat1_open", "beat2_architecture", "beat3_case", "beat4_loop", "beat5_outro"]

def build_srt(lead_in_s: float = 1.5) -> str:
    cues = []
    cumulative = 0.0
    for beat in BEAT_ORDER:
        beat_phrases = [p for p in PHRASES if p["beat"] == beat]
        is_first_phrase_of_video = (beat == BEAT_ORDER[0])
        for i, phrase in enumerate(beat_phrases):
            t0 = cumulative + (lead_in_s if (is_first_phrase_of_video and i == 0) else 0)
            t1 = cumulative + phrase["duration_s"] - 0.15
            cues.append((t0, t1, phrase["text"]))
            cumulative += phrase["duration_s"]
    return _srt(cues)
```

(Removed: `_split_into_lines`, the BEATS list, the cumulative duration logic. All replaced by phrase iteration.)

## Voice generation rewrite

```python
# scripts/demo_video/voice_gen.py (PATCH)
from .phrases import PHRASES

BEAT_ORDER = ["beat1_open", "beat2_architecture", "beat3_case", "beat4_loop", "beat5_outro"]

def voiceover_for_beat(beat_name: str) -> str:
    """Concatenate all phrases in this beat into the voice line."""
    return " ".join(p["text"] for p in PHRASES if p["beat"] == beat_name)

# main() iterates BEAT_ORDER (not the old BEATS list), generating one MP3 per beat.
```

## Files affected

| File | Change |
|---|---|
| `scripts/demo_video/phrases.py` | NEW: PHRASES list |
| `scripts/demo_video/captions.py` | REWRITE: derive cues from PHRASES |
| `scripts/demo_video/voice_gen.py` | PATCH: derive voiceover from PHRASES per beat |
| `scripts/demo_video/scenes/_helpers.py` | NEW: highlight() + unhighlight() |
| `scripts/demo_video/scenes/beat1_open.py` | REWRITE: phrase iterator |
| `scripts/demo_video/scenes/beat2_architecture.py` | REWRITE: phrase iterator + initial scroll-to "Five trust controls" |
| `scripts/demo_video/scenes/beat3_case.py` | REWRITE: phrase iterator + SPA state intercepts |
| `scripts/demo_video/scenes/beat4_loop.py` | REWRITE: phrase iterator + Approve intercept |
| `scripts/demo_video/scenes/beat5_outro.py` | REWRITE: phrase iterator |
| `scripts/demo_video/burn_captions.sh` | NO CHANGE (already pinned PlayResX/Y) |
| `scripts/demo_video/assemble_silent.sh` | NO CHANGE |
| `scripts/demo_video/assemble_final.sh` | NO CHANGE |
| `scripts/demo_video/Dockerfile` | NO CHANGE |
| `tests/test_demo_video_captions.py` | UPDATE: replace BEATS-based assertions with PHRASES-based ones |
| `D:/Python Applications/Sri Studio Helper/SKILL.md` | UPDATE later: capture per-phrase pattern as a documented best practice |

## Selector pre-flight

Before any re-recording, probe each unique selector in the PHRASES list against the live site to confirm it resolves. Add `scripts/demo_video/probes/check_phrase_selectors.py` that walks PHRASES and reports any `selector` that does NOT find an element. Fix selectors before recording so we do not waste recording time on misses.

## Out of scope

- Animated arrows, label callouts, spotlight overlays. Outlined box only.
- Per-word sync (sub-second). Per-phrase is the granularity.
- Auto-derived phrase durations from voice timing. Durations are HARDCODED upfront so captions and scenes line up; voice generation is constrained by them.
- Re-recording beats 1, 4, 5 is optional (current versions are passable). Beats 2 and 3 must be re-recorded with the new phrase pattern.
- Modifying the Sri Studio Helper standalone repo to use the phrase pattern. That's a separate cycle after Find Evil ships.

## Open questions

None. Phrase model + outlined-box annotation + SPA-state intercepts in scenes covers the visual-to-voice match Charan asked for. Spec ready for review; on approval, writing-plans skill generates the implementation plan.
