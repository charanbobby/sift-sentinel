# Phrase-Driven Demo Video Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewire the SANS Find Evil demo video pipeline so every voiceover phrase has a matching visual highlight on the named DOM element, with a single PHRASES list as the source of truth for captions, voice, and scene timing.

**Architecture:** Replace per-beat scene scripts with phrase iterators. Each phrase has `{beat, text, duration_s, selector}`; scene scripts walk PHRASES for their beat, draw an outlined box on `selector` while voice would speak `text`, sleep `duration_s`, remove highlight. Captions and voice generation derive from the same list. Spec at `docs/superpowers/specs/2026-05-09-phrase-driven-demo-video-design.md` (commit `6882168`).

**Tech Stack:** Existing Find Evil demo_video pipeline (Playwright + ffmpeg + ElevenLabs), `demo-video:latest` Docker image already built. No new dependencies.

---

## File structure

| File | Role | Change |
|---|---|---|
| `scripts/demo_video/phrases.py` | Source of truth: PHRASES list | NEW |
| `scripts/demo_video/scenes/_helpers.py` | highlight() / unhighlight() drawing the outlined box via page.evaluate | NEW |
| `scripts/demo_video/captions.py` | Build SRT from PHRASES | REWRITE |
| `scripts/demo_video/voice_gen.py` | Build voiceover per beat from PHRASES | PATCH |
| `scripts/demo_video/scenes/beat1_open.py` | phrase iterator | REWRITE |
| `scripts/demo_video/scenes/beat2_architecture.py` | phrase iterator | REWRITE |
| `scripts/demo_video/scenes/beat3_case.py` | phrase iterator + SPA state intercepts | REWRITE |
| `scripts/demo_video/scenes/beat4_loop.py` | phrase iterator + Approve intercept | REWRITE |
| `scripts/demo_video/scenes/beat5_outro.py` | phrase iterator | REWRITE |
| `scripts/demo_video/probes/check_phrase_selectors.py` | Resolve every PHRASES selector against live pages | NEW |
| `tests/test_demo_video_captions.py` | Replace BEATS-based tests with PHRASES-based ones | REWRITE |

---

## Task 1: phrases.py source of truth

**Files:**
- Create: `scripts/demo_video/phrases.py`

- [ ] **Step 1: Write phrases.py with the locked PHRASES list**

Use the PHRASES list from the spec verbatim, with two adjustments (the spec calls these out as implementation detail):

1. **beat 3 phrase durations must sum to 180s.** Spec total is 163.5s. Add the missing 16.5s by extending these specific phrases by these specific deltas:
   - 3a "looking at both the disk image and a memory snapshot in the same run." 5.0 -> 6.0 (+1.0)
   - 3a "set to auto-start, running a binary called msadvapi2_32.exe out of Program Files." 6.0 -> 7.0 (+1.0)
   - 3b "Click the citation and you reach the actual tool output that produced it." 5.5 -> 7.0 (+1.5)
   - 3b "Here is the RegRipper services dump where the service was registered." 5.5 -> 7.0 (+1.5)
   - 3c "the critic noticed something in one of the tool outputs." 5.0 -> 7.0 (+2.0)
   - 3c "matching a pattern the injection scanner uses to detect adversarial prompt content." 6.5 -> 8.5 (+2.0)
   - 3c "It quarantined the tool output, escalated to human review," 5.5 -> 7.5 (+2.0)
   - 3d "in a separate session, with no shared state." 4.0 -> 6.0 (+2.0)
   - 3d "Same fake Microsoft naming pattern, same paired thirty-two and sixty-four bit service." 7.0 -> 9.5 (+2.5)
   - Total added: 16.5. Beat 3 now sums to 180.

2. Keep all other beats as in spec (they already sum correctly: beat1=15, beat2=45, beat4=45, beat5=15).

```python
"""Phrase-level source of truth for the demo video.

Every phrase carries the text the narrator says, how long it takes to say it,
and the DOM element on screen during that phrase. Captions, voice generation,
and scene scripts all derive from this single list.

Spec: docs/superpowers/specs/2026-05-09-phrase-driven-demo-video-design.md
"""
from __future__ import annotations

PHRASES: list[dict] = [
    # ── beat1_open (15s, 3 phrases) ──────────────────────────────────────
    {"beat": "beat1_open", "text": "Last night, an AI agent I built found a fake Microsoft service hiding on a real Windows server.", "duration_s": 6.0, "selector": None},
    {"beat": "beat1_open", "text": "Then it caught itself making a mistake on the next finding.", "duration_s": 4.5, "selector": None},
    {"beat": "beat1_open", "text": "Then it drafted a rule so it gets the next case right. Here is how.", "duration_s": 4.5, "selector": None},

    # ── beat2_architecture (45s, 9 phrases) ──────────────────────────────
    {"beat": "beat2_architecture", "text": "Sentinel runs the autonomous incident response loop", "duration_s": 4.5, "selector": "h2:has-text('Five trust controls')"},
    {"beat": "beat2_architecture", "text": "with three architectural guardrails, not just prompt promises.", "duration_s": 4.5, "selector": None},
    {"beat": "beat2_architecture", "text": "First: every tool call crosses a capability-token boundary at the MCP server,", "duration_s": 6.0, "selector": "h3:has-text('Execution boundary')"},
    {"beat": "beat2_architecture", "text": "scoped to the case ID and the allowed paths.", "duration_s": 4.0, "selector": "h2:has-text('Execution boundary deep dive')"},
    {"beat": "beat2_architecture", "text": "Second: an injection scanner sits in the Critic", "duration_s": 5.0, "selector": "h3:has-text('Defender AI integrity')"},
    {"beat": "beat2_architecture", "text": "and quarantines tool output that looks adversarial.", "duration_s": 4.5, "selector": "h2:has-text('Defender AI integrity deep dive')"},
    {"beat": "beat2_architecture", "text": "Third: every step of every run is hash-chained into an integrity ledger,", "duration_s": 5.5, "selector": "h2:has-text('Integrity deep dive')"},
    {"beat": "beat2_architecture", "text": "so a finding can be traced back to the exact tool execution that produced it.", "duration_s": 5.5, "selector": ".external-ledger"},
    {"beat": "beat2_architecture", "text": "The critic and the learn nodes are where the autonomy lives.", "duration_s": 5.5, "selector": "h3:has-text('Deterministic checks')"},

    # ── beat3_case (180s, 33 phrases across 4 sub-beats) ────────────────
    # 3a findings overview (32s)
    {"beat": "beat3_case", "text": "The case: a Windows server from a 2018 enterprise compromise.", "duration_s": 5.0, "selector": ".case-header:has-text('srl-2018-base-rd-02-dual')"},
    {"beat": "beat3_case", "text": "The agent ran in dual-channel mode,", "duration_s": 3.5, "selector": ".channel-pill.channel-dual"},
    {"beat": "beat3_case", "text": "looking at both the disk image and a memory snapshot in the same run.", "duration_s": 6.0, "selector": None},
    {"beat": "beat3_case", "text": "The first finding is a Windows service called Microsoft Advanced API thirty-two,", "duration_s": 6.0, "selector": ".finding.cls-attacker_persistence:nth-of-type(1) .finding-mech"},
    {"beat": "beat3_case", "text": "set to auto-start, running a binary called msadvapi2_32.exe out of Program Files.", "duration_s": 7.0, "selector": ".finding.cls-attacker_persistence:nth-of-type(1) .finding-value"},
    {"beat": "beat3_case", "text": "That product does not exist. The agent flagged it with high confidence.", "duration_s": 4.5, "selector": ".finding.cls-attacker_persistence:nth-of-type(1) .finding-meta-row"},

    # 3b audit trail (50s)
    {"beat": "beat3_case", "text": "Every finding is a citation.", "duration_s": 3.0, "selector": ".finding.cls-attacker_persistence:nth-of-type(1) .finding-evidence-row"},
    {"beat": "beat3_case", "text": "Click the citation and you reach the actual tool output that produced it.", "duration_s": 7.0, "selector": "[data-tab='evidence']"},
    {"beat": "beat3_case", "text": "Here is the RegRipper services dump where the service was registered.", "duration_s": 7.0, "selector": ".evidence-record:nth-of-type(1)"},
    {"beat": "beat3_case", "text": "ImagePath, type, start mode, all there.", "duration_s": 4.0, "selector": None},
    {"beat": "beat3_case", "text": "Click the second citation, and you are in the memory-side pslist.", "duration_s": 5.5, "selector": ".evidence-record:nth-of-type(2)"},
    {"beat": "beat3_case", "text": "The same binary is running right now at PID 2292.", "duration_s": 4.5, "selector": None},
    {"beat": "beat3_case", "text": "Disk says it should be running. Memory confirms it is running.", "duration_s": 5.5, "selector": None},
    {"beat": "beat3_case", "text": "That is what dual-channel means here.", "duration_s": 4.0, "selector": ".channel-pill.channel-dual"},
    {"beat": "beat3_case", "text": "Both services installed within eighteen seconds on May eighth, 2018.", "duration_s": 5.5, "selector": None},
    {"beat": "beat3_case", "text": "One attacker installation event, not two unrelated services.", "duration_s": 4.0, "selector": None},

    # 3c critic disagreement (57.5s)
    {"beat": "beat3_case", "text": "Now the self-correction.", "duration_s": 3.0, "selector": "[data-tab='pipeline']"},
    {"beat": "beat3_case", "text": "While the agent was producing findings,", "duration_s": 3.5, "selector": None},
    {"beat": "beat3_case", "text": "the critic noticed something in one of the tool outputs.", "duration_s": 7.0, "selector": ".pipeline-event:has-text('critic')"},
    {"beat": "beat3_case", "text": "A byte sequence in the raw registry hive contained the substring T1033,", "duration_s": 6.5, "selector": ".pipeline-event:has-text('INJECTION_QUARANTINE')"},
    {"beat": "beat3_case", "text": "matching a pattern the injection scanner uses to detect adversarial prompt content.", "duration_s": 8.5, "selector": ".pipeline-event:has-text('INJ_ATTCK_EMIT')"},
    {"beat": "beat3_case", "text": "It was random binary noise, not a real injection.", "duration_s": 4.5, "selector": None},
    {"beat": "beat3_case", "text": "But the agent did not silently dismiss it.", "duration_s": 4.0, "selector": None},
    {"beat": "beat3_case", "text": "It quarantined the tool output, escalated to human review,", "duration_s": 7.5, "selector": ".pipeline-event:has-text('escalate')"},
    {"beat": "beat3_case", "text": "and refused to act on findings that depended on it.", "duration_s": 4.5, "selector": None},
    {"beat": "beat3_case", "text": "Three findings escalated. None silently approved.", "duration_s": 4.5, "selector": None},
    {"beat": "beat3_case", "text": "That is what auditable autonomy looks like.", "duration_s": 4.0, "selector": None},

    # 3d cross-host (40.5s)
    {"beat": "beat3_case", "text": "One more thing.", "duration_s": 2.0, "selector": ".case-header:has-text('srl-2018-base-file')"},
    {"beat": "beat3_case", "text": "The agent ran on the file server in the same network,", "duration_s": 5.0, "selector": ".case-header:has-text('srl-2018-base-file') .case-header-name"},
    {"beat": "beat3_case", "text": "in a separate session, with no shared state.", "duration_s": 6.0, "selector": None},
    {"beat": "beat3_case", "text": "It found the same msadvapi2 kit.", "duration_s": 4.0, "selector": ".finding.cls-attacker_persistence:has-text('msadvapi2')"},
    {"beat": "beat3_case", "text": "Same fake Microsoft naming pattern, same paired thirty-two and sixty-four bit service.", "duration_s": 9.5, "selector": ".finding.cls-attacker_persistence:has-text('msadvapi2') .finding-value"},
    {"beat": "beat3_case", "text": "That cross-host signal was not engineered. The agent reached it independently on each host.", "duration_s": 8.0, "selector": None},
    {"beat": "beat3_case", "text": "The corroboration emerges from the data, not from a heuristic.", "duration_s": 5.0, "selector": None},

    # ── beat4_loop (45s, 9 phrases) ──────────────────────────────────────
    {"beat": "beat4_loop", "text": "And the loop closes here.", "duration_s": 3.0, "selector": "#section-rules h2"},
    {"beat": "beat4_loop", "text": "Every night, the cron at 22:30 UTC runs the agent against fresh threat intel.", "duration_s": 6.5, "selector": "#widget-input"},
    {"beat": "beat4_loop", "text": "When it misses something, a drafter agent synthesizes a candidate rule.", "duration_s": 6.0, "selector": "#widget-queued"},
    {"beat": "beat4_loop", "text": "Today, twelve rules are waiting.", "duration_s": 3.5, "selector": "#widget-queued #w-queued-num"},
    {"beat": "beat4_loop", "text": "I read one, decide it is safe, click approve.", "duration_s": 5.0, "selector": "#rule-card-apt28_cve_2026_32202_lnk_spoofing_task-c99bf8f051"},
    {"beat": "beat4_loop", "text": "The rule is now in the live agent's rule store.", "duration_s": 5.0, "selector": "#widget-live"},
    {"beat": "beat4_loop", "text": "Tomorrow night's run picks it up automatically.", "duration_s": 5.0, "selector": None},
    {"beat": "beat4_loop", "text": "This is not a demo, this is the production system.", "duration_s": 5.0, "selector": None},
    {"beat": "beat4_loop", "text": "The whole loop runs on the same dashboard you are watching.", "duration_s": 6.0, "selector": None},

    # ── beat5_outro (15s, 4 phrases) ─────────────────────────────────────
    {"beat": "beat5_outro", "text": "Sift Sentinel.", "duration_s": 2.0, "selector": ".name"},
    {"beat": "beat5_outro", "text": "Live at sentinel.sshub.dev.", "duration_s": 3.5, "selector": ".row:nth-of-type(1) .v"},
    {"beat": "beat5_outro", "text": "Code on GitHub at github.com/charanbobby/sift-sentinel.", "duration_s": 5.5, "selector": ".row:nth-of-type(2) .v"},
    {"beat": "beat5_outro", "text": "Built by Charan Bobby for the SANS Find Evil hackathon. Thanks for watching.", "duration_s": 4.0, "selector": ".row:nth-of-type(3) .v"},
]


BEAT_ORDER = ["beat1_open", "beat2_architecture", "beat3_case", "beat4_loop", "beat5_outro"]


def phrases_for(beat: str) -> list[dict]:
    """All phrases for a single beat, in order."""
    return [p for p in PHRASES if p["beat"] == beat]


def beat_total_seconds(beat: str) -> float:
    return sum(p["duration_s"] for p in phrases_for(beat))


# Sanity asserts at import time so a broken edit fails fast.
assert sum(p["duration_s"] for p in PHRASES) == 300.0, \
    f"PHRASES must total 300s, got {sum(p['duration_s'] for p in PHRASES)}"
for _b in BEAT_ORDER:
    _expected = {"beat1_open": 15, "beat2_architecture": 45, "beat3_case": 180, "beat4_loop": 45, "beat5_outro": 15}[_b]
    _actual = beat_total_seconds(_b)
    assert _actual == _expected, f"beat {_b} should sum to {_expected}s, got {_actual}"
```

- [ ] **Step 2: Probe the import + asserts pass**

```
MSYS_NO_PATHCONV=1 docker run --rm -v "/d/Python Applications/Find Evil - Hackathon:/work" -w /work demo-video:latest python -c "
import sys; sys.path.insert(0, '/work/scripts')
from demo_video.phrases import PHRASES, BEAT_ORDER, beat_total_seconds
print('phrases:', len(PHRASES))
for b in BEAT_ORDER:
    print(f'  {b}: {beat_total_seconds(b)}s')
"
```

Expected output:
```
phrases: 58
  beat1_open: 15.0s
  beat2_architecture: 45.0s
  beat3_case: 180.0s
  beat4_loop: 45.0s
  beat5_outro: 15.0s
```

- [ ] **Step 3: Commit**

```bash
cd "D:/Python Applications/Find Evil - Hackathon"
git add scripts/demo_video/phrases.py
git commit -m "demo_video: phrases.py source of truth for voice + captions + scenes"
```

---

## Task 2: scenes/_helpers.py highlight + unhighlight

**Files:**
- Create: `scripts/demo_video/scenes/_helpers.py`

- [ ] **Step 1: Write the helpers module**

```python
"""Shared helpers for per-phrase Playwright scenes.

highlight() draws an outlined box around the first element matching `selector`.
unhighlight() removes the box. Both are no-ops if the selector does not match.
"""
from __future__ import annotations

from playwright.async_api import Page


HIGHLIGHT_COLOR = "#60a5fa"  # blue, matches dashboard accent
HIGHLIGHT_WIDTH_PX = 3
HIGHLIGHT_OUTLINE_OFFSET_PX = 4


_FIND_EL_JS = """
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
"""


async def highlight(page: Page, selector: str) -> bool:
    """Draw an outlined box around the first element matching `selector`.
    Returns True if found and styled, False otherwise. Does not raise.
    """
    return await page.evaluate(
        _FIND_EL_JS + """({sel, color, width, offset}) => {
            const el = findEl(sel);
            if (!el) return false;
            el.scrollIntoView({behavior: 'smooth', block: 'center'});
            el.dataset._origCss = el.style.cssText;
            el.style.outline = width + 'px solid ' + color;
            el.style.outlineOffset = offset + 'px';
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
        _FIND_EL_JS + """(sel) => {
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

- [ ] **Step 2: Syntax check**

```
MSYS_NO_PATHCONV=1 docker exec sift-sentinel python -c "import ast; ast.parse(open('/workspace/../scripts/demo_video/scenes/_helpers.py').read())"
```

Expected: no output (means parsed cleanly). If sift-sentinel does not see the path, copy via docker cp first.

- [ ] **Step 3: Commit**

```bash
cd "D:/Python Applications/Find Evil - Hackathon"
git add scripts/demo_video/scenes/_helpers.py
git commit -m "demo_video: scenes/_helpers.py with highlight/unhighlight via page.evaluate"
```

---

## Task 3: Rewrite captions.py to derive from PHRASES (TDD)

**Files:**
- Modify: `scripts/demo_video/captions.py`
- Modify: `tests/test_demo_video_captions.py`

- [ ] **Step 1: Update tests first (TDD)**

Replace `tests/test_demo_video_captions.py` entirely with:

```python
"""Tests for scripts/demo_video/captions.py SRT generator (PHRASES-based)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from demo_video.captions import build_srt
from demo_video.phrases import PHRASES, BEAT_ORDER, beat_total_seconds


def test_phrases_total_300_seconds():
    assert sum(p["duration_s"] for p in PHRASES) == 300.0


def test_each_beat_sums_to_budget():
    expected = {"beat1_open": 15, "beat2_architecture": 45, "beat3_case": 180, "beat4_loop": 45, "beat5_outro": 15}
    for b in BEAT_ORDER:
        assert beat_total_seconds(b) == expected[b], f"beat {b} mismatch"


def test_build_srt_one_cue_per_phrase():
    srt = build_srt()
    cue_count = srt.count(" --> ")
    assert cue_count == len(PHRASES), f"expected {len(PHRASES)} cues, got {cue_count}"


def test_build_srt_first_cue_has_lead_in():
    srt = build_srt(lead_in_s=1.5)
    # First cue should start at 00:00:01,500
    assert "00:00:01,500" in srt or "00:00:1,500" in srt or "1\n00:00:01" in srt, \
        f"first cue should have ~1.5s lead-in, srt head: {srt[:200]!r}"


def test_each_phrase_has_text():
    for p in PHRASES:
        assert p["text"].strip(), f"phrase missing text in beat {p['beat']}"
```

- [ ] **Step 2: Run tests, expect FAIL**

```
MSYS_NO_PATHCONV=1 docker exec sift-sentinel /workspace/.venv/bin/pytest /workspace/../tests/test_demo_video_captions.py -v
```

Expected: ImportError on `from demo_video.phrases import ...` (Task 1 already added phrases.py, so this should actually pass that import). The cue-count test will fail because old captions.py builds different cue counts.

- [ ] **Step 3: Rewrite captions.py**

```python
"""Build the SRT caption file from the phrase list (phrases.py).

Each phrase becomes one SRT cue. The first cue gets a small lead-in so the
cold-open frame breathes before the first caption appears.

Source of truth: scripts/demo_video/phrases.py
"""
from __future__ import annotations

from .phrases import PHRASES, BEAT_ORDER


def _hms(seconds: float) -> str:
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    ms = int(round((seconds - int(seconds)) * 1000))
    if ms == 1000:
        ms = 0
        s += 1
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"


def build_srt(lead_in_s: float = 1.5, gap_s: float = 0.15) -> str:
    """Build the full SRT covering every phrase. Each cue starts at the
    cumulative beat-relative offset and ends `gap_s` seconds before the
    next phrase begins (so cues do not visually overlap).

    The very first phrase of the video starts at `lead_in_s` so the cold
    open has a brief silent moment.
    """
    cues: list[tuple[float, float, str]] = []
    cumulative = 0.0
    is_first = True
    for beat in BEAT_ORDER:
        for p in (q for q in PHRASES if q["beat"] == beat):
            t0 = cumulative + (lead_in_s if is_first else 0)
            t1 = cumulative + p["duration_s"] - gap_s
            cues.append((t0, t1, p["text"]))
            cumulative += p["duration_s"]
            is_first = False
    out_parts: list[str] = []
    for idx, (t0, t1, text) in enumerate(cues, start=1):
        out_parts.append(f"{idx}\n{_hms(t0)} --> {_hms(t1)}\n{text}\n")
    return "\n".join(out_parts)


if __name__ == "__main__":
    from .config import OUT_DIR
    srt_path = OUT_DIR / "captions.srt"
    srt_path.write_text(build_srt(), encoding="utf-8")
    print(f"wrote {srt_path}")
```

- [ ] **Step 4: Run tests again**

```
MSYS_NO_PATHCONV=1 docker exec sift-sentinel /workspace/.venv/bin/pytest /workspace/../tests/test_demo_video_captions.py -v
```

Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
cd "D:/Python Applications/Find Evil - Hackathon"
git add scripts/demo_video/captions.py tests/test_demo_video_captions.py
git commit -m "demo_video: captions.py derives one cue per phrase from PHRASES"
```

---

## Task 4: Patch voice_gen.py to use PHRASES per beat

**Files:**
- Modify: `scripts/demo_video/voice_gen.py`

- [ ] **Step 1: Replace the BEATS import + per-beat lookup**

Find the line `from .captions import BEATS` and replace the import + usage with:

```python
from .phrases import PHRASES, BEAT_ORDER


def _voiceover_for_beat(beat_name: str) -> str:
    """Concatenate all phrases in this beat into the voice line."""
    return " ".join(p["text"] for p in PHRASES if p["beat"] == beat_name)
```

Then in `main()`, replace the `selected = [b for b in BEATS if (args.beat is None or b["name"] == args.beat)]` and the loop body so it iterates `BEAT_ORDER`:

```python
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("beat", nargs="?", help="beat name; omit to generate all")
    args = ap.parse_args()
    api_key = os.environ.get("ELEVENLABS_API_KEY")
    voice_id = os.environ.get("ELEVENLABS_VOICE_ID")
    if not api_key or not voice_id:
        print("ELEVENLABS_API_KEY and ELEVENLABS_VOICE_ID env vars required", file=sys.stderr)
        return 2
    selected = [b for b in BEAT_ORDER if (args.beat is None or b == args.beat)]
    if not selected:
        print(f"unknown beat {args.beat!r}", file=sys.stderr)
        return 1
    for beat_name in selected:
        out_path = OUT_DIR / f"voice_{beat_name}.mp3"
        if out_path.exists():
            print(f"skip {beat_name} (already exists at {out_path}); delete to regenerate")
            continue
        text = _voiceover_for_beat(beat_name)
        print(f"generating {beat_name} -> {out_path} ({len(text)} chars)")
        _generate_one(api_key, voice_id, text, out_path)
        print(f"  wrote {out_path.stat().st_size} bytes")
    return 0
```

Keep `_generate_one()` and `API_URL_TEMPLATE` unchanged.

- [ ] **Step 2: Probe import**

```
MSYS_NO_PATHCONV=1 docker exec sift-sentinel python -c "
import sys; sys.path.insert(0, '/workspace/../scripts')
from demo_video.voice_gen import _voiceover_for_beat
print(repr(_voiceover_for_beat('beat1_open'))[:120])
"
```

Expected: prints the concatenated beat 1 voiceover starting with "Last night,...".

- [ ] **Step 3: Commit**

```bash
cd "D:/Python Applications/Find Evil - Hackathon"
git add scripts/demo_video/voice_gen.py
git commit -m "demo_video: voice_gen.py derives voiceover from PHRASES per beat"
```

---

## Task 5: Rewrite scenes/beat1_open.py

**Files:**
- Modify: `scripts/demo_video/scenes/beat1_open.py`

- [ ] **Step 1: Replace the file**

```python
"""Beat 1: cold open. 15s. Static dashboard hero hold; 3 phrases, no
selectors (purely a visual hook, narrator carries the story).
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL
from ..phrases import phrases_for
from ._helpers import highlight, unhighlight


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/site/dashboard.html?cb=demo")
    await page.wait_for_load_state("networkidle")
    await page.wait_for_function(
        "() => document.getElementById('w-queued-num')?.textContent !== ','"
    )
    for phrase in phrases_for("beat1_open"):
        if phrase["selector"]:
            await highlight(page, phrase["selector"])
        await asyncio.sleep(phrase["duration_s"])
        if phrase["selector"]:
            await unhighlight(page, phrase["selector"])
```

- [ ] **Step 2: Syntax check + commit**

```
MSYS_NO_PATHCONV=1 docker exec sift-sentinel python -c "import ast; ast.parse(open('/workspace/../scripts/demo_video/scenes/beat1_open.py').read())"
git add scripts/demo_video/scenes/beat1_open.py
git commit -m "demo_video: beat 1 phrase iterator"
```

---

## Task 6: Rewrite scenes/beat2_architecture.py

**Files:**
- Modify: `scripts/demo_video/scenes/beat2_architecture.py`

- [ ] **Step 1: Replace the file**

```python
"""Beat 2: architecture page. 45s, 9 phrases, each pointing at a named
"Five trust controls" / "deep dive" element on /site/architecture.html.
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL
from ..phrases import phrases_for
from ._helpers import highlight, unhighlight


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/site/architecture.html")
    await page.wait_for_load_state("domcontentloaded")
    # Land on the "Five trust controls" section to set the visual context.
    await page.evaluate(
        """() => {
            const h2 = Array.from(document.querySelectorAll('h2'))
                .find(h => h.textContent.includes('Five trust controls'));
            if (h2) h2.scrollIntoView({behavior: 'instant', block: 'start'});
        }"""
    )
    await asyncio.sleep(0.4)
    for phrase in phrases_for("beat2_architecture"):
        if phrase["selector"]:
            await highlight(page, phrase["selector"])
        await asyncio.sleep(phrase["duration_s"])
        if phrase["selector"]:
            await unhighlight(page, phrase["selector"])
```

- [ ] **Step 2: Commit**

```
git add scripts/demo_video/scenes/beat2_architecture.py
git commit -m "demo_video: beat 2 phrase iterator pointing at named guardrails"
```

---

## Task 7: Rewrite scenes/beat3_case.py with SPA intercepts

**Files:**
- Modify: `scripts/demo_video/scenes/beat3_case.py`

- [ ] **Step 1: Replace the file**

```python
"""Beat 3: case walkthrough. 180s, 33 phrases.

The viewer is a single-page app driven by toggleCase() and loadRun(). At
specific phrase boundaries the scene calls those functions (or clicks tabs)
to advance the SPA state, then the highlight on the next phrase points at
the newly-rendered element.
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL, CASE_ID, RUN_ID, SECOND_CASE_ID, SECOND_RUN_ID
from ..phrases import phrases_for
from ._helpers import highlight, unhighlight


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/viewer/")
    await page.wait_for_load_state("domcontentloaded")
    await page.wait_for_function(
        "() => typeof toggleCase === 'function' && typeof loadRun === 'function'"
    )
    await asyncio.sleep(0.4)

    for phrase in phrases_for("beat3_case"):
        text = phrase["text"]

        # SPA state intercepts BEFORE drawing the highlight on this phrase.
        if text.startswith("The case:"):
            await page.evaluate(f"toggleCase('{CASE_ID}')")
            await asyncio.sleep(0.3)
            await page.evaluate(f"loadRun('{CASE_ID}', '{RUN_ID}')")
            try:
                await page.wait_for_function(
                    "() => document.querySelectorAll('.finding').length >= 2",
                    timeout=10000,
                )
            except Exception:
                pass
            await asyncio.sleep(0.3)
        elif text.startswith("Click the citation"):
            await page.evaluate('document.querySelector(\'[data-tab="evidence"]\')?.click()')
            await asyncio.sleep(0.3)
        elif text.startswith("Now the self-correction"):
            await page.evaluate('document.querySelector(\'[data-tab="pipeline"]\')?.click()')
            await asyncio.sleep(0.3)
        elif text.startswith("One more thing"):
            # Switch back to Findings tab so the next loadRun lands clean.
            await page.evaluate('document.querySelector(\'[data-tab="findings"]\')?.click()')
            await asyncio.sleep(0.2)
            await page.evaluate(f"toggleCase('{SECOND_CASE_ID}')")
            await asyncio.sleep(0.3)
            await page.evaluate(f"loadRun('{SECOND_CASE_ID}', '{SECOND_RUN_ID}')")
            try:
                await page.wait_for_function(
                    "() => document.querySelectorAll('.finding').length >= 1",
                    timeout=10000,
                )
            except Exception:
                pass
            await asyncio.sleep(0.3)

        if phrase["selector"]:
            await highlight(page, phrase["selector"])
        await asyncio.sleep(phrase["duration_s"])
        if phrase["selector"]:
            await unhighlight(page, phrase["selector"])
```

- [ ] **Step 2: Commit**

```
git add scripts/demo_video/scenes/beat3_case.py
git commit -m "demo_video: beat 3 phrase iterator with SPA state intercepts"
```

---

## Task 8: Rewrite scenes/beat4_loop.py with Approve intercept

**Files:**
- Modify: `scripts/demo_video/scenes/beat4_loop.py`

- [ ] **Step 1: Replace the file**

```python
"""Beat 4: loop closing. 45s, 9 phrases. At the "click approve" phrase the
scene calls openApproveModal + confirmPromote on the live dashboard.
SIDE EFFECT: actually promotes RULE_ID_FOR_PROMOTE on the live store.
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL, RULE_ID_FOR_PROMOTE
from ..phrases import phrases_for
from ._helpers import highlight, unhighlight


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/site/dashboard.html?cb=demo-beat4")
    await page.wait_for_load_state("networkidle")
    await page.wait_for_function(
        "() => document.querySelectorAll('[id^=\"rule-card-\"]').length > 0"
    )
    # Scroll past hero into the drafted-rules section so the widgets are in
    # view for the first phrases.
    await page.evaluate(
        """() => {
            const target = document.getElementById('section-rules');
            if (target) target.scrollIntoView({behavior: 'instant', block: 'start'});
        }"""
    )
    await asyncio.sleep(0.4)

    for phrase in phrases_for("beat4_loop"):
        text = phrase["text"]

        # When the narrator says "I read one, decide it is safe, click approve"
        # actually open the modal so the highlight lands on the rule card +
        # the next phrase ("The rule is now in the live agent's rule store")
        # sees the widget count update.
        if text.startswith("I read one"):
            await page.evaluate(
                f"document.getElementById('rule-card-{RULE_ID_FOR_PROMOTE}')"
                f"?.scrollIntoView({{behavior: 'smooth', block: 'center'}})"
            )
            await asyncio.sleep(0.5)
        elif text.startswith("The rule is now"):
            # Open + confirm the promote.
            await page.evaluate(f"openApproveModal('{RULE_ID_FOR_PROMOTE}', CURRENT_DATE)")
            await asyncio.sleep(0.6)
            await page.evaluate(f"confirmPromote('{RULE_ID_FOR_PROMOTE}', CURRENT_DATE)")
            await asyncio.sleep(0.4)

        if phrase["selector"]:
            await highlight(page, phrase["selector"])
        await asyncio.sleep(phrase["duration_s"])
        if phrase["selector"]:
            await unhighlight(page, phrase["selector"])
```

- [ ] **Step 2: Commit**

```
git add scripts/demo_video/scenes/beat4_loop.py
git commit -m "demo_video: beat 4 phrase iterator with Approve intercept on the named phrase"
```

---

## Task 9: Rewrite scenes/beat5_outro.py

**Files:**
- Modify: `scripts/demo_video/scenes/beat5_outro.py`

- [ ] **Step 1: Replace the file**

```python
"""Beat 5: outro end-card. 15s, 4 phrases pointing at the URL rows.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from playwright.async_api import Page

from ..phrases import phrases_for
from ._helpers import highlight, unhighlight

CARD = Path(__file__).resolve().parent / "end_card.html"


async def record(page: Page) -> None:
    await page.goto(f"file:///{CARD.as_posix()}")
    await page.wait_for_load_state("networkidle")
    for phrase in phrases_for("beat5_outro"):
        if phrase["selector"]:
            await highlight(page, phrase["selector"])
        await asyncio.sleep(phrase["duration_s"])
        if phrase["selector"]:
            await unhighlight(page, phrase["selector"])
```

- [ ] **Step 2: Commit**

```
git add scripts/demo_video/scenes/beat5_outro.py
git commit -m "demo_video: beat 5 phrase iterator pointing at end-card URL rows"
```

---

## Task 10: probes/check_phrase_selectors.py

**Files:**
- Create: `scripts/demo_video/probes/check_phrase_selectors.py`

- [ ] **Step 1: Write the probe**

```python
"""Pre-flight check that every PHRASES selector resolves to a real DOM
element on the target page. Run before recording so misses do not waste
recording time.

Each beat is checked against the page that beat will record. SPA pages
(viewer, dashboard) are loaded fresh for each beat.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from playwright.async_api import async_playwright

from demo_video.config import (
    SITE_URL, CASE_ID, RUN_ID, SECOND_CASE_ID, SECOND_RUN_ID,
    RULE_ID_FOR_PROMOTE,
)
from demo_video.phrases import PHRASES, phrases_for


_FIND_EL_JS = """
(s) => {
    const m = s.match(/^(.*?):has-text\\('(.+?)'\\)(.*)$/);
    if (!m) return !!document.querySelector(s);
    const [_, base, text, after] = m;
    const candidates = base ? document.querySelectorAll(base) : document.querySelectorAll('*');
    for (const el of candidates) {
        if ((el.textContent || '').includes(text)) {
            if (after) {
                if (el.querySelector(after.replace(/^\\s+/, ''))) return true;
            } else {
                return true;
            }
        }
    }
    return false;
}
"""


async def _setup_for_beat(page, beat: str) -> None:
    if beat == "beat1_open":
        await page.goto(f"{SITE_URL}/site/dashboard.html")
        await page.wait_for_load_state("networkidle")
    elif beat == "beat2_architecture":
        await page.goto(f"{SITE_URL}/site/architecture.html")
        await page.wait_for_load_state("domcontentloaded")
    elif beat == "beat3_case":
        await page.goto(f"{SITE_URL}/viewer/")
        await page.wait_for_load_state("domcontentloaded")
        await page.wait_for_function("() => typeof toggleCase === 'function'")
        await page.evaluate(f"toggleCase('{CASE_ID}')")
        await asyncio.sleep(0.5)
        await page.evaluate(f"loadRun('{CASE_ID}', '{RUN_ID}')")
        await asyncio.sleep(1.5)
        # also pre-toggle the second case so file-server selectors resolve
        await page.evaluate(f"toggleCase('{SECOND_CASE_ID}')")
        await asyncio.sleep(0.5)
    elif beat == "beat4_loop":
        await page.goto(f"{SITE_URL}/site/dashboard.html")
        await page.wait_for_load_state("networkidle")
        await page.wait_for_function(
            "() => document.querySelectorAll('[id^=\"rule-card-\"]').length > 0"
        )
    elif beat == "beat5_outro":
        # End card is local file; selectors against generic .name + .row.
        from pathlib import Path as _P
        card = _P(__file__).resolve().parents[1] / "scenes" / "end_card.html"
        await page.goto(f"file:///{card.as_posix()}")
        await page.wait_for_load_state("networkidle")


async def main() -> int:
    misses_by_beat: dict[str, list[str]] = {}
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        for beat in ["beat1_open", "beat2_architecture", "beat3_case", "beat4_loop", "beat5_outro"]:
            page = await (await browser.new_context()).new_page()
            await _setup_for_beat(page, beat)
            for phrase in phrases_for(beat):
                sel = phrase["selector"]
                if not sel:
                    continue
                # For beat3, switch tabs as needed before checking the selector.
                if beat == "beat3_case":
                    if sel.startswith("[data-tab='evidence']") or sel.startswith(".evidence-record"):
                        await page.evaluate('document.querySelector(\'[data-tab="evidence"]\')?.click()')
                        await asyncio.sleep(0.3)
                    elif sel.startswith("[data-tab='pipeline']") or sel.startswith(".pipeline-event"):
                        await page.evaluate('document.querySelector(\'[data-tab="pipeline"]\')?.click()')
                        await asyncio.sleep(0.3)
                found = await page.evaluate(_FIND_EL_JS, sel)
                if not found:
                    misses_by_beat.setdefault(beat, []).append(sel + "   (phrase: " + phrase["text"][:60] + ")")
            await page.close()
        await browser.close()

    if misses_by_beat:
        print("FAIL: some selectors did not resolve:")
        for beat, misses in misses_by_beat.items():
            print(f"  {beat}:")
            for m in misses:
                print(f"    - {m}")
        return 1
    print("ALL PHRASE SELECTORS RESOLVE.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
```

- [ ] **Step 2: Commit**

```
git add scripts/demo_video/probes/check_phrase_selectors.py
git commit -m "demo_video: probes/check_phrase_selectors.py validates every PHRASES selector"
```

---

## Task 11: Selector pre-flight (run the probe, fix any misses)

- [ ] **Step 1: Run the probe**

```
cd "D:/Python Applications/Find Evil - Hackathon"
MSYS_NO_PATHCONV=1 docker run --rm -v "/d/Python Applications/Find Evil - Hackathon:/work" -w /work demo-video:latest python -m scripts.demo_video.probes.check_phrase_selectors
```

Expected: `ALL PHRASE SELECTORS RESOLVE.`

- [ ] **Step 2: If any miss, edit phrases.py and re-run**

For each miss reported, open the live page in Playwright MCP and find the actual selector for that element, edit `scripts/demo_video/phrases.py`, re-run the probe. Repeat until clean. Common fixes:
- `.pipeline-event:has-text('critic')` may need a different tag if the viewer uses a different element name; replace with whatever the Pipeline tab actually renders.
- `.evidence-record:nth-of-type(N)` may need to be `.evidence-card` or similar; check the Evidence tab DOM.

- [ ] **Step 3: Commit any phrases.py fixes**

```
git add scripts/demo_video/phrases.py
git commit -m "demo_video: phrases.py selector fixes after live pre-flight"
```

---

## Task 12: Re-record beats 2 and 3

**Files:**
- Touches: `out/demo_video/beat2_architecture.mp4`, `out/demo_video/beat3_case.mp4`

- [ ] **Step 1: Run the Phase A site probe first**

```
MSYS_NO_PATHCONV=1 docker run --rm -v "/d/Python Applications/Find Evil - Hackathon:/work" -w /work demo-video:latest python scripts/demo_video/probes/check_site.py
```

Expected: `ALL PROBES PASS, ready to record.`

- [ ] **Step 2: Re-record beat 2**

```
rm -f out/demo_video/beat2_architecture.mp4
MSYS_NO_PATHCONV=1 docker run --rm -v "/d/Python Applications/Find Evil - Hackathon:/work" -w /work demo-video:latest python -m scripts.demo_video.record_beat beat2_architecture
```

Expected: `wrote /work/out/demo_video/beat2_architecture.mp4`. Verify duration:

```
MSYS_NO_PATHCONV=1 docker run --rm -v "/d/Python Applications/Find Evil - Hackathon:/work" -w /work --entrypoint ffprobe demo-video:latest -v quiet -show_entries format=duration -of csv=p=0 /work/out/demo_video/beat2_architecture.mp4
```

Expected: `45.0xx`.

- [ ] **Step 3: Re-record beat 3**

The apt28 rule for beat 4 was already promoted in the prior session, so check that beat 4's RULE_ID_FOR_PROMOTE is updated if needed (Task 13 deals with this).

```
rm -f out/demo_video/beat3_case.mp4
MSYS_NO_PATHCONV=1 docker run --rm -v "/d/Python Applications/Find Evil - Hackathon:/work" -w /work demo-video:latest python -m scripts.demo_video.record_beat beat3_case
```

Expected: `wrote ...beat3_case.mp4`. Verify duration ~180.

---

## Task 13: Re-record beats 1, 4, 5

The phrase-iterator rewrites also affect beats 1, 4, 5. Re-record so all 5 scenes use the same pattern.

- [ ] **Step 1: Beat 1 (no side effects)**

```
rm -f out/demo_video/beat1_open.mp4
MSYS_NO_PATHCONV=1 docker run --rm -v "/d/Python Applications/Find Evil - Hackathon:/work" -w /work demo-video:latest python -m scripts.demo_video.record_beat beat1_open
```

Verify ~15s.

- [ ] **Step 2: Beat 5 (no side effects)**

```
rm -f out/demo_video/beat5_outro.mp4
MSYS_NO_PATHCONV=1 docker run --rm -v "/d/Python Applications/Find Evil - Hackathon:/work" -w /work demo-video:latest python -m scripts.demo_video.record_beat beat5_outro
```

Verify ~15s.

- [ ] **Step 3: Beat 4 needs a fresh pending rule**

Run the Phase A probe; if `RULE_ID_FOR_PROMOTE = apt28_cve_2026_32202_lnk_spoofing_task-c99bf8f051` is no longer pending, edit `scripts/demo_video/config.py` to a still-pending rule id from `/api/proposed-rules`, AND update the matching phrase selector in `phrases.py`:

```python
{"beat": "beat4_loop", "text": "I read one, decide it is safe, click approve.", "duration_s": 5.0, "selector": "#rule-card-<NEW-RULE-ID>"},
```

Commit the rule-id change before recording.

```
rm -f out/demo_video/beat4_loop.mp4
MSYS_NO_PATHCONV=1 docker run --rm -v "/d/Python Applications/Find Evil - Hackathon:/work" -w /work demo-video:latest python -m scripts.demo_video.record_beat beat4_loop
```

Verify ~45s.

---

## Task 14: Re-stitch silent + burn captions

- [ ] **Step 1: Concat silent**

```
MSYS_NO_PATHCONV=1 docker run --rm -v "/d/Python Applications/Find Evil - Hackathon:/work" -w /work demo-video:latest bash scripts/demo_video/assemble_silent.sh
```

Expected: prints duration close to 300.

- [ ] **Step 2: Generate SRT**

```
MSYS_NO_PATHCONV=1 docker run --rm -v "/d/Python Applications/Find Evil - Hackathon:/work" -w /work demo-video:latest python -m scripts.demo_video.captions
```

Expected: `wrote /work/out/demo_video/captions.srt`.

- [ ] **Step 3: Burn captions**

```
MSYS_NO_PATHCONV=1 docker run --rm -v "/d/Python Applications/Find Evil - Hackathon:/work" -w /work demo-video:latest bash scripts/demo_video/burn_captions.sh
```

Expected: prints duration close to 300.

- [ ] **Step 4: Confirm artifact present**

```
ls -la out/demo_video/demo_silent_with_captions.mp4
```

Expected: file exists.

---

## Task 15: Phase D.5 review gate (manual; halt for Charan)

- [ ] **Step 1: Hand off**

Tell Charan: open `out/demo_video/demo_silent_with_captions.mp4` and watch end to end with sound off. The captions alone should carry the story. For each phrase, the highlight should land on the named element when the caption shows.

- [ ] **Step 2: Wait for explicit signoff**

Do NOT advance to voice generation without explicit "approved, generate voice" or equivalent.

- [ ] **Step 3: If changes requested**

Identify whether the issue is a phrase TEXT change, a phrase DURATION change, or a phrase SELECTOR change. Edit `phrases.py`, re-run the relevant beat record (Task 12 or 13), re-stitch (Task 14), re-present.

---

## Self-review

**Spec coverage:**
- PHRASES list -> Task 1.
- highlight/unhighlight helpers -> Task 2.
- Captions rewrite (PHRASES-derived) -> Task 3.
- Voice gen patch (PHRASES-derived) -> Task 4.
- Scene rewrites (5 beats) -> Tasks 5-9.
- Selector pre-flight probe -> Tasks 10-11.
- Re-record + re-stitch + review gate -> Tasks 12-15.

**Placeholder scan:** Task 13 Step 3 mentions "If RULE_ID_FOR_PROMOTE is no longer pending" with explicit fix path. Not a placeholder; concrete contingency. No TBD/TODO/etc.

**Type/signature consistency:** `phrases_for(beat) -> list[dict]`, `beat_total_seconds(beat) -> float`, `BEAT_ORDER: list[str]` referenced consistently across captions.py, voice_gen.py, all scenes, and the probe. Highlight selector uses standard CSS + `:has-text('...')` consistently across phrases.py, _helpers.py, and check_phrase_selectors.py.

**Out of scope (per spec):** animated arrows, label callouts, spotlight overlays, per-word sync, auto-derived durations, modifying the Sri Studio Helper standalone repo. Confirmed not in any task.
