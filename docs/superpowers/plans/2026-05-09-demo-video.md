# Demo Video Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a 5-minute demo video for the SANS Find Evil hackathon submission, following the spec at `docs/superpowers/specs/2026-05-09-demo-video-script-design.md`. Visuals first, voice last; ElevenLabs voice generation gated on a Charan-watched silent-with-captions cut.

**Architecture:** Per-beat Playwright recording at 1920x1080, ffmpeg for concat / caption burn / audio mux, ElevenLabs API for voice clone, manual review gate between captions and voice. One file per beat through the whole pipeline so re-cuts touch one beat at a time.

**Tech Stack:** Playwright Python (already installed), ffmpeg (host-side), ElevenLabs Python SDK, IBM Plex Sans font for caption rendering. Existing `scripts/record_demo.py` is the reference pattern; this work creates a separate `scripts/demo_video/` tree.

---

## File structure

| File | Role |
|---|---|
| `scripts/demo_video/__init__.py` | package marker |
| `scripts/demo_video/config.py` | constants: SITE_URL, CASE_ID, RUN_ID, RULE_ID_FOR_PROMOTE, OUT_DIR, DURATIONS |
| `scripts/demo_video/captions.py` | SRT generator from spec voiceover text |
| `scripts/demo_video/scenes/beat1_open.py` | Playwright scene 1 (15s, dashboard hero hold) |
| `scripts/demo_video/scenes/beat2_architecture.py` | Playwright scene 2 (45s, architecture page slow scroll) |
| `scripts/demo_video/scenes/beat3_case.py` | Playwright scene 3 (3:00, viewer rd-02-dual walkthrough + critic) |
| `scripts/demo_video/scenes/beat4_loop.py` | Playwright scene 4 (45s, dashboard scroll + live promote) |
| `scripts/demo_video/scenes/beat5_outro.py` | Playwright scene 5 (15s, end-card image) |
| `scripts/demo_video/record_beat.py` | runner: takes a beat name, dispatches to scenes/, writes mp4 |
| `scripts/demo_video/voice_gen.py` | ElevenLabs voice gen wrapper (one beat per call) |
| `scripts/demo_video/assemble.sh` | ffmpeg concat + caption burn + audio mux + final export |
| `scripts/demo_video/probes/check_site.py` | Phase A probe: site reachable + rule still pending |
| `tests/test_demo_video_captions.py` | TDD test for SRT generator |
| `out/demo_video/` | generated artifacts (gitignored): scene1_open.mp4 ... voice5_outro.mp3 ... final.mp4 |

`out/demo_video/` is gitignored. Source scripts and tests are committed.

---

## Task 1: Bootstrap directory + config + .gitignore

**Files:**
- Create: `scripts/demo_video/__init__.py`
- Create: `scripts/demo_video/config.py`
- Create: `out/demo_video/.gitkeep`
- Modify: `.gitignore` (append rule for `out/demo_video/*` except `.gitkeep`)

- [ ] **Step 1: Create the package init**

```python
# scripts/demo_video/__init__.py
"""Demo video production pipeline for the SANS hackathon submission.

Per-beat Playwright recordings, ffmpeg-based assembly, ElevenLabs voice
generation. See docs/superpowers/specs/2026-05-09-demo-video-script-design.md.
"""
```

- [ ] **Step 2: Create the shared config**

```python
# scripts/demo_video/config.py
"""Constants shared across all beat scenes and the assembler.

Locked from the spec at docs/superpowers/specs/2026-05-09-demo-video-script-design.md.
Change here, not in individual scene files.
"""
from pathlib import Path

SITE_URL = "https://sentinel.sshub.dev"
CASE_ID = "srl-2018-base-rd-02-dual"
RUN_ID = "srl-2018-base-rd-02-dual-002"
SECOND_CASE_ID = "srl-2018-base-file"
SECOND_RUN_ID = "srl-2018-base-file-005"
RULE_ID_FOR_PROMOTE = "apt28_cve_2026_32202_lnk_spoofing_task-c99bf8f051"

VIEWPORT_WIDTH = 1920
VIEWPORT_HEIGHT = 1080
FRAMERATE = 30

# Beat duration budget in seconds. Total must equal 300 (5:00).
DURATIONS = {
    "beat1_open": 15,
    "beat2_architecture": 45,
    "beat3_case": 180,
    "beat4_loop": 45,
    "beat5_outro": 15,
}
assert sum(DURATIONS.values()) == 300, "beat durations must sum to 300 seconds"

OUT_DIR = Path(__file__).resolve().parents[2] / "out" / "demo_video"
OUT_DIR.mkdir(parents=True, exist_ok=True)
```

- [ ] **Step 3: Add gitignore rule**

Append to `.gitignore`:
```
# Demo video artifacts (generated, large, do not commit)
out/demo_video/*
!out/demo_video/.gitkeep
```

- [ ] **Step 4: Probe config loads**

Run:
```
docker exec sift-sentinel /workspace/.venv/bin/python -c "import sys; sys.path.insert(0, '/workspace/../scripts'); from demo_video.config import DURATIONS, OUT_DIR; print('total:', sum(DURATIONS.values()), 'out:', OUT_DIR)"
```

Wait, the host runs the demo recording (Playwright + ffmpeg are host-side), not the container. Use Windows host:

```
cd "D:/Python Applications/Find Evil - Hackathon"
python -c "import sys; sys.path.insert(0, 'scripts'); from demo_video.config import DURATIONS, OUT_DIR; print('total:', sum(DURATIONS.values()), 'out:', OUT_DIR)"
```

Expected: `total: 300 out: D:\Python Applications\Find Evil - Hackathon\out\demo_video`

- [ ] **Step 5: Commit**

```
cd "D:/Python Applications/Find Evil - Hackathon"
git add scripts/demo_video/__init__.py scripts/demo_video/config.py out/demo_video/.gitkeep .gitignore
git commit -m "demo_video: bootstrap config + gitignore artifacts"
```

---

## Task 2: Captions SRT generator (TDD)

**Files:**
- Create: `scripts/demo_video/captions.py`
- Create: `tests/test_demo_video_captions.py`

The voiceover text from each beat in the spec must be converted to a single SRT file with timestamps anchored to the beat boundaries (0:00, 0:15, 1:00, 4:00, 4:45). Each beat's text is split into 1-2 caption lines per screen, max 80 chars per line.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_demo_video_captions.py
"""Tests for scripts/demo_video/captions.py SRT generator."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from demo_video.captions import build_srt, BEATS


def test_build_srt_has_one_cue_per_caption_line():
    srt = build_srt()
    assert "1\n00:00:" in srt
    assert " --> " in srt
    cue_count = srt.count(" --> ")
    assert cue_count >= len(BEATS), f"expected at least one cue per beat, got {cue_count}"


def test_build_srt_anchors_first_cue_to_2_seconds_in():
    srt = build_srt()
    assert "00:00:02," in srt, "first caption should appear at 2s into the cold open"


def test_build_srt_no_caption_line_over_80_chars():
    srt = build_srt()
    for line in srt.splitlines():
        if "-->" in line or line.strip().isdigit() or not line.strip():
            continue
        assert len(line) <= 80, f"caption line too long ({len(line)}): {line!r}"


def test_beats_total_300_seconds():
    total = sum(b["duration_s"] for b in BEATS)
    assert total == 300


def test_each_beat_has_voiceover_text():
    for b in BEATS:
        assert b["voiceover"].strip(), f"beat {b['name']} missing voiceover text"
```

- [ ] **Step 2: Run test, expect FAIL (no captions module yet)**

Run:
```
cd "D:/Python Applications/Find Evil - Hackathon"
python -m pytest tests/test_demo_video_captions.py -v
```

Expected: ImportError or test failure.

- [ ] **Step 3: Implement captions.py**

```python
# scripts/demo_video/captions.py
"""Generate the SRT caption file from the locked voiceover text per beat.

Source of truth: docs/superpowers/specs/2026-05-09-demo-video-script-design.md.
Caption text MUST match voiceover text verbatim (so when voice is generated
in Phase E it does not drift from the burned-in caption).
"""
from __future__ import annotations

from pathlib import Path

# Each beat: name, start_s offset, duration_s, voiceover paragraph.
# Start offsets are cumulative (beat1 starts at 0, beat2 at 15, etc.).
BEATS = [
    {
        "name": "beat1_open",
        "start_s": 0,
        "duration_s": 15,
        "voiceover": (
            "Last night, an AI agent I built found a fake Microsoft service "
            "hiding on a real Windows server. Then it caught itself making "
            "a mistake on the next finding. Then it drafted a rule so it "
            "gets the next case right. Here is how."
        ),
    },
    {
        "name": "beat2_architecture",
        "start_s": 15,
        "duration_s": 45,
        "voiceover": (
            "Sentinel runs the autonomous incident response loop with three "
            "architectural guardrails, not just prompt promises. First: every "
            "tool call crosses a capability-token boundary at the MCP server, "
            "scoped to the case ID and the allowed paths. Second: an injection "
            "scanner sits in the Critic and quarantines tool output that looks "
            "adversarial, before that output ever reaches the LLM that "
            "interprets findings. Third: every step of every run is hash-chained "
            "into an integrity ledger, so a finding can be traced back to the "
            "exact tool execution that produced it. The loop itself is six nodes: "
            "extract, plan, execute, interpret, critic, and learn. The critic "
            "and the learn nodes are where the autonomy lives."
        ),
    },
    {
        "name": "beat3a_findings",
        "start_s": 60,
        "duration_s": 30,
        "voiceover": (
            "The case: a Windows server from a 2018 enterprise compromise. "
            "The agent ran in dual-channel mode, looking at both the disk image "
            "and a memory snapshot in the same run. It produced five findings. "
            "The first one is a Windows service called Microsoft Advanced API "
            "thirty-two, set to auto-start, running a binary called msadvapi2_32.exe "
            "out of Program Files. That product does not exist. The agent flagged "
            "it with high confidence."
        ),
    },
    {
        "name": "beat3b_audit",
        "start_s": 90,
        "duration_s": 45,
        "voiceover": (
            "Every finding is a citation. Click the citation and you reach the "
            "actual tool output that produced it. Here is the RegRipper services "
            "dump where the service was registered. ImagePath, type, start mode, "
            "all there. Click the second citation, and you are in the memory-side "
            "pslist. The same binary, msadvapi2_32, is running right now at PID "
            "2292. Disk says it should be running. Memory confirms it is running. "
            "That is what dual-channel means here. Notice the timestamps on the "
            "two services. Both installed within eighteen seconds of each other "
            "on May eighth, 2018. That is one attacker installation event, not "
            "two unrelated services."
        ),
    },
    {
        "name": "beat3c_critic",
        "start_s": 135,
        "duration_s": 60,
        "voiceover": (
            "Now the self-correction. While the agent was producing findings, "
            "the critic noticed something in one of the tool outputs. A byte "
            "sequence in the raw registry hive contained the substring T1033, "
            "which matches the pattern the injection scanner uses to detect "
            "adversarial prompt content trying to inject MITRE technique IDs. "
            "In this case, the substring was random binary noise from a regf "
            "hive, not a real injection. But the agent did not silently dismiss "
            "it. It quarantined the tool output, escalated to human review, and "
            "refused to act on findings that depended on it until a human cleared "
            "the quarantine. That is the architectural guardrail firing. A "
            "prompt-only system would have let this through, or worse, treated "
            "the injected technique IDs as real evidence. Three findings escalated. "
            "None were silently approved. That is what auditable autonomy looks like."
        ),
    },
    {
        "name": "beat3d_corroboration",
        "start_s": 195,
        "duration_s": 45,
        "voiceover": (
            "One more thing. The agent ran on the file server in the same "
            "network, in a separate session, with no shared state. It found "
            "the same msadvapi2 kit. Same fake Microsoft naming pattern, same "
            "paired thirty-two and sixty-four bit service, same auto-start "
            "configuration. That cross-host signal was not engineered. The "
            "agent reached it independently on each host, with separate evidence "
            "chains, and the audit trail from both runs lines up. For an analyst, "
            "this is the strongest evidence we have that the agent is not just "
            "confidently wrong. It is confidently right, and the corroboration "
            "emerges from the data, not from a heuristic that was pre-baked."
        ),
    },
    {
        "name": "beat4_loop",
        "start_s": 240,
        "duration_s": 45,
        "voiceover": (
            "And the loop closes here. Every night, the cron at 22:30 UTC runs "
            "the agent against fresh threat intel from CISA, Rapid7, GitGuardian, "
            "the public KEV. When it misses something, a drafter agent synthesizes "
            "a candidate rule from the miss and stages it. Today, twelve rules "
            "are waiting. I read one, decide it is safe, click approve. The rule "
            "is now in the live agent's rule store. Tomorrow night's run picks "
            "it up automatically. The widget counts update in front of you. This "
            "is not a demo, this is the production system. The whole loop runs "
            "on the same dashboard you are watching."
        ),
    },
    {
        "name": "beat5_outro",
        "start_s": 285,
        "duration_s": 15,
        "voiceover": (
            "Sift Sentinel. Live at sentinel.sshub.dev. Code on GitHub at "
            "github.com/charanbobby/sift-sentinel. Built by Charan Bobby for "
            "the SANS Find Evil hackathon. Thanks for watching."
        ),
    },
]


def _split_into_lines(text: str, max_chars: int = 80) -> list[str]:
    """Greedy word-wrap, preferring 2-line blocks under max_chars each."""
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    for w in words:
        candidate = " ".join(current + [w])
        if len(candidate) <= max_chars:
            current.append(w)
        else:
            lines.append(" ".join(current))
            current = [w]
    if current:
        lines.append(" ".join(current))
    return lines


def _hms(seconds: float) -> str:
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    ms = int((seconds - int(seconds)) * 1000)
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"


def build_srt(lead_in_s: float = 2.0, max_chars: int = 80) -> str:
    """Build an SRT string covering all 8 sub-beats. Each beat's voiceover is
    split into ~80-char lines and distributed evenly across the beat duration,
    leaving a 0.3s gap between cues so they do not overlap visually.
    """
    cues: list[tuple[float, float, str]] = []
    for beat in BEATS:
        text = beat["voiceover"]
        lines = _split_into_lines(text, max_chars=max_chars)
        # 2-line caption windows
        windows = [lines[i:i + 2] for i in range(0, len(lines), 2)]
        n = len(windows)
        if n == 0:
            continue
        beat_start = beat["start_s"] + (lead_in_s if beat["name"] == "beat1_open" else 0)
        beat_end = beat["start_s"] + beat["duration_s"]
        avail = max(0.5, beat_end - beat_start - 0.3)
        per = avail / n
        for i, window in enumerate(windows):
            t0 = beat_start + i * per
            t1 = t0 + per - 0.3
            cues.append((t0, t1, "\n".join(window)))

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

- [ ] **Step 4: Run tests, verify PASS**

```
cd "D:/Python Applications/Find Evil - Hackathon"
python -m pytest tests/test_demo_video_captions.py -v
```

Expected: 5 PASS.

- [ ] **Step 5: Commit**

```
git add scripts/demo_video/captions.py tests/test_demo_video_captions.py
git commit -m "demo_video: SRT caption generator with locked beat voiceover"
```

---

## Task 3: Phase A probe script

**Files:**
- Create: `scripts/demo_video/probes/__init__.py`
- Create: `scripts/demo_video/probes/check_site.py`

- [ ] **Step 1: Create the probe**

```python
# scripts/demo_video/probes/__init__.py
"""Pre-record probes per spec Phase A."""
```

```python
# scripts/demo_video/probes/check_site.py
"""Phase A pre-record probes. Run before Phase B (recording).

Verifies:
1. https://sentinel.sshub.dev/site/dashboard.html returns 200.
2. /api/proposed-rules returns the locked rule_id (still pending).
3. /viewer/api/cases lists the spine case.
"""
from __future__ import annotations

import sys
import urllib.request
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from demo_video.config import SITE_URL, CASE_ID, RULE_ID_FOR_PROMOTE


def _http_get(url: str, timeout: int = 10) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"user-agent": "demo-video-probe"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.getcode(), resp.read().decode("utf-8")


def main() -> int:
    failures: list[str] = []

    code, _ = _http_get(f"{SITE_URL}/site/dashboard.html")
    print(f"dashboard.html  -> {code}")
    if code != 200:
        failures.append(f"dashboard returned {code}")

    code, body = _http_get(f"{SITE_URL}/api/proposed-rules")
    print(f"proposed-rules  -> {code}, count={json.loads(body).get('count')}")
    if code != 200:
        failures.append(f"proposed-rules returned {code}")
    else:
        ids = [r["id"] for r in json.loads(body).get("rules", [])]
        if RULE_ID_FOR_PROMOTE not in ids:
            failures.append(
                f"locked rule {RULE_ID_FOR_PROMOTE!r} not in pending list. "
                f"Update RULE_ID_FOR_PROMOTE in config.py to a still-pending one."
            )

    code, body = _http_get(f"{SITE_URL}/viewer/api/cases")
    print(f"viewer cases    -> {code}")
    if code != 200:
        failures.append(f"viewer/api/cases returned {code}")
    else:
        cases = json.loads(body)
        case_ids = [c.get("case_id") if isinstance(c, dict) else c for c in cases.get("cases", cases)]
        if CASE_ID not in case_ids:
            failures.append(f"case {CASE_ID!r} not listed by viewer")

    if failures:
        print("\nFAIL:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nALL PROBES PASS, ready to record.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Run the probe**

```
cd "D:/Python Applications/Find Evil - Hackathon"
python scripts/demo_video/probes/check_site.py
```

Expected: "ALL PROBES PASS, ready to record." If any failure, fix the underlying issue before continuing.

- [ ] **Step 3: Commit**

```
git add scripts/demo_video/probes/
git commit -m "demo_video: Phase A pre-record probe"
```

---

## Task 4: Beat 1 scene (open hook, 15s static hold)

**Files:**
- Create: `scripts/demo_video/scenes/__init__.py`
- Create: `scripts/demo_video/scenes/beat1_open.py`
- Create: `scripts/demo_video/record_beat.py`

- [ ] **Step 1: Create the scene**

```python
# scripts/demo_video/scenes/__init__.py
"""Per-beat Playwright scene scripts. Each module exposes record(page, out_path)."""
```

```python
# scripts/demo_video/scenes/beat1_open.py
"""Beat 1: cold open. Dashboard hero held static for 15 seconds.

The hero shows 'Last night (2026-05-08), Sentinel ran. Tonight it gets better.'
plus the 4-widget board. Static frame for 2 seconds, then continues holding
for the remaining 13 seconds while the voiceover plays in Phase F.
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL, DURATIONS


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/site/dashboard.html?cb=demo")
    await page.wait_for_load_state("networkidle")
    # Wait for /api/status + /api/proposed-rules to populate
    await page.wait_for_function(
        "() => document.getElementById('w-queued-num')?.textContent !== ','"
    )
    await asyncio.sleep(DURATIONS["beat1_open"])
```

- [ ] **Step 2: Create the recorder runner**

```python
# scripts/demo_video/record_beat.py
"""Record a single beat to MP4 via Playwright.

Usage:
    python scripts/demo_video/record_beat.py beat1_open
    python scripts/demo_video/record_beat.py beat2_architecture
    ...

Output: out/demo_video/<beat_name>.mp4 (transcoded from Playwright's webm).
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import shutil
import subprocess
import sys
from pathlib import Path

from playwright.async_api import async_playwright

from .config import OUT_DIR, VIEWPORT_WIDTH, VIEWPORT_HEIGHT


async def _record(beat_name: str) -> Path:
    scene_module = importlib.import_module(f"demo_video.scenes.{beat_name}")
    raw_dir = OUT_DIR / "_raw" / beat_name
    raw_dir.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
            record_video_dir=str(raw_dir),
            record_video_size={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
        )
        page = await context.new_page()
        try:
            await scene_module.record(page)
        finally:
            await context.close()
            await browser.close()
    webms = list(raw_dir.glob("*.webm"))
    if not webms:
        raise RuntimeError(f"no webm produced in {raw_dir}")
    webm = webms[0]
    out_path = OUT_DIR / f"{beat_name}.mp4"
    subprocess.run(
        ["ffmpeg", "-y", "-i", str(webm), "-c:v", "libx264", "-preset", "veryfast",
         "-crf", "20", "-pix_fmt", "yuv420p", "-an", str(out_path)],
        check=True,
    )
    shutil.rmtree(raw_dir, ignore_errors=True)
    return out_path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("beat", help="beat name, e.g. beat1_open")
    args = ap.parse_args()
    out = asyncio.run(_record(args.beat))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    sys.exit(main())
```

- [ ] **Step 3: Probe by recording beat 1**

```
cd "D:/Python Applications/Find Evil - Hackathon"
python -m scripts.demo_video.record_beat beat1_open
```

Expected: prints `wrote .../out/demo_video/beat1_open.mp4`. Open the file and verify the dashboard hero is showing the SELF-CORRECTION LOOP label and the hero title.

- [ ] **Step 4: Verify duration is 15 +/- 1 seconds**

```
ffprobe -v quiet -show_entries format=duration -of csv=p=0 out/demo_video/beat1_open.mp4
```

Expected: `15.0xx`.

- [ ] **Step 5: Commit**

```
git add scripts/demo_video/scenes/__init__.py scripts/demo_video/scenes/beat1_open.py scripts/demo_video/record_beat.py
git commit -m "demo_video: beat 1 (open hook, 15s static hold)"
```

---

## Task 5: Beat 2 scene (architecture, 45s slow scroll)

**Files:**
- Create: `scripts/demo_video/scenes/beat2_architecture.py`

- [ ] **Step 1: Create the scene**

```python
# scripts/demo_video/scenes/beat2_architecture.py
"""Beat 2: architecture page slow-scroll. 45 seconds.

The existing /site/architecture.html is dense (3870 lines). For this beat
we just slow-scroll past it; the voiceover carries the meaning.
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL, DURATIONS


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/site/architecture.html")
    await page.wait_for_load_state("networkidle")
    await asyncio.sleep(1)
    # Slow scroll to bottom over 43 seconds, leaving 1s pad each side.
    duration_s = DURATIONS["beat2_architecture"] - 2
    steps = duration_s * 4  # 4 scroll ticks per second for smoothness
    await page.evaluate(
        """async ({ steps, duration_ms }) => {
            const total = document.documentElement.scrollHeight - window.innerHeight;
            const stepPx = total / steps;
            const stepMs = duration_ms / steps;
            for (let i = 0; i <= steps; i++) {
                window.scrollTo(0, i * stepPx);
                await new Promise(r => setTimeout(r, stepMs));
            }
        }""",
        {"steps": steps, "duration_ms": duration_s * 1000},
    )
    await asyncio.sleep(1)
```

- [ ] **Step 2: Probe by recording**

```
python -m scripts.demo_video.record_beat beat2_architecture
ffprobe -v quiet -show_entries format=duration -of csv=p=0 out/demo_video/beat2_architecture.mp4
```

Expected: duration `45.0xx`. Open and verify the architecture diagram scrolls smoothly top to bottom.

- [ ] **Step 3: Commit**

```
git add scripts/demo_video/scenes/beat2_architecture.py
git commit -m "demo_video: beat 2 (architecture page slow scroll, 45s)"
```

---

## Task 6: Beat 3 scene (case walkthrough, 3:00 four sub-beats)

**Files:**
- Create: `scripts/demo_video/scenes/beat3_case.py`

This is the longest and most complex scene. It records as ONE 3-minute MP4 with four phases inside (findings overview 30s, audit trail 45s, critic 60s, cross-host 45s). Sub-beat boundaries are the 30s/75s/135s marks.

- [ ] **Step 1: Create the scene**

```python
# scripts/demo_video/scenes/beat3_case.py
"""Beat 3: case walkthrough. 180 seconds.

Four sub-beats inside one recording:
  3a (0-30s): findings overview at /viewer/ for rd-02-dual
  3b (30-75s): audit trail trace, click two cited tool_call_ids
  3c (75-135s): critic disagreement section, INJECTION_QUARANTINE
  3d (135-180s): cross-host corroboration on srl-2018-base-file
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL, CASE_ID, RUN_ID, SECOND_CASE_ID, SECOND_RUN_ID


async def _wait(s: float) -> None:
    await asyncio.sleep(s)


async def record(page: Page) -> None:
    # 3a: findings overview (0 - 30s)
    await page.goto(f"{SITE_URL}/viewer/?case={CASE_ID}&run={RUN_ID}")
    await page.wait_for_load_state("networkidle")
    await _wait(2)
    await page.evaluate("window.scrollTo({ top: 200, behavior: 'smooth' })")
    await _wait(4)
    await page.evaluate("document.querySelectorAll('[data-finding-card]')[0]?.scrollIntoView({behavior:'smooth', block:'center'})")
    await _wait(8)
    # Hover the high-confidence pill on finding 0
    pill = page.locator('[data-finding-card]').first.locator('.pill-red, .pill-amber, [class*="confidence"]').first
    try:
        await pill.hover(timeout=3000)
    except Exception:
        pass
    await _wait(15)  # total 30

    # 3b: audit trail trace (30 - 75s)
    # Click the first cited tool_call_id of finding 0
    await page.evaluate("""
        const card = document.querySelectorAll('[data-finding-card]')[0];
        if (card) {
            const cite = card.querySelector('a[href*="tool_call_id"], [data-tool-call-id]');
            if (cite) cite.click();
        }
    """)
    await _wait(2)
    await page.evaluate("window.scrollBy({ top: 400, behavior: 'smooth' })")
    await _wait(8)
    await page.evaluate("history.back()")
    await page.wait_for_load_state("networkidle")
    await _wait(2)
    # Second citation
    await page.evaluate("""
        const card = document.querySelectorAll('[data-finding-card]')[0];
        if (card) {
            const cites = card.querySelectorAll('a[href*="tool_call_id"], [data-tool-call-id]');
            if (cites[1]) cites[1].click();
        }
    """)
    await _wait(2)
    await page.evaluate("window.scrollBy({ top: 600, behavior: 'smooth' })")
    await _wait(15)
    await page.evaluate("history.back()")
    await page.wait_for_load_state("networkidle")
    await _wait(11)  # cumulative 75

    # 3c: critic disagreement (75 - 135s)
    await page.evaluate("document.querySelector('[data-section=\"critic\"], #critic-section')?.scrollIntoView({behavior:'smooth'})")
    await _wait(8)
    # Pan slowly through the critic events area
    for _ in range(10):
        await page.evaluate("window.scrollBy({ top: 80, behavior: 'smooth' })")
        await _wait(5)
    await _wait(2)  # cumulative 135

    # 3d: cross-host corroboration (135 - 180s)
    await page.goto(f"{SITE_URL}/viewer/?case={SECOND_CASE_ID}&run={SECOND_RUN_ID}")
    await page.wait_for_load_state("networkidle")
    await _wait(3)
    await page.evaluate("""
        const txt = 'Microsoft Advanced API';
        const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
        let node;
        while (node = walk.nextNode()) {
            if (node.nodeValue && node.nodeValue.includes(txt)) {
                node.parentElement.scrollIntoView({behavior:'smooth', block:'center'});
                node.parentElement.style.outline = '2px solid #34d399';
                break;
            }
        }
    """)
    await _wait(42)  # cumulative 180
```

- [ ] **Step 2: Probe by recording**

```
python -m scripts.demo_video.record_beat beat3_case
ffprobe -v quiet -show_entries format=duration -of csv=p=0 out/demo_video/beat3_case.mp4
```

Expected: duration `180.0xx +/- 2s`. Open and step through; verify each sub-beat lands on the right content.

- [ ] **Step 3: If selectors do not match**

The viewer's HTML class names may differ from the assumed `[data-finding-card]`. If the JS evaluate calls produce no scroll, open the live viewer page in DevTools and find the actual selector for the finding cards and the citation links. Update `beat3_case.py` selectors and re-record. Probe again until duration is 180s and the right content shows in each window.

- [ ] **Step 4: Commit**

```
git add scripts/demo_video/scenes/beat3_case.py
git commit -m "demo_video: beat 3 (case walkthrough, 3:00 four sub-beats)"
```

---

## Task 7: Beat 4 scene (loop closing, 45s with live promote)

**Files:**
- Create: `scripts/demo_video/scenes/beat4_loop.py`

WARNING: this scene actually clicks the Approve button on a real rule. The recording side-effect is a real promotion in the live store. Do not re-run repeatedly without resetting; pick a different rule each time.

- [ ] **Step 1: Create the scene**

```python
# scripts/demo_video/scenes/beat4_loop.py
"""Beat 4: loop closing live. 45 seconds.

Scrolls past the hero + widgets to the drafted-rules section, hovers the
locked rule card, clicks Approve, confirms in the modal. The card disappears,
queued widget decrements, live widget increments. Recording captures the
state change in real time.

SIDE EFFECT: this actually promotes the rule in the live store. The
RULE_ID_FOR_PROMOTE in config.py is consumed by this run; pick a fresh
rule before re-recording.
"""
from __future__ import annotations

import asyncio
from playwright.async_api import Page

from ..config import SITE_URL, RULE_ID_FOR_PROMOTE


async def record(page: Page) -> None:
    await page.goto(f"{SITE_URL}/site/dashboard.html?cb=demo-beat4")
    await page.wait_for_load_state("networkidle")
    await page.wait_for_function(
        "() => document.querySelectorAll('[id^=\"rule-card-\"]').length > 0"
    )
    await asyncio.sleep(2)
    # Slow scroll past hero + widgets down to drafted-rules section
    await page.evaluate(
        """async () => {
            const target = document.getElementById('section-rules');
            const top = target.getBoundingClientRect().top + window.scrollY;
            const start = window.scrollY;
            const steps = 60;
            for (let i = 0; i <= steps; i++) {
                window.scrollTo(0, start + (top - start) * (i / steps));
                await new Promise(r => setTimeout(r, 100));
            }
        }"""
    )
    await asyncio.sleep(2)
    # Scroll the locked rule into view
    rule_id = RULE_ID_FOR_PROMOTE
    await page.evaluate(
        f"document.getElementById('rule-card-{rule_id}')?.scrollIntoView("
        f"{{behavior:'smooth', block:'center'}})"
    )
    await asyncio.sleep(3)
    # Click Approve
    await page.evaluate(f"openApproveModal('{rule_id}', CURRENT_DATE)")
    await asyncio.sleep(4)
    # Click Yes, promote
    await page.evaluate(f"confirmPromote('{rule_id}', CURRENT_DATE)")
    await asyncio.sleep(2)
    # Settle on the new widget counts
    await asyncio.sleep(11)
```

- [ ] **Step 2: Pre-record gate: confirm the rule is still pending**

```
python scripts/demo_video/probes/check_site.py
```

Expected: `ALL PROBES PASS`. If the locked rule was already promoted in a prior run, update RULE_ID_FOR_PROMOTE in config.py and re-probe.

- [ ] **Step 3: Record**

```
python -m scripts.demo_video.record_beat beat4_loop
ffprobe -v quiet -show_entries format=duration -of csv=p=0 out/demo_video/beat4_loop.mp4
```

Expected: duration `45.0xx`. Open and verify: scroll-down animation, modal opens, modal closes, card disappears, queued count drops by 1, live count goes up by 1.

- [ ] **Step 4: Commit**

```
git add scripts/demo_video/scenes/beat4_loop.py
git commit -m "demo_video: beat 4 (loop closing live promote, 45s)"
```

---

## Task 8: Beat 5 scene (outro end-card, 15s)

**Files:**
- Create: `scripts/demo_video/scenes/beat5_outro.py`
- Create: `scripts/demo_video/scenes/end_card.html`

- [ ] **Step 1: Create the end-card HTML**

```html
<!-- scripts/demo_video/scenes/end_card.html -->
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<style>
  html, body {
    margin: 0; padding: 0; background: #0b1020; color: #f8fafc;
    font-family: 'IBM Plex Mono', ui-monospace, Menlo, Consolas, monospace;
    height: 100vh; width: 100vw;
    display: flex; align-items: center; justify-content: center;
  }
  .card { text-align: center; line-height: 1.8; }
  .label { color: #94a3b8; text-transform: uppercase; letter-spacing: 0.12em; font-size: 14px; margin-bottom: 24px; }
  .name { font-family: 'IBM Plex Sans', sans-serif; font-size: 48px; font-weight: 700; margin-bottom: 32px; }
  .row { font-size: 22px; margin: 8px 0; }
  .row .k { color: #94a3b8; margin-right: 12px; }
  .row .v { color: #60a5fa; }
</style>
</head>
<body>
  <div class="card">
    <div class="label">SANS Find Evil Hackathon</div>
    <div class="name">Sift Sentinel</div>
    <div class="row"><span class="k">live</span><span class="v">sentinel.sshub.dev</span></div>
    <div class="row"><span class="k">code</span><span class="v">github.com/charanbobby/sift-sentinel</span></div>
    <div class="row"><span class="k">by</span><span class="v">Charan Bobby</span></div>
  </div>
</body>
</html>
```

- [ ] **Step 2: Create the scene**

```python
# scripts/demo_video/scenes/beat5_outro.py
"""Beat 5: outro end-card. 15 seconds.

Static frame: project name, live URL, code URL, author. Hold for 15s.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from playwright.async_api import Page

from ..config import DURATIONS

CARD = Path(__file__).resolve().parent / "end_card.html"


async def record(page: Page) -> None:
    await page.goto(f"file:///{CARD.as_posix()}")
    await page.wait_for_load_state("networkidle")
    await asyncio.sleep(DURATIONS["beat5_outro"])
```

- [ ] **Step 3: Record + verify**

```
python -m scripts.demo_video.record_beat beat5_outro
ffprobe -v quiet -show_entries format=duration -of csv=p=0 out/demo_video/beat5_outro.mp4
```

Expected: duration `15.0xx`. Open and verify the end-card layout and three lines.

- [ ] **Step 4: Commit**

```
git add scripts/demo_video/scenes/beat5_outro.py scripts/demo_video/scenes/end_card.html
git commit -m "demo_video: beat 5 (outro end-card, 15s)"
```

---

## Task 9: Phase C silent assembly + timing verify

**Files:**
- Create: `scripts/demo_video/assemble_silent.sh`

- [ ] **Step 1: Create the silent-assembly script**

```bash
#!/usr/bin/env bash
# scripts/demo_video/assemble_silent.sh
# Concat the 5 silent beat MP4s into a single demo_silent.mp4.
# Output: out/demo_video/demo_silent.mp4
set -euo pipefail

OUT_DIR="$(cd "$(dirname "$0")/../.." && pwd)/out/demo_video"
cd "$OUT_DIR"

LIST=demo_silent_concat.txt
> "$LIST"
for beat in beat1_open beat2_architecture beat3_case beat4_loop beat5_outro; do
  if [ ! -f "$beat.mp4" ]; then
    echo "missing $beat.mp4 in $OUT_DIR" >&2
    exit 1
  fi
  echo "file '$beat.mp4'" >> "$LIST"
done

ffmpeg -y -f concat -safe 0 -i "$LIST" -c copy demo_silent.mp4
ffprobe -v quiet -show_entries format=duration -of csv=p=0 demo_silent.mp4
rm "$LIST"
```

- [ ] **Step 2: Make executable + run**

```
cd "D:/Python Applications/Find Evil - Hackathon"
chmod +x scripts/demo_video/assemble_silent.sh
bash scripts/demo_video/assemble_silent.sh
```

Expected: prints duration close to `300.0`. Open `out/demo_video/demo_silent.mp4`, scrub to 0:15, 1:00, 4:00, 4:45 boundaries, verify visuals match the spec at each.

- [ ] **Step 3: If duration is over 300**

Find the over-budget beat with `ffprobe -v quiet -show_entries format=duration -of csv=p=0 out/demo_video/<beat>.mp4`. Trim the asyncio.sleep durations in the offending scene and re-record that beat only. Re-run assemble_silent.sh.

- [ ] **Step 4: Commit**

```
git add scripts/demo_video/assemble_silent.sh
git commit -m "demo_video: Phase C silent assembly script"
```

---

## Task 10: SRT generation + caption burn

**Files:**
- Create: `scripts/demo_video/burn_captions.sh`

- [ ] **Step 1: Generate the SRT**

```
cd "D:/Python Applications/Find Evil - Hackathon"
python -c "from scripts.demo_video.captions import build_srt; from scripts.demo_video.config import OUT_DIR; (OUT_DIR / 'captions.srt').write_text(build_srt(), encoding='utf-8'); print('wrote', OUT_DIR / 'captions.srt')"
```

Expected: prints `wrote .../out/demo_video/captions.srt`. Open the SRT and verify cue 1 starts at 00:00:02 and the last cue ends close to 00:05:00.

- [ ] **Step 2: Create the burn script**

```bash
#!/usr/bin/env bash
# scripts/demo_video/burn_captions.sh
# Burn captions.srt into demo_silent.mp4 -> demo_silent_with_captions.mp4
set -euo pipefail

OUT_DIR="$(cd "$(dirname "$0")/../.." && pwd)/out/demo_video"
cd "$OUT_DIR"

if [ ! -f demo_silent.mp4 ]; then echo "missing demo_silent.mp4"; exit 1; fi
if [ ! -f captions.srt ]; then echo "missing captions.srt"; exit 1; fi

# Caption styling: white text, semi-transparent black box, IBM Plex Sans, 24pt,
# anchored to the lower third (alignment 2 + margin V=80).
ffmpeg -y -i demo_silent.mp4 -vf \
  "subtitles=captions.srt:force_style='Fontname=IBM Plex Sans,Fontsize=24,PrimaryColour=&H00FFFFFF,BackColour=&H80000000,BorderStyle=4,Outline=2,Shadow=0,Alignment=2,MarginV=80'" \
  -c:a copy demo_silent_with_captions.mp4

ffprobe -v quiet -show_entries format=duration -of csv=p=0 demo_silent_with_captions.mp4
```

- [ ] **Step 3: Run the burn**

```
chmod +x scripts/demo_video/burn_captions.sh
bash scripts/demo_video/burn_captions.sh
```

Expected: produces `out/demo_video/demo_silent_with_captions.mp4`. ffprobe duration should still be ~300s.

- [ ] **Step 4: Visual verify**

Open `demo_silent_with_captions.mp4`. Scrub to 0:02, 0:30, 1:30, 3:30, 4:30. Each timestamp should show a readable caption line that does not cover the dashboard's top nav or rule-card kind badges.

- [ ] **Step 5: Commit**

```
git add scripts/demo_video/burn_captions.sh
git commit -m "demo_video: burn captions into silent video (Phase D)"
```

---

## Task 11: Phase D.5 review gate (manual; halt for Charan signoff)

**Files:**
- None (manual review)

- [ ] **Step 1: Hand off the silent-with-captions cut**

Tell Charan: "Open `out/demo_video/demo_silent_with_captions.mp4` and watch end-to-end with the speakers off. The captions alone should carry the story. If anything is off, name the beat and the issue."

- [ ] **Step 2: Wait for explicit signoff**

Do NOT advance to Phase E (voice generation) without an explicit "approved, generate voice" or equivalent.

- [ ] **Step 3: If changes requested**

Identify which beat is affected. Update either the scene script (Tasks 4-8) or the voiceover text in `scripts/demo_video/captions.py` (Task 2). Re-record that beat only. Re-run Tasks 9 and 10. Re-present at Step 1.

---

## Task 12: ElevenLabs voice generation (the only paid step)

**Files:**
- Create: `scripts/demo_video/voice_gen.py`

Requires `ELEVENLABS_API_KEY` and `ELEVENLABS_VOICE_ID` env vars set. Voice clone ID lives in Charan's ElevenLabs account.

- [ ] **Step 1: Implement voice gen wrapper**

```python
# scripts/demo_video/voice_gen.py
"""Generate ElevenLabs voice for each beat. One MP3 per beat. Run AFTER
Phase D.5 review-gate signoff. This is the only paid step in the pipeline.

Env vars required:
    ELEVENLABS_API_KEY       Charan's ElevenLabs API key
    ELEVENLABS_VOICE_ID      Charan's voice clone ID

Usage:
    python -m scripts.demo_video.voice_gen           # all beats
    python -m scripts.demo_video.voice_gen beat1_open  # one beat
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import urllib.request
import urllib.error

from .captions import BEATS
from .config import OUT_DIR


API_URL_TEMPLATE = "https://api.elevenlabs.io/v1/text-to-speech/{voice_id}"


def _generate_one(api_key: str, voice_id: str, voiceover: str, out_path: Path) -> None:
    body = {
        "text": voiceover,
        "model_id": "eleven_multilingual_v2",
        "voice_settings": {"stability": 0.5, "similarity_boost": 0.75},
    }
    import json
    req = urllib.request.Request(
        API_URL_TEMPLATE.format(voice_id=voice_id),
        method="POST",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "xi-api-key": api_key,
            "content-type": "application/json",
            "accept": "audio/mpeg",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        out_path.write_bytes(resp.read())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("beat", nargs="?", help="beat name; omit to generate all")
    args = ap.parse_args()
    api_key = os.environ.get("ELEVENLABS_API_KEY")
    voice_id = os.environ.get("ELEVENLABS_VOICE_ID")
    if not api_key or not voice_id:
        print("ELEVENLABS_API_KEY and ELEVENLABS_VOICE_ID env vars required", file=sys.stderr)
        return 2
    selected = [b for b in BEATS if (args.beat is None or b["name"] == args.beat)]
    if not selected:
        print(f"unknown beat {args.beat!r}", file=sys.stderr)
        return 1
    for b in selected:
        out_path = OUT_DIR / f"voice_{b['name']}.mp3"
        if out_path.exists():
            print(f"skip {b['name']} (already exists at {out_path}); delete to regenerate")
            continue
        print(f"generating {b['name']} -> {out_path}")
        _generate_one(api_key, voice_id, b["voiceover"], out_path)
        print(f"  wrote {out_path.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Probe one beat first (cheapest fail-fast)**

```
$env:ELEVENLABS_API_KEY="<paste-from-charan>"
$env:ELEVENLABS_VOICE_ID="<paste-from-charan>"
python -m scripts.demo_video.voice_gen beat5_outro
ffprobe -v quiet -show_entries format=duration -of csv=p=0 out/demo_video/voice_beat5_outro.mp3
```

Expected: produces `voice_beat5_outro.mp3` of length under or close to 15 seconds. Listen to confirm voice clone is correct.

- [ ] **Step 3: If voice runs over the beat slot**

Edit the voiceover text in `scripts/demo_video/captions.py` to be shorter; re-run captions Task 10 (regenerate SRT, re-burn captions); re-run Phase D.5 if the captions changed in a way that affects timing; only then re-generate that one beat.

- [ ] **Step 4: Generate remaining beats**

```
python -m scripts.demo_video.voice_gen
```

Expected: 8 sub-beat MP3s in `out/demo_video/voice_*.mp3` (note: BEATS has 8 entries because beat3 is split into 4 sub-beats).

- [ ] **Step 5: Commit (script only; audio files are gitignored)**

```
git add scripts/demo_video/voice_gen.py
git commit -m "demo_video: ElevenLabs voice gen wrapper"
```

---

## Task 13: Final assembly + export (Phase F)

**Files:**
- Create: `scripts/demo_video/assemble_final.sh`

- [ ] **Step 1: Create the final-assembly script**

```bash
#!/usr/bin/env bash
# scripts/demo_video/assemble_final.sh
# Concatenate beat audio files in spec order, then mux against the
# captions-burned silent video. Output: out/demo_video/final.mp4
set -euo pipefail

OUT_DIR="$(cd "$(dirname "$0")/../.." && pwd)/out/demo_video"
cd "$OUT_DIR"

if [ ! -f demo_silent_with_captions.mp4 ]; then
  echo "missing demo_silent_with_captions.mp4 (Phase D output)"
  exit 1
fi

# Build the audio track. BEATS order from captions.py.
LIST=audio_concat.txt
> "$LIST"
for beat in beat1_open beat2_architecture beat3a_findings beat3b_audit beat3c_critic beat3d_corroboration beat4_loop beat5_outro; do
  f="voice_${beat}.mp3"
  if [ ! -f "$f" ]; then echo "missing $f"; exit 1; fi
  echo "file '$f'" >> "$LIST"
done

ffmpeg -y -f concat -safe 0 -i "$LIST" -c copy audio_track.mp3
rm "$LIST"

# Mux. Use -shortest so the output stops at video end (300s).
ffmpeg -y -i demo_silent_with_captions.mp4 -i audio_track.mp3 \
  -c:v copy -c:a aac -b:a 192k -shortest final.mp4

ffprobe -v quiet -show_entries format=duration -of csv=p=0 final.mp4
ls -lh final.mp4
```

- [ ] **Step 2: Run final assembly**

```
chmod +x scripts/demo_video/assemble_final.sh
bash scripts/demo_video/assemble_final.sh
```

Expected: produces `out/demo_video/final.mp4` at ~300 seconds. File size should be 30-100 MB at 1080p H.264. Open and watch end-to-end.

- [ ] **Step 3: Final visual verify**

Open `final.mp4`. Watch from 0:00 to 5:00. Verify: visuals match captions match voiceover at every beat boundary; no audio gaps; end-card holds for the full 15 seconds; YouTube upload-ready.

- [ ] **Step 4: Commit**

```
git add scripts/demo_video/assemble_final.sh
git commit -m "demo_video: Phase F final assembly + export"
```

---

## Task 14: Upload + paste URL into Devpost description

**Files:**
- Modify: `docs/submission/devpost-description.md`

- [ ] **Step 1: Upload final.mp4 to YouTube as Unlisted**

Manual step: upload `out/demo_video/final.mp4` via YouTube Studio. Set visibility to Unlisted. Title: "Sift Sentinel - SANS Find Evil hackathon demo (5 min)". Description: link to sentinel.sshub.dev and GitHub.

- [ ] **Step 2: Paste the URL into devpost-description.md under the Demo Video field**

Edit `docs/submission/devpost-description.md`. Find the "Demo Video" section. Add the YouTube URL.

- [ ] **Step 3: Commit**

```
git add docs/submission/devpost-description.md
git commit -m "submission: paste demo video URL into Devpost description"
```

- [ ] **Step 4: Push everything to origin**

```
git push origin main
```

---

## Self-review summary

**Spec coverage:**
- 5 beats with locked timings: Tasks 4 (beat1), 5 (beat2), 6 (beat3 covers 3a/3b/3c/3d as one recording), 7 (beat4), 8 (beat5).
- Phase A pre-record probes: Task 3.
- Phase B per-beat silent recording: Tasks 4-8.
- Phase C silent assembly + timing: Task 9.
- Phase D captions + burn: Task 10.
- Phase D.5 review gate: Task 11 (manual halt).
- Phase E voice generation: Task 12.
- Phase F final assembly + export: Task 13.
- Submission upload: Task 14.

**Placeholder scan:** the only "user supplies value" item is `ELEVENLABS_API_KEY` + `ELEVENLABS_VOICE_ID` env vars in Task 12, which is correct (those are secrets that must come from Charan, not the plan).

**Type / signature consistency:** `BEATS` list in `captions.py` is consumed by `voice_gen.py` and `assemble_final.sh` with the same order and beat names. `OUT_DIR` from `config.py` is the only output path used across all tasks. `RULE_ID_FOR_PROMOTE` from `config.py` is the only mutable element; Task 7 Step 2 explicitly re-checks it before recording.

**Out of scope (per spec):** live terminal demo, code walkthrough segment, founder-on-camera, architecture diagram redesign. Confirmed not in any task.
