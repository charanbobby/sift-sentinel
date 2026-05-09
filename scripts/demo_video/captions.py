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
