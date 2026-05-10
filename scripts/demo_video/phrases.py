"""Phrase-level source of truth for the demo video.

Every phrase carries the text the narrator says, how long it takes to say it,
and the DOM element on screen during that phrase. Captions, voice generation,
and scene scripts all derive from this single list.

Spec: docs/superpowers/specs/2026-05-09-phrase-driven-demo-video-design.md
"""
from __future__ import annotations

PHRASES: list[dict] = [
    # -- beat1_open (15s, 3 phrases) ------------------------------------------
    {"beat": "beat1_open", "text": "Last night, an AI agent I built found a fake Microsoft service hiding on a real Windows server.", "duration_s": 6.0, "selector": None},
    {"beat": "beat1_open", "text": "Then it caught itself making a mistake on the next finding.", "duration_s": 4.5, "selector": None},
    {"beat": "beat1_open", "text": "Then it drafted a rule so it gets the next case right. Here is how.", "duration_s": 4.5, "selector": None},

    # -- beat2_architecture (60s, 12 phrases) ----------------------------------
    # Walks "Full deployment topology" panel: two containers, capability
    # token boundary, attack surface NONE, then how they are connected.
    {"beat": "beat2_architecture", "text": "Sentinel runs in two Docker containers.", "duration_s": 3.0, "selector": "h2:has-text('Full deployment topology')"},
    {"beat": "beat2_architecture", "text": "The agent process here, the forensic tools over here, separated by an internal Docker bridge.", "duration_s": 7.0, "selector": ".subtitle:has-text('streamable-HTTP')"},
    {"beat": "beat2_architecture", "text": "On the left, the agent process. The pipeline runner built on LangGraph.", "duration_s": 5.5, "selector": ".process-title:has-text('Agent process')"},
    {"beat": "beat2_architecture", "text": "On the right, the MCP server. This is what the agent actually calls when it needs a tool.", "duration_s": 6.5, "selector": ".process-title:has-text('MCP server')"},
    {"beat": "beat2_architecture", "text": "The agent container has no forensic tools installed, no Docker socket, no Docker CLI.", "duration_s": 6.5, "selector": ".pb-body:has-text('no forensic tools installed')"},
    {"beat": "beat2_architecture", "text": "Its attack surface, by design, is none.", "duration_s": 3.0, "selector": ".pb-body:has-text('no forensic tools installed')"},
    {"beat": "beat2_architecture", "text": "Every tool call crosses a bearer-token boundary first.", "duration_s": 4.5, "selector": ".pb-body:has-text('bearer-token middleware')"},
    {"beat": "beat2_architecture", "text": "Then a capability token, scoped to the case ID, plan digest, and allowed paths.", "duration_s": 6.5, "selector": ".pb-body:has-text('capability token scoped to')"},
    {"beat": "beat2_architecture", "text": "Below the topology: how the two are actually wired together.", "duration_s": 5.0, "selector": ".shared-label:has-text('how the two are connected')"},
    {"beat": "beat2_architecture", "text": "A shared Docker volume named sift-home holds extracted artifacts.", "duration_s": 5.5, "selector": ".mono-inline:has-text('sift-home')"},
    {"beat": "beat2_architecture", "text": "And the raw evidence bind-mounts in read-only, only on the tool side.", "duration_s": 5.0, "selector": ".mono-inline:has-text('/mnt/hackathon:ro')"},
    {"beat": "beat2_architecture", "text": "If a hijacked agent tried to reach the host filesystem, it cannot.", "duration_s": 4.0, "selector": ".pb-body:has-text('no forensic tools installed')"},
    # Pipeline phases walkthrough (12s, 3 phrases). The agent's runtime is
    # a six-phase pipeline; each phase has structured output the next consumes.
    {"beat": "beat2_architecture", "text": "Now, how the agent actually runs.", "duration_s": 3.0, "selector": "h2:has-text('The pipeline')"},
    {"beat": "beat2_architecture", "text": "Six phases: extract, plan, gates, execute, interpret, critic.", "duration_s": 6.0, "selector": ["div.name"]},
    {"beat": "beat2_architecture", "text": "Each phase produces structured output the next phase consumes.", "duration_s": 4.0, "selector": ["div.name"]},

    # -- beat3_case (153s, trimmed by 12s for Beat 2 pipeline walkthrough) ---
    # PRIMARY case: srl-2018-base-rd-01-dual (RDP server, dual channel)
    # 4 findings: scheduled-task persistence + p.exe injection + powershell injection + Outlook disambiguation
    # Plus an INJECTION_QUARANTINE event in the critic phase.
    # CROSS-HOST: srl-2018-base-file-dual - different persistence mechanism but
    # SAME C2 destination 172.16.4.10:8080. Independent agents, shared attacker
    # infrastructure detected across both hosts.

    # 3a findings overview (26s, 6 phrases)
    {"beat": "beat3_case", "text": "The case: an RDP server from a 2018 enterprise compromise.", "duration_s": 4.5, "selector": ".case-header:has-text('srl-2018-base-rd-01-dual')"},
    {"beat": "beat3_case", "text": "The agent ran in dual-channel mode,", "duration_s": 3.0, "selector": ".channel-pill.channel-dual"},
    {"beat": "beat3_case", "text": "looking at both the disk image and a memory snapshot in the same run.", "duration_s": 4.5, "selector": None},
    {"beat": "beat3_case", "text": "Four findings: a scheduled task, two injected processes, and a beacon to a remote address.", "duration_s": 7.0, "selector": [".finding"]},
    {"beat": "beat3_case", "text": "The agent also flagged Outlook for human review, because it could not tell if the memory regions were a plugin or an attack.", "duration_s": 7.5, "selector": [".finding.cls-requires_disambiguation"]},

    # 3b audit trail (43s, 9 phrases)
    {"beat": "beat3_case", "text": "Every finding is a citation.", "duration_s": 3.0, "selector": ".finding-evidence-row"},
    {"beat": "beat3_case", "text": "The persistence finding points at a scheduled task running a batch file from Windows Temp.", "duration_s": 6.0, "selector": [".finding.cls-attacker_persistence"]},
    {"beat": "beat3_case", "text": "Click the citation and you reach the actual tool output that produced it.", "duration_s": 5.0, "selector": "[data-tab='evidence']"},
    {"beat": "beat3_case", "text": "Here is the scheduled tasks dump showing the entry the agent flagged.", "duration_s": 5.0, "selector": ".ev-record:has-text('scheduled')"},
    {"beat": "beat3_case", "text": "Now the injection finding, in memory.", "duration_s": 4.0, "selector": ".ev-record:has-text('malfind')"},
    {"beat": "beat3_case", "text": "Powershell with multiple writable, executable memory regions and an empty command line. That combination does not happen in legitimate use.", "duration_s": 9.0, "selector": None},
    {"beat": "beat3_case", "text": "Disk found persistence, memory confirms the injected process running.", "duration_s": 5.5, "selector": ".channel-pill.channel-dual"},
    {"beat": "beat3_case", "text": "And the C2 beacon: an established connection to 172.16.4.10 on port 8080.", "duration_s": 7.0, "selector": [".finding.cls-c2_beacon"]},

    # 3c critic + self-correction (62s, 12 phrases). T1033 selectors point at
    # #quarantine-banner; viewer was changed to render the banner even when
    # the run as a whole is HUMAN_APPROVED (not just QUARANTINED).
    {"beat": "beat3_case", "text": "Now the self-correction.", "duration_s": 2.0, "selector": "[data-tab='pipeline']"},
    {"beat": "beat3_case", "text": "While the agent was producing findings,", "duration_s": 3.0, "selector": None},
    {"beat": "beat3_case", "text": "the injection scanner noticed something in one of the tool outputs.", "duration_s": 5.5, "selector": "#quarantine-banner"},
    {"beat": "beat3_case", "text": "A byte sequence in the raw registry hive contained the substring T1033,", "duration_s": 6.0, "selector": ".injection-excerpt"},
    {"beat": "beat3_case", "text": "matching one of the patterns the injection guard runs on every tool output.", "duration_s": 5.0, "selector": "#quarantine-banner"},
    {"beat": "beat3_case", "text": "It was random binary noise, not a real injection,", "duration_s": 4.5, "selector": None},
    {"beat": "beat3_case", "text": "but the agent quarantined that tool's output anyway, refusing to use it downstream.", "duration_s": 5.0, "selector": "#quarantine-banner"},
    {"beat": "beat3_case", "text": "Then on every finding the critic also runs sixteen quality rules.", "duration_s": 6.0, "selector": ".phase-critic-row .rules"},
    {"beat": "beat3_case", "text": "Did the excerpt match the raw output, is the confidence calibrated, is the cited tool in the approved plan.", "duration_s": 6.0, "selector": ".phase-critic-row .rules"},
    {"beat": "beat3_case", "text": "One of those rules catches attackers using AI themselves: tested by planting a local LLM on a synthetic Windows host.", "duration_s": 7.0, "selector": "#rule-R_16"},
    {"beat": "beat3_case", "text": "Its decisions are pass, retry, escalate, or human review.", "duration_s": 5.0, "selector": ".phase-critic-row.escalate"},
    {"beat": "beat3_case", "text": "Three findings escalated to me for approval, one held for disambiguation, none silently auto-approved. That is auditable autonomy.", "duration_s": 8.0, "selector": None},

    # 3d cross-host (34s, 6 phrases) - beat 3 total: 26.5 + 43.5 + 62 + 34 = 166s
    {"beat": "beat3_case", "text": "One more thing.", "duration_s": 2.0, "selector": ".case-header:has-text('srl-2018-base-file-dual')"},
    {"beat": "beat3_case", "text": "The agent ran on the file server in the same network, separate session, no shared state.", "duration_s": 7.0, "selector": ".case-header:has-text('srl-2018-base-file-dual') .case-header-name"},
    {"beat": "beat3_case", "text": "Different persistence mechanism: services masquerading as Microsoft Advanced API.", "duration_s": 6.5, "selector": [".finding.cls-attacker_persistence"]},
    {"beat": "beat3_case", "text": "But the same powershell injection pattern, and the same C2 destination at 172.16.4.10.", "duration_s": 7.5, "selector": [".finding.cls-c2_beacon"]},
    {"beat": "beat3_case", "text": "Two hosts, two different footholds, one shared attacker endpoint.", "duration_s": 5.5, "selector": None},
    {"beat": "beat3_case", "text": "The corroboration emerges from the data, not from a heuristic.", "duration_s": 5.5, "selector": None},

    # -- beat4_loop (57s, 11 phrases) -----------------------------------------
    # PLANT + HUNT phrases added so the loop is read-plant-hunt-score-learn,
    # not just read-then-learn. The plant + rerun step is the actual learning
    # mechanism and the differentiator vs "human approves what agent missed".
    {"beat": "beat4_loop", "text": "And the loop closes here.", "duration_s": 3.0, "selector": "#section-rules h2"},
    {"beat": "beat4_loop", "text": "Every night, the cron at 22:30 UTC reads fresh threat intel,", "duration_s": 6.0, "selector": "#widget-input #w-input-num"},
    {"beat": "beat4_loop", "text": "plants the new tradecraft on a synthetic Windows host,", "duration_s": 5.5, "selector": None},
    {"beat": "beat4_loop", "text": "then runs the agent against that planted host to see what it catches and what it misses.", "duration_s": 7.0, "selector": "#widget-result"},
    {"beat": "beat4_loop", "text": "When it misses something, a drafter agent synthesizes a candidate rule.", "duration_s": 6.0, "selector": "#widget-queued"},
    {"beat": "beat4_loop", "text": "Today, twelve rules are waiting.", "duration_s": 3.5, "selector": "#widget-queued #w-queued-num"},
    {"beat": "beat4_loop", "text": "I read one, decide it is safe, click approve.", "duration_s": 5.0, "selector": "[id^='rule-card-']"},
    {"beat": "beat4_loop", "text": "The rule is now in the live agent's rule store.", "duration_s": 5.0, "selector": "#widget-live"},
    {"beat": "beat4_loop", "text": "Tomorrow night's run picks it up automatically.", "duration_s": 5.0, "selector": None},
    {"beat": "beat4_loop", "text": "This is not a demo, this is the production system.", "duration_s": 5.0, "selector": None},
    {"beat": "beat4_loop", "text": "The whole loop runs on the same dashboard you are watching.", "duration_s": 6.0, "selector": None},

    # -- beat5_outro (14s, 4 phrases) -----------------------------------------
    # Final phrase tightened from the long credit to "Thanks for watching." -
    # the full attribution lives on the end card visually, no need to repeat it.
    {"beat": "beat5_outro", "text": "Sift Sentinel.", "duration_s": 2.0, "selector": ".name"},
    {"beat": "beat5_outro", "text": "Live at sentinel.sshub.dev.", "duration_s": 3.5, "selector": ".row:has-text('sentinel.sshub.dev') .v"},
    {"beat": "beat5_outro", "text": "Code on GitHub at github.com/charanbobby/sift-sentinel.", "duration_s": 5.5, "selector": ".row:has-text('github.com') .v"},
    {"beat": "beat5_outro", "text": "Thanks for watching.", "duration_s": 3.0, "selector": None},
]


BEAT_ORDER = ["beat1_open", "beat2_architecture", "beat3_case", "beat4_loop", "beat5_outro"]


def phrases_for(beat: str) -> list[dict]:
    """All phrases for a single beat, in order."""
    return [p for p in PHRASES if p["beat"] == beat]


def beat_total_seconds(beat: str) -> float:
    return sum(p["duration_s"] for p in phrases_for(beat))


# Sanity asserts at import time so a broken edit fails fast.
# Total is 329s (5:28) after 4 phrase budgets bumped to fit ElevenLabs
# voice at 1.0 speed (no voice re-bill, only visual budgets changed).
assert sum(p["duration_s"] for p in PHRASES) == 329.0, \
    f"PHRASES must total 329s, got {sum(p['duration_s'] for p in PHRASES)}"
for _b in BEAT_ORDER:
    _expected = {"beat1_open": 15, "beat2_architecture": 75, "beat3_case": 168, "beat4_loop": 57, "beat5_outro": 14}[_b]
    _actual = beat_total_seconds(_b)
    assert _actual == _expected, f"beat {_b} should sum to {_expected}s, got {_actual}"
