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

    # -- beat2_architecture (45s, 9 phrases) -----------------------------------
    {"beat": "beat2_architecture", "text": "Sentinel runs the autonomous incident response loop", "duration_s": 4.5, "selector": "h2:has-text('Five trust controls')"},
    {"beat": "beat2_architecture", "text": "with three architectural guardrails, not just prompt promises.", "duration_s": 4.5, "selector": None},
    {"beat": "beat2_architecture", "text": "First: every tool call crosses a capability-token boundary at the MCP server,", "duration_s": 6.0, "selector": "h3:has-text('Execution boundary')"},
    {"beat": "beat2_architecture", "text": "scoped to the case ID and the allowed paths.", "duration_s": 4.0, "selector": "h2:has-text('Execution boundary deep dive')"},
    {"beat": "beat2_architecture", "text": "Second: an injection scanner sits in the Critic", "duration_s": 5.0, "selector": "h3:has-text('Defender AI integrity')"},
    {"beat": "beat2_architecture", "text": "and quarantines tool output that looks adversarial.", "duration_s": 4.5, "selector": "h2:has-text('Defender AI integrity deep dive')"},
    {"beat": "beat2_architecture", "text": "Third: every step of every run is hash-chained into an integrity ledger,", "duration_s": 5.5, "selector": "h2:has-text('Integrity deep dive')"},
    {"beat": "beat2_architecture", "text": "so a finding can be traced back to the exact tool execution that produced it.", "duration_s": 5.5, "selector": ".external-ledger"},
    {"beat": "beat2_architecture", "text": "The critic and the learn nodes are where the autonomy lives.", "duration_s": 5.5, "selector": "h3:has-text('Deterministic checks')"},

    # -- beat3_case (180s, 34 phrases across 4 sub-beats) ---------------------
    # 3a findings overview (32s, 6 phrases)
    {"beat": "beat3_case", "text": "The case: a Windows server from a 2018 enterprise compromise.", "duration_s": 5.0, "selector": ".case-header:has-text('srl-2018-base-rd-02-dual')"},
    {"beat": "beat3_case", "text": "The agent ran in dual-channel mode,", "duration_s": 3.5, "selector": ".channel-pill.channel-dual"},
    {"beat": "beat3_case", "text": "looking at both the disk image and a memory snapshot in the same run.", "duration_s": 6.0, "selector": None},
    {"beat": "beat3_case", "text": "The first finding is a Windows service called Microsoft Advanced API thirty-two,", "duration_s": 6.0, "selector": ".finding-mech"},
    {"beat": "beat3_case", "text": "set to auto-start, running a binary called msadvapi2_32.exe out of Program Files.", "duration_s": 7.0, "selector": ".finding-value"},
    {"beat": "beat3_case", "text": "That product does not exist. The agent flagged it with high confidence.", "duration_s": 4.5, "selector": ".finding-meta-row"},

    # 3b audit trail (50s, 10 phrases)
    {"beat": "beat3_case", "text": "Every finding is a citation.", "duration_s": 3.0, "selector": ".finding-evidence-row"},
    {"beat": "beat3_case", "text": "Click the citation and you reach the actual tool output that produced it.", "duration_s": 7.0, "selector": "[data-tab='evidence']"},
    {"beat": "beat3_case", "text": "Here is the RegRipper services dump where the service was registered.", "duration_s": 7.0, "selector": ".ev-record"},
    {"beat": "beat3_case", "text": "ImagePath, type, start mode, all there.", "duration_s": 4.0, "selector": ".ev-fields"},
    {"beat": "beat3_case", "text": "Click the second citation, and you are in the memory-side pslist.", "duration_s": 5.5, "selector": ".ev-tool"},
    {"beat": "beat3_case", "text": "The same binary is running right now at PID 2292.", "duration_s": 4.5, "selector": None},
    {"beat": "beat3_case", "text": "Disk says it should be running. Memory confirms it is running.", "duration_s": 5.5, "selector": None},
    {"beat": "beat3_case", "text": "That is what dual-channel means here.", "duration_s": 4.0, "selector": ".channel-pill.channel-dual"},
    {"beat": "beat3_case", "text": "Both services installed within eighteen seconds on May eighth, 2018.", "duration_s": 5.5, "selector": None},
    {"beat": "beat3_case", "text": "One attacker installation event, not two unrelated services.", "duration_s": 4.0, "selector": None},

    # 3c critic disagreement (57.5s, 11 phrases)
    {"beat": "beat3_case", "text": "Now the self-correction.", "duration_s": 3.0, "selector": "[data-tab='pipeline']"},
    {"beat": "beat3_case", "text": "While the agent was producing findings,", "duration_s": 3.5, "selector": None},
    {"beat": "beat3_case", "text": "the critic noticed something in one of the tool outputs.", "duration_s": 7.0, "selector": ".phase-critic-row"},
    {"beat": "beat3_case", "text": "A byte sequence in the raw registry hive contained the substring T1033,", "duration_s": 6.5, "selector": ".badge.badge-quarantine"},
    {"beat": "beat3_case", "text": "matching a pattern the injection scanner uses to detect adversarial prompt content.", "duration_s": 8.5, "selector": ".phase-critic-row.escalate"},
    {"beat": "beat3_case", "text": "It was random binary noise, not a real injection.", "duration_s": 4.5, "selector": None},
    {"beat": "beat3_case", "text": "But the agent did not silently dismiss it.", "duration_s": 4.0, "selector": None},
    {"beat": "beat3_case", "text": "It quarantined the tool output, escalated to human review,", "duration_s": 7.5, "selector": ".phase-critic-row.escalate"},
    {"beat": "beat3_case", "text": "and refused to act on findings that depended on it.", "duration_s": 4.5, "selector": None},
    {"beat": "beat3_case", "text": "Three findings escalated. None silently approved.", "duration_s": 4.5, "selector": None},
    {"beat": "beat3_case", "text": "That is what auditable autonomy looks like.", "duration_s": 4.0, "selector": None},

    # 3d cross-host (40.5s, 7 phrases) - beat 3 total: 32 + 50 + 57.5 + 40.5 = 180s
    {"beat": "beat3_case", "text": "One more thing.", "duration_s": 2.0, "selector": ".case-header:has-text('srl-2018-base-file')"},
    {"beat": "beat3_case", "text": "The agent ran on the file server in the same network,", "duration_s": 5.0, "selector": ".case-header:has-text('srl-2018-base-file') .case-header-name"},
    {"beat": "beat3_case", "text": "in a separate session, with no shared state.", "duration_s": 6.0, "selector": None},
    {"beat": "beat3_case", "text": "It found the same msadvapi2 kit.", "duration_s": 4.0, "selector": ".finding.cls-attacker_persistence:has-text('msadvapi2')"},
    {"beat": "beat3_case", "text": "Same fake Microsoft naming pattern, same paired thirty-two and sixty-four bit service.", "duration_s": 9.5, "selector": ".finding.cls-attacker_persistence:has-text('msadvapi2') .finding-value"},
    {"beat": "beat3_case", "text": "That cross-host signal was not engineered. The agent reached it independently on each host.", "duration_s": 8.0, "selector": None},
    {"beat": "beat3_case", "text": "The corroboration emerges from the data, not from a heuristic.", "duration_s": 6.0, "selector": None},

    # -- beat4_loop (45s, 9 phrases) ------------------------------------------
    {"beat": "beat4_loop", "text": "And the loop closes here.", "duration_s": 3.0, "selector": "#section-rules h2"},
    {"beat": "beat4_loop", "text": "Every night, the cron at 22:30 UTC runs the agent against fresh threat intel.", "duration_s": 6.5, "selector": "#widget-input"},
    {"beat": "beat4_loop", "text": "When it misses something, a drafter agent synthesizes a candidate rule.", "duration_s": 6.0, "selector": "#widget-queued"},
    {"beat": "beat4_loop", "text": "Today, twelve rules are waiting.", "duration_s": 3.5, "selector": "#widget-queued #w-queued-num"},
    {"beat": "beat4_loop", "text": "I read one, decide it is safe, click approve.", "duration_s": 5.0, "selector": "#rule-card-lnk_ntlm_coercion_folder_trigger-58245f5aa9"},
    {"beat": "beat4_loop", "text": "The rule is now in the live agent's rule store.", "duration_s": 5.0, "selector": "#widget-live"},
    {"beat": "beat4_loop", "text": "Tomorrow night's run picks it up automatically.", "duration_s": 5.0, "selector": None},
    {"beat": "beat4_loop", "text": "This is not a demo, this is the production system.", "duration_s": 5.0, "selector": None},
    {"beat": "beat4_loop", "text": "The whole loop runs on the same dashboard you are watching.", "duration_s": 6.0, "selector": None},

    # -- beat5_outro (15s, 4 phrases) -----------------------------------------
    {"beat": "beat5_outro", "text": "Sift Sentinel.", "duration_s": 2.0, "selector": ".name"},
    {"beat": "beat5_outro", "text": "Live at sentinel.sshub.dev.", "duration_s": 3.5, "selector": ".row:has-text('sentinel.sshub.dev') .v"},
    {"beat": "beat5_outro", "text": "Code on GitHub at github.com/charanbobby/sift-sentinel.", "duration_s": 5.5, "selector": ".row:has-text('github.com') .v"},
    {"beat": "beat5_outro", "text": "Built by Charan Bobby for the SANS Find Evil hackathon. Thanks for watching.", "duration_s": 4.0, "selector": ".row:has-text('Charan Bobby') .v"},
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
