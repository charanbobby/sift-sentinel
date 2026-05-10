"""Constants shared across all beat scenes and the assembler.

Locked from the spec at docs/superpowers/specs/2026-05-09-demo-video-script-design.md.
Change here, not in individual scene files.
"""
from pathlib import Path

SITE_URL = "https://sentinel.sshub.dev"
CASE_ID = "srl-2018-base-rd-01-dual"
RUN_ID = "srl-2018-base-rd-01-dual-003"
SECOND_CASE_ID = "srl-2018-base-file-dual"
SECOND_RUN_ID = "srl-2018-base-file-dual-001"
# Beat 4 picks the first currently-queued rule at runtime so this never goes
# stale (every recording promotes the previous pick, removing it from the queue).
RULE_ID_FOR_PROMOTE = None

VIEWPORT_WIDTH = 1920
VIEWPORT_HEIGHT = 1080
FRAMERATE = 30

# Beat duration budget in seconds. Total is 313s (5:13); user accepted up to 5:10 plus a small overage.
# 2026-05-10: Beat 3c expanded again to add an AI-USING attacker callout
# tied to R_16 (AI_ASSIST_ANCHOR_MISSING) plus a synthetic-validation note.
# Combined with the earlier T1033 + 16-rules expansion this is +13s vs the
# original 300s budget. TTS pace bumped to 1.25 in voice_gen.py.
DURATIONS = {
    "beat1_open": 15,
    "beat2_architecture": 72,
    "beat3_case": 166,
    "beat4_loop": 45,
    "beat5_outro": 15,
}
assert sum(DURATIONS.values()) == 313, "beat durations must sum to 313 seconds"

OUT_DIR = Path(__file__).resolve().parents[2] / "out" / "demo_video"
OUT_DIR.mkdir(parents=True, exist_ok=True)
