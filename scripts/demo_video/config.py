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

# Beat duration budget in seconds. Total is 325s (5:25); user accepted.
# 2026-05-10: Beat 4 grew to 57s with PLANT + HUNT phrases inserted so the
# learning loop reads as read-plant-hunt-score-learn, not the compressed
# read-then-learn that hid the synthetic-host re-run differentiator.
DURATIONS = {
    "beat1_open": 15,
    "beat2_architecture": 75,
    "beat3_case": 168,
    "beat4_loop": 57,
    "beat5_outro": 14,
}
assert sum(DURATIONS.values()) == 329, "beat durations must sum to 329 seconds"

OUT_DIR = Path(__file__).resolve().parents[2] / "out" / "demo_video"
OUT_DIR.mkdir(parents=True, exist_ok=True)
