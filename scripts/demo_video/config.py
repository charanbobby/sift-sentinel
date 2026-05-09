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
RULE_ID_FOR_PROMOTE = "lnk_ntlm_coercion_folder_trigger-58245f5aa9"

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
