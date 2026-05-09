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
        raw = json.loads(body)
        # /viewer/api/cases returns either a plain list or {"cases": [...]}
        items = raw if isinstance(raw, list) else raw.get("cases", raw)
        case_ids = [c.get("case_id") if isinstance(c, dict) else c for c in items]
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
