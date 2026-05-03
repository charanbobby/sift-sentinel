#!/usr/bin/env python3
"""scripts/cross_host_escalate.py

Cross-host C2 escalation aggregator (Option A from the wkstn-01 runbook).

Walks every dual-sweep run dir under a root. Builds a global destination
index from netscan evidence and INTERPRET findings. Flags hosts whose
network evidence contains a destination classified as c2_beacon by ANOTHER
host but locally graded lower (or not surfaced as a finding at all).

Goal: catch the wkstn-01-class FN where the agent saw the live C2 connection
but classified it as "requires_disambiguation" because it lacked sibling-host
context.

Output: a markdown report listing per-host escalations, the supporting
sibling hosts, and the original verdict.

Usage:
    scripts/cross_host_escalate.py
    scripts/cross_host_escalate.py --root experiments/slice-2-notebook/out/runs \\
                                    --match 'srl-2018-base-*-dual' \\
                                    --out docs/submission/cross-host-escalations-2026-05-02.md

Exit codes:
    0 = success (with or without escalations)
    1 = no run dirs matched
    2 = validation / IO error
"""
from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ROOT = REPO_ROOT / "experiments" / "slice-2-notebook" / "out" / "runs"
DEFAULT_MATCH = "srl-2018-base-*-dual"
DEFAULT_OUT = REPO_ROOT / "docs" / "submission" / "cross-host-escalations-2026-05-02.md"

# A connection record in netscan structured_fields. We pull the IPv4:port from
# foreign_address with a single regex. Lenient enough to catch quoted JSON
# fragments without a full json walk per line.
CONNECTION_RE = re.compile(
    r'"foreign_address"\s*:\s*"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<port>\d+)"'
    r'[^{}]*?"state"\s*:\s*"(?P<state>[A-Z_]+)"'
)
LOCAL_RE = re.compile(
    r'"local_address"\s*:\s*"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+"'
)

# Loopback + multicast + link-local + broadcast destinations are never C2.
# Used in is_external() to keep the destination index focused on real hosts.
INTERNAL_NOISE_PREFIXES = ("127.", "0.", "224.", "255.", "169.254.")


def is_external(ip: str) -> bool:
    """True if the IP is not loopback / multicast / link-local / broadcast."""
    return not ip.startswith(INTERNAL_NOISE_PREFIXES)


@dataclass
class HostObservations:
    """Everything we extract from a single dual-sweep run dir."""
    case_id: str
    run_dir: Path
    local_ips: set[str] = field(default_factory=set)
    # (foreign_ip, port) -> list of states observed
    foreign_destinations: dict[tuple[str, int], list[str]] = field(default_factory=dict)
    # all findings as dicts (parsed from 05_interpret_findings.json)
    findings: list[dict] = field(default_factory=list)
    # findings classified as c2_beacon, with their destination strings
    c2_findings: list[dict] = field(default_factory=list)


@dataclass
class Escalation:
    """A (host, destination) pair we want to escalate to HIGH c2_beacon."""
    case_id: str
    destination: tuple[str, int]
    states: list[str]
    has_established: bool
    sibling_hosts: list[str]
    local_finding_classification: str  # "(no finding)" if absent
    local_finding_confidence: str  # same
    local_finding_excerpt: str  # short string for the report


def extract_host_observations(run_dir: Path) -> HostObservations | None:
    """Build a HostObservations for a single canonical run dir.

    Returns None if the dir has no `05_interpret_findings.json` (incomplete /
    hung run; we cannot grade it).
    """
    findings_path = run_dir / "05_interpret_findings.json"
    evidence_path = run_dir / "04_execute_evidence.jsonl"
    if not findings_path.exists() or not evidence_path.exists():
        return None

    case_id = json.loads(findings_path.read_text(encoding="utf-8")).get("case_id", run_dir.parent.name)
    obs = HostObservations(case_id=case_id, run_dir=run_dir)

    # Findings
    findings_blob = json.loads(findings_path.read_text(encoding="utf-8"))
    obs.findings = findings_blob.get("findings", []) or []
    obs.c2_findings = [f for f in obs.findings if f.get("classification") == "c2_beacon"]

    # Netscan: regex-scan the evidence file. We do not need to parse every JSON
    # line because we only care about (foreign_ip, port, state) triples and
    # local IP discovery.
    text = evidence_path.read_text(encoding="utf-8", errors="replace")
    for m in CONNECTION_RE.finditer(text):
        ip = m.group("ip")
        if not is_external(ip):
            continue
        port = int(m.group("port"))
        state = m.group("state")
        obs.foreign_destinations.setdefault((ip, port), []).append(state)
    for m in LOCAL_RE.finditer(text):
        ip = m.group("ip")
        if is_external(ip):
            obs.local_ips.add(ip)

    return obs


def find_canonical_run_dirs(root: Path, match: str) -> list[Path]:
    """For every <root>/<case_id> dir whose name matches `match`, resolve the
    canonical run subdir from latest.txt. Skip dirs without latest.txt or
    where latest.txt points at a missing subdir.
    """
    if not root.exists():
        return []
    out = []
    for case_dir in sorted(root.iterdir()):
        if not case_dir.is_dir():
            continue
        if not fnmatch.fnmatch(case_dir.name, match):
            continue
        latest_file = case_dir / "latest.txt"
        if not latest_file.exists():
            continue
        sub = latest_file.read_text(encoding="utf-8").strip()
        run_dir = case_dir / sub
        if run_dir.exists():
            out.append(run_dir)
    return out


def find_c2_destinations(per_host: list[HostObservations]) -> dict[tuple[str, int], list[str]]:
    """Build a (ip, port) -> [supporting_case_ids] index of destinations that
    at least one host classifies as c2_beacon. The supporting list is the set
    of hosts whose c2_finding mentions this destination.
    """
    idx: dict[tuple[str, int], set[str]] = defaultdict(set)
    for obs in per_host:
        for f in obs.c2_findings:
            blob = (f.get("value", "") or "") + " " + (f.get("mechanism", "") or "")
            for m in re.finditer(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)", blob):
                ip = m.group(1)
                if not is_external(ip):
                    continue
                idx[(ip, int(m.group(2)))].add(obs.case_id)
    return {k: sorted(v) for k, v in idx.items()}


def _finding_mentions(finding: dict, dest: tuple[str, int]) -> bool:
    """True if a finding's value / mechanism / notes mentions the destination."""
    blob = " ".join(
        str(finding.get(k, "") or "")
        for k in ("value", "mechanism", "notes")
    )
    return f"{dest[0]}:{dest[1]}" in blob


def compute_escalations(
    per_host: list[HostObservations],
    c2_destinations: dict[tuple[str, int], list[str]],
) -> list[Escalation]:
    """For each host x destination pair, decide whether to escalate.

    Escalation criteria:
      - dest is in c2_destinations (at least one sibling host says c2_beacon)
      - host has netscan records to dest (so we have local evidence)
      - host's existing finding (if any) is NOT classified c2_beacon

    A sibling that is the c2-supporter for itself is excluded from the
    sibling_hosts list (no self-supporting escalations).
    """
    out: list[Escalation] = []
    for obs in per_host:
        for dest, states in obs.foreign_destinations.items():
            if dest not in c2_destinations:
                continue
            siblings = [h for h in c2_destinations[dest] if h != obs.case_id]
            if not siblings:
                continue
            # Find ALL local findings that mention this destination. If any of
            # them is already classified c2_beacon, the local host has already
            # called this correctly and no escalation is needed (regression-
            # safe even if a sibling finding also mentions the destination as
            # context).
            local_matches = [f for f in obs.findings if _finding_mentions(f, dest)]
            if any(f.get("classification") == "c2_beacon" for f in local_matches):
                continue
            # Otherwise, pick the first mentioning finding (if any) for the
            # report; its classification is what we are escalating away from.
            local_match = local_matches[0] if local_matches else None
            classification = (local_match or {}).get("classification", "(no finding)")
            confidence = (local_match or {}).get("confidence", "(no finding)")
            value = (local_match or {}).get("value", "(no local finding mentions this destination)")
            out.append(Escalation(
                case_id=obs.case_id,
                destination=dest,
                states=sorted(set(states)),
                has_established="ESTABLISHED" in states,
                sibling_hosts=siblings,
                local_finding_classification=classification,
                local_finding_confidence=confidence,
                local_finding_excerpt=value[:200],
            ))
    return out


def render_report(
    escalations: list[Escalation],
    per_host: list[HostObservations],
    c2_destinations: dict[tuple[str, int], list[str]],
    today: str,
) -> str:
    lines: list[str] = []
    lines.append(f"# Cross-host C2 escalations, {today}")
    lines.append("")
    lines.append("## TL;DR")
    lines.append("")
    lines.append(
        f"Cross-host aggregator scanned {len(per_host)} dual-sweep run dirs. "
        f"Built a global C2 destination index of {len(c2_destinations)} unique "
        f"(ip, port) pairs supported by at least one host's `c2_beacon` finding. "
        f"Flagged {len(escalations)} per-host escalations where local evidence "
        f"matches a known C2 destination but the local finding either does not "
        f"exist or is graded lower than `c2_beacon`."
    )
    lines.append("")

    lines.append("## Hosts scanned")
    lines.append("")
    lines.append("| Case | Local IPs | Findings | c2_beacon findings | Distinct foreign destinations |")
    lines.append("|---|---|---|---|---|")
    for obs in per_host:
        lines.append(
            f"| `{obs.case_id}` | {', '.join(sorted(obs.local_ips)) or '(none)'} "
            f"| {len(obs.findings)} | {len(obs.c2_findings)} "
            f"| {len(obs.foreign_destinations)} |"
        )
    lines.append("")

    lines.append("## Known C2 destinations (any host classified as c2_beacon)")
    lines.append("")
    if not c2_destinations:
        lines.append("_None._")
    else:
        lines.append("| Destination | Supporting hosts |")
        lines.append("|---|---|")
        for dest in sorted(c2_destinations.keys()):
            supporters = ", ".join(c2_destinations[dest])
            lines.append(f"| `{dest[0]}:{dest[1]}` | {supporters} |")
    lines.append("")

    lines.append("## Escalations")
    lines.append("")
    if not escalations:
        lines.append("_No escalations to report._")
    else:
        lines.append("| Case | Destination | States | ESTABLISHED? | Sibling hosts | Local classification | Local confidence |")
        lines.append("|---|---|---|---|---|---|---|")
        for e in escalations:
            lines.append(
                f"| `{e.case_id}` | `{e.destination[0]}:{e.destination[1]}` "
                f"| {', '.join(e.states)} "
                f"| {'YES' if e.has_established else 'no'} "
                f"| {', '.join(e.sibling_hosts)} "
                f"| {e.local_finding_classification} "
                f"| {e.local_finding_confidence} |"
            )
        lines.append("")
        lines.append("### Per-escalation detail")
        lines.append("")
        for e in escalations:
            lines.append(f"#### `{e.case_id}` -> `{e.destination[0]}:{e.destination[1]}`")
            lines.append("")
            lines.append(f"- States observed: {', '.join(e.states)}")
            lines.append(f"- Live at capture (ESTABLISHED present): {'YES' if e.has_established else 'no'}")
            lines.append(f"- Sibling hosts already classifying as c2_beacon: {', '.join(e.sibling_hosts)}")
            lines.append(f"- Local finding classification: `{e.local_finding_classification}`")
            lines.append(f"- Local finding confidence: `{e.local_finding_confidence}`")
            lines.append(f"- Local finding excerpt: `{e.local_finding_excerpt}`")
            lines.append("")
    lines.append("")
    lines.append("## How to apply this")
    lines.append("")
    lines.append(
        "For each escalation row, the local host's verdict should be promoted to "
        "HIGH `c2_beacon` (or at minimum to `requires_disambiguation` MEDIUM if the "
        "states are CLOSED only with no ESTABLISHED). Update the per-run `05_interpret_findings.json` "
        "by hand or, in the next pipeline rev, fold this aggregator's output into "
        "the INTERPRET prompt as a `--known-bad-destinations` list (Option B from "
        "the wkstn-01 runbook)."
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    p.add_argument("--match", default=DEFAULT_MATCH)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--today", default=None)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    today = args.today or _dt.datetime.utcnow().strftime("%Y-%m-%d")

    run_dirs = find_canonical_run_dirs(args.root, args.match)
    if not run_dirs:
        print(f"no run dirs matched {args.match} under {args.root}", file=sys.stderr)
        return 1

    per_host: list[HostObservations] = []
    for rd in run_dirs:
        obs = extract_host_observations(rd)
        if obs is None:
            if not args.quiet:
                print(f"  skip incomplete: {rd}", file=sys.stderr)
            continue
        per_host.append(obs)

    if not per_host:
        print("no completed runs found (none had both 04_execute_evidence.jsonl and 05_interpret_findings.json)", file=sys.stderr)
        return 1

    c2_destinations = find_c2_destinations(per_host)
    escalations = compute_escalations(per_host, c2_destinations)

    if not args.quiet:
        print(f"[aggregator] {len(per_host)} hosts scanned, {len(c2_destinations)} known C2 destinations, {len(escalations)} escalations", file=sys.stderr)

    report = render_report(escalations, per_host, c2_destinations, today)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    if not args.quiet:
        print(f"[aggregator] wrote {args.out}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
