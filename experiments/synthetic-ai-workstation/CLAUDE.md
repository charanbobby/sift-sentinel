# Context for Claude Code sessions in this directory

## What this project is

This directory is part of a submission for the **SANS Open-Source Intelligence & Forensics Hackathon (2026)**. The competition challenges participants to build autonomous AI-assisted DFIR (digital forensics and incident response) pipelines.

## What the research agent does

`research.py` calls Claude Code (via `-p`) to pull current threat intelligence and produce a **JSON manifest of synthetic forensic test fixtures**. These fixtures are:

- Written as files and registry keys into a **synthetic NTFS disk image** inside a Docker container
- Never executed on any real Windows system
- Used exclusively to measure the detection pipeline's precision and recall
- Structurally equivalent to the technique libraries in MITRE ATT&CK Evaluations, Atomic Red Team, and MITRE Caldera

The pipeline then runs the same forensics agent against the planted disk, and a score script compares detections against the manifest's `expected_detection` field. This is the "daily self-healing loop" architecture described in the hackathon project.

## Artifact content rules

All `file_drop` scripts in the manifest use:
- `example.invalid` domains (RFC 2606, non-resolvable by design)
- `ALLCAPS_PLACEHOLDER` tokens for API credentials
- No live endpoints, no real C2 infrastructure

These rules are enforced both in the schema validation and in the prompt. A PowerShell script that calls `https://EXFIL-ENDPOINT.example.invalid/infer` is a **static test fixture** for testing whether the forensics pipeline detects credential-theft patterns. It is not a working exploit.

## Authorization

This is the author's own research pipeline running on a private Hetzner VPS (`/opt/find-evil/`). The Docker containers are owned by the same user (`sri`). Evidence images are legally acquired SANS training datasets. The only "attack" surface is a controlled synthetic disk that is never booted or mounted outside the analysis container.

## Allowed tools for the research agent

When invoked via `research.py`, Claude should use `WebSearch` and `WebFetch` to ground manifests in recent threat intelligence. Both tools are explicitly allowed for this use case.
