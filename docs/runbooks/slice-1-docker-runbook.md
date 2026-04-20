# Slice 1 Runbook (Docker) — Stack Proof

**Goal:** SIFT + Protocol SIFT + Claude Code running in a Docker container; one smoke test against a real disk image succeeds.

**Why Docker, not the SIFT VM?** On Windows 11 with WSL2 + Docker Desktop already active, Hyper-V owns the virtualization extensions. VirtualBox falls back to software emulation (10–50× slower). Docker uses Hyper-V natively → native speed. See `docs/planning/PLAN.md` Key Decisions for the full rationale.

**Canonical record:** tick boxes as you go. Chat instructions disappear; this file is the source of truth.

**Context primer:** [concepts.md](../planning/concepts.md) covers host vs. container vs. E01 if any term is unclear. The *host ↔ container* mental model is identical to *host ↔ VM* — just a different virtualization technology.

---

## Prereqs

- [x] Docker Desktop running (check tray icon — whale must be steady, not animating)
- [x] Docker Desktop set to WSL2 backend (Settings → General → "Use WSL 2 based engine")
- [x] Internet access from host
- [ ] Anthropic API key ready (Claude Code prompts on first launch — still required in Step 7)

Verify Docker is healthy from Windows terminal:

```bash
docker version
docker info
```

- [x] `docker version` prints client + server versions (Docker Desktop 4.69.0, Engine 29.4.0, WSL2 kernel 6.6.87.2)
- [x] `docker info` shows `Server Version` and no errors

---

## Step 1 — Project compose file

Already created at [docker/docker-compose.yaml](../../docker/docker-compose.yaml). Skim it — key lines:

- Image: `digitalsleuth/sift-docker:jammy` (Ubuntu 22.04 + ~200 SIFT tools)
- Bind mount: `D:/Python Applications/Find Evil - Hackathon/HACKATHON-2026` → `/mnt/hackathon:ro`
- Named volume `sift-home` preserves `~/.claude/` and `~/cases/` across restarts

No edits needed unless you move the evidence folder.

### Verify Docker Desktop can read D:

Docker Desktop (WSL2 backend) shares all drives by default, but confirm:

- Docker Desktop → **Settings → Resources → File Sharing** — if there's an explicit list, `D:\` must be in it (WSL2 backend usually makes the list implicit).
- [x] File sharing configured for D: drive (evidence mounted successfully in Step 8)

---

## Step 2 — Pull and start the container

```bash
cd "/d/Python Applications/Find Evil - Hackathon/docker"
docker compose pull
docker compose up -d
```

First pull: the image is ~4 GB, one-time download. Took a few minutes on first run.

Check it's alive:

```bash
docker ps
docker compose logs --tail 50
```

- [x] `docker compose pull` completed — `digitalsleuth/sift-docker:jammy` cached
- [x] `docker compose up -d` started the container cleanly (network created, named volume created, container started)
- [x] `docker ps` shows `sift` `Up`
- [x] No errors in logs

### Container lifecycle (reference)

| Action | Command |
|---|---|
| Stop (keeps data, fast restart) | `docker compose stop` |
| Start again | `docker compose start` |
| Down (removes container, KEEPS named volume) | `docker compose down` |
| Nuke everything incl. `sift-home` volume | `docker compose down -v` ⚠️ wipes Protocol SIFT + cases |

---

## Step 3 — Exec into the container (always use `--user sansforensics`)

**Important gotcha.** `docker exec -it sift bash` lands you as **root** with `$HOME=/root/` — but our persisted named volume is mounted at `/home/sansforensics/`. Anything you write to `/root/` is lost on container recreation. Always use the `--user` flag:

```bash
docker exec -it --user sansforensics sift bash
```

You should land at `sansforensics@sift:/$`. From here forward, commands run **inside the container** unless noted.

- [x] Prompt reads `sansforensics@sift`, `$HOME=/home/sansforensics`
- [x] `~/.local/bin` added to `.bashrc` so `claude` is on PATH for future shells

Exit back to Windows shell with `exit` or Ctrl+D. The container keeps running.

---

## Step 4 — Smoke test SIFT tools are present

Inside the container:

```bash
which mmls fls volatility3 7z EvtxECmd 2>/dev/null
mmls 2>&1 | head -5
```

- [x] `mmls`, `fls`, `7z` all resolve at `/usr/bin/` (Sleuth Kit + 7zip installed)
- [x] `mmls` prints its usage banner
- [ ] `volatility3` and `EvtxECmd` not in image — install if/when a later slice needs them (not a Slice 1 blocker)

---

## Step 5 — Install Protocol SIFT inside container

**Gotcha — two runs required.** The installer first runs the Claude Code installer, which lands `claude` at `~/.local/bin/claude` but warns that `~/.local/bin` is not on PATH. Because of that PATH gap, the Protocol SIFT installer's own subsequent step (which checks for `claude`) fails silently and the script exits with code 1 before writing the skills/CLAUDE.md.

**Run it once to install Claude Code, then run it again with PATH set** to finish the Protocol SIFT part:

```bash
# First run — installs Claude Code, exits 1 without writing SIFT files
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash || true

# Second run — Claude Code now exists, installer writes CLAUDE.md + skills
export PATH=$HOME/.local/bin:$PATH
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash

# Persist PATH for future shells
grep -q ".local/bin" ~/.bashrc || echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc
```

All writes land in `~/.claude/` (persisted via the `sift-home` named volume).

- [x] First run installed Claude Code 2.1.112 at `~/.local/bin/claude`
- [x] Second run wrote `CLAUDE.md`, `settings.json`, 5 skills, case template, analysis script
- [x] `~/.local/bin` appended to `~/.bashrc`

---

## Step 6 — Verify Protocol SIFT install

```bash
ls -la ~/.claude/CLAUDE.md ~/.claude/settings.json
ls -la ~/.claude/skills/*/SKILL.md
claude --version
```

- [x] `CLAUDE.md` (3.5 KB) + `settings.json` (3.1 KB) present in `~/.claude/`
- [x] Five skills: `memory-analysis`, `plaso-timeline`, `sleuthkit`, `windows-artifacts`, `yara-hunting`
- [x] `claude --version` → `2.1.112 (Claude Code)`
- [x] `~/.claude/case-templates/CLAUDE.md` and `~/.claude/analysis-scripts/generate_pdf_report.py` also present

---

## Step 7 — Smoke test Claude Code (no evidence yet)

```bash
mkdir -p /tmp/test-case/{analysis,exports,reports}
cp ~/.claude/case-templates/CLAUDE.md /tmp/test-case/CLAUDE.md
cd /tmp/test-case && claude
```

Prompt:
> "What DFIR skills do you have loaded?"

- [ ] Claude lists the Protocol SIFT skills
- [ ] Exit with `/exit`

### Launching Claude Code in future sessions

```bash
# from Windows terminal:
docker exec -it sift bash
# then inside container:
cd ~/cases/<your-case-folder>     # or /tmp/test-case for no-case smoke
claude
```

Where you run `claude` matters:
- Inside a case folder → case's `CLAUDE.md` + global skills loaded.
- Random directory → only global skills, no case context.

---

## Step 8 — Verify evidence is visible

```bash
ls -la /mnt/hackathon/
find /mnt/hackathon -maxdepth 3 -type f 2>/dev/null
```

- [x] `ls` shows HACKATHON-2026 contents mounted as `/mnt/hackathon/`
- [x] Evidence files found (flattened layout — user didn't preserve Egnyte's nested folders):
  - `/mnt/hackathon/base-wkstn-05-cdrive.E01` — 14,809,873,122 B (~14.8 GB)
  - `/mnt/hackathon/base-wkstn-05-memory/base-wkstn-05-memory.img` — 3,221,225,472 B (~3 GB, **already extracted** from the `.7z`)
  - `/mnt/hackathon/base-wkstn-05-memory/base-wkstn-05-memory.md5` — 405 B (integrity hash for the memory)

### E01 forensic metadata (from `ewfinfo`)

- Case number: `20180905-001`
- Description: `base-wkstn-05 C-Drive`
- Examiner: Clint Barton
- Acquisition: 2018-09-07 via F-Response + FTK Imager (AD Imager 4.2)
- Source: Windows physical fixed disk, 29 GiB (61,886,464 × 512-byte sectors)
- MD5: `7542174a73f980db461103859b49371f`
- SHA1: `2e1190c1b433263efb79e97eede6dae2c3445a21`

> **F-Response quirk:** the image was captured as a **raw NTFS volume**, not a partitioned physical disk. `mmls` returns nothing (there's no MBR/GPT to parse); `fsstat` reads the NTFS directly. Noted — this shapes the Step 11 smoke-test prompt.

---

## Step 9 — Wire evidence into a case folder

Bytes stay on D: (read-only bind mount). Symlinks give canonical case paths.

```bash
mkdir -p ~/cases/srl-2018-wkstn-05/{analysis,exports,reports,evidence}
cd ~/cases/srl-2018-wkstn-05/evidence

# Paths match actual flattened layout from Step 8
ln -sf /mnt/hackathon/base-wkstn-05-cdrive.E01 .
ln -sf /mnt/hackathon/base-wkstn-05-memory/base-wkstn-05-memory.img .
ln -sf /mnt/hackathon/base-wkstn-05-memory/base-wkstn-05-memory.md5 .

cp ~/.claude/case-templates/CLAUDE.md ~/cases/srl-2018-wkstn-05/CLAUDE.md
```

Verify:

```bash
ls -la ~/cases/srl-2018-wkstn-05/evidence/
file ~/cases/srl-2018-wkstn-05/evidence/*
```

- [x] Case folder scaffolded — `analysis/`, `exports/`, `reports/`, `evidence/`, plus the per-case `CLAUDE.md`
- [x] All three symlinks resolve (`.E01`, `.img`, `.md5`)
- [x] `file` identifies each target correctly

---

## Step 10 — Extract memory dump ~~(skipped — already extracted on host)~~

- [x] **N/A** — the memory dump was already extracted on the host before mounting. `/mnt/hackathon/base-wkstn-05-memory/base-wkstn-05-memory.img` is ready (3 GB raw). MD5 hash file included for integrity verification later.

Retained for reference: if you ever need to extract a `.7z` inside the container, note that `/mnt/hackathon` is read-only, so extraction must land in `~/cases/<case>/evidence/` (writable named volume):

```bash
cd ~/cases/srl-2018-wkstn-05/evidence
7z x /path/to/some.7z -o.
```

---

## Step 11 — First real smoke test (interactive — requires your API key)

```bash
docker exec -it --user sansforensics sift bash
cd ~/cases/srl-2018-wkstn-05
claude
```

**Prompt (updated to leverage the F-Response quirk as a teaching moment):**
> "What type of filesystem is in `evidence/base-wkstn-05-cdrive.E01`, and what's its partition layout?"

The interesting behaviour to observe:
- A naïve agent runs `mmls`, gets nothing, and stops (wrong answer).
- A capable agent notices the empty output, tries a different tactic (`ewfinfo` metadata, `fsstat` directly on the E01), realises this is a volume-level acquisition (NTFS captured by F-Response without an MBR), and reports that.

Both behaviours prove the MCP chain works. The second one is the Slice 1 "this will be impressive by Slice 3" demo seed.

Success criteria:

- [x] Claude Code launches in the case folder, loads `~/.claude/CLAUDE.md` + `~/cases/srl-2018-wkstn-05/CLAUDE.md` + the five skills
- [x] Picks a Sleuth Kit tool from the `sleuthkit` skill (`fsstat` — correctly pivoting past empty `mmls` output)
- [x] Tool executes against the E01 (the `/dev/fuse` device + `privileged` + libewf chain works)
- [x] Reasons about the output in plain English (volume serial, sector/cluster counts, MFT layout — all matched ground-truth `ewfinfo`)
- [ ] **Capture the full session transcript** — Slice 1 demo material (use `/export` inside Claude Code, save under `~/cases/srl-2018-wkstn-05/reports/`)

**Slice 1 is done.** One MCP tool, one real artifact, one reasoned answer — plus an unplanned Slice 3 foreshadowing: the agent autonomously pivoted from `mmls` (empty) to `fsstat` (correct), which is exactly the self-correction loop we want to formalise in later slices.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `docker compose pull` fails: no matching manifest | Tag `jammy` moved | `docker search digitalsleuth/sift-docker` or swap tag to `latest` / `focal` in compose |
| `docker compose up` errors: "privileged not allowed" | Rootless Docker or corporate restriction | Switch Docker Desktop to rootful, or revisit in VM approach |
| `/mnt/hackathon/` empty inside container | D: not shared to Docker | Docker Desktop → Settings → Resources → File Sharing, add `D:\` |
| `mmls`/`fls` not found | Image flavor lacks Sleuth Kit | `sudo apt update && sudo apt install -y sleuthkit` inside container |
| `curl` fails during Protocol SIFT install | No egress / corporate proxy | `echo $http_proxy`; set proxy env or run from an unfiltered network |
| `claude: command not found` after install | PATH not reloaded | `source ~/.bashrc` or exit and re-exec |
| Claude API key rejected | Wrong key / no credit | Re-auth with `claude` and paste key from console.anthropic.com |
| `file` says symlink broken | Step 8 path didn't match Step 9 symlink target | Rebuild symlinks with exact `find` output |
| `7z x` fails: not enough space | Docker volume tight | `docker system df`; `docker system prune` to reclaim, or resize WSL2 VHDX |
| Container keeps restarting (`Restarting` in `docker ps`) | `privileged` or `/dev/fuse` rejected by kernel | Check Docker Desktop Settings → General → ensure "Virtualization framework" is set appropriately |

---

## Reference — paths quick card

| Location | Where |
|---|---|
| Compose file | `D:\Python Applications\Find Evil - Hackathon\docker\docker-compose.yaml` (host) |
| Evidence (read-only) | `/mnt/hackathon/...` (inside container) = `D:\...\HACKATHON-2026\...` (host) |
| Case folders | `~/cases/<case>/` (inside container, on `sift-home` volume) |
| Claude skills | `~/.claude/skills/` (inside container, on `sift-home` volume) |
| Into the container | `docker exec -it sift bash` (from Windows) |
| Stop / start | `docker compose stop` / `start` (from `docker/` folder on host) |

---

## Next

Once Step 11 is green: update [PLAN.md](../planning/PLAN.md) slice 1 to ✅ and open a Slice 2 runbook (Jupyter notebook prototype).
