# Docker Commands — Find Evil Hackathon

Canonical cheat sheet for driving the compose stack yourself.

**All commands run from the project root** (`d:/Python Applications/Find Evil - Hackathon`) using the `-f` flag, so you never have to `cd` into `docker/`.

```bash
# Short alias (paste into your shell profile if you want):
#   alias fe='docker compose -f "d:/Python Applications/Find Evil - Hackathon/docker/docker-compose.yaml"'
```

---

## Daily driving

| Action | Command |
|---|---|
| Bring stack up (build if needed) | `docker compose -f docker/docker-compose.yaml up -d --build` |
| Bring stack up (no rebuild) | `docker compose -f docker/docker-compose.yaml up -d` |
| Status | `docker compose -f docker/docker-compose.yaml ps` |
| Stop (keep containers) | `docker compose -f docker/docker-compose.yaml stop` |
| Stop + remove containers (keep volumes) | `docker compose -f docker/docker-compose.yaml down` |
| Stop + remove containers AND `sift-home` volume (nuke) | `docker compose -f docker/docker-compose.yaml down -v` |
| Rebuild just notebook image | `docker compose -f docker/docker-compose.yaml build notebook` |
| Rebuild + replace running notebook | `docker compose -f docker/docker-compose.yaml up -d --build notebook` |
| Rebuild just sift image (after `docker/sift/Dockerfile` edits) | `docker compose -f docker/docker-compose.yaml build sift` |
| Rebuild + replace running sift | `docker compose -f docker/docker-compose.yaml up -d --build sift` |

---

## Watching

| Action | Command |
|---|---|
| Follow notebook logs | `docker logs -f find-evil-notebook` |
| Follow sift logs | `docker logs -f sift` |
| Notebook startup progress (uv sync + jupyter) | `docker logs find-evil-notebook --tail 40` |

---

## Shelling in

| Action | Command |
|---|---|
| Shell into sift as forensics user | `docker exec -it --user sansforensics sift bash` |
| Shell into notebook (root, dev) | `docker exec -it find-evil-notebook bash` |
| Test MCP bridge (notebook → sift) | `docker exec find-evil-notebook docker exec --user sansforensics sift fsstat -V` |

---

## Endpoints

| What | Where |
|---|---|
| Jupyter Lab | http://localhost:8888 (no token — dev only) |
| Langfuse | https://us.cloud.langfuse.com (note: US region) |

---

## First-time setup

1. Copy `docker/.env.example` → `docker/.env`, fill in real keys.
2. `docker compose -f docker/docker-compose.yaml up -d --build`
3. Wait ~60s for `uv sync` to pull Jupyter deps on first run.
4. Verify: `docker logs find-evil-notebook --tail 10` should show `Jupyter Server ... is running at`.
5. Open http://localhost:8888.

## Sift image — MCP deps baked in via Dockerfile

The sift base image (`digitalsleuth/sift-docker:jammy`) doesn't ship the Python MCP SDK, so we extend it. See `docker/sift/Dockerfile` — it adds `uv` and installs `mcp` + `pydantic` into system Python at **build time**. No runtime bootstrap, no volume-persisted `~/.local` workaround.

```bash
# After editing docker/sift/Dockerfile:
docker compose -f docker/docker-compose.yaml build sift
docker compose -f docker/docker-compose.yaml up -d sift

# Sanity check — server.py deps import cleanly
docker exec --user sansforensics sift python3 -c "from mcp.server.fastmcp import FastMCP; import pydantic; print('mcp OK, pydantic', pydantic.__version__)"
```

---

## Troubleshooting

| Symptom | Check |
|---|---|
| Jupyter returns empty reply / connection refused | `uv sync` still running on first boot. Tail the logs. |
| Bridge test `docker: executable not found` | Notebook image built before the `bookworm` pin. Rebuild: `docker compose ... build --no-cache notebook && docker compose ... up -d notebook` |
| `docker.sock` permission denied from notebook | Docker Desktop not running, or socket not mounted. Check `docker compose ... config` for the volume line. |
| Sift container unhealthy after restart | `docker compose ... restart sift` |
| Evidence path empty inside sift | `D:/Python Applications/Find Evil - Hackathon/HACKATHON-2026` missing on host — check the bind mount source path. |
