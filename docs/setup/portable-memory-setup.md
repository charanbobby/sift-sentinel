# Portable Claude Code Memory — via Junction from C:\ to D:\

**Goal:** Claude Code's per-project memory files live on the portable D:\ drive instead of C:\, so they travel with the drive across computers.

**Mechanism:** Windows directory junction (`mklink /J`). The C:\ path Claude Code expects still works — it's just an alias that resolves to the real folder on D:\. No admin privileges required.

**Why not just commit the memory folder:** memory files are explicitly designed as "point-in-time observations" that decay — committing them freezes stale notes. The durable cross-machine substrate is `SKILL.md` + committed docs. This setup is a *convenience* so the junction lets session-local notes travel too.

---

## Paths used below

| | Path |
|---|---|
| **Real memory home (on D:\, portable)** | `D:\Python Applications\Find Evil - Hackathon\.claude-memory\` |
| **Alias Claude Code expects (on C:\)** | `C:\Users\chara\.claude\projects\d--Python-Applications-Find-Evil---Hackathon\memory\` |

---

## Scenario A — First-time setup on the machine that currently holds the live memory

Run from **`cmd.exe`** (not bash/PowerShell — `mklink` is a cmd built-in; it works in PowerShell too, but these commands are written for cmd).

**⚠️ Exit Claude Code first.** Do not run these while a session is writing to the memory folder.

```cmd
REM 1. Create the new home on D:
mkdir "D:\Python Applications\Find Evil - Hackathon\.claude-memory"

REM 2. Copy existing memory content to D: (keeps originals until we verify)
robocopy "C:\Users\chara\.claude\projects\d--Python-Applications-Find-Evil---Hackathon\memory" "D:\Python Applications\Find Evil - Hackathon\.claude-memory" /E

REM 3. Verify — list both, confirm contents match
dir "C:\Users\chara\.claude\projects\d--Python-Applications-Find-Evil---Hackathon\memory"
dir "D:\Python Applications\Find Evil - Hackathon\.claude-memory"

REM 4. ONLY if step 3 looks good: remove the C: folder
rmdir /S /Q "C:\Users\chara\.claude\projects\d--Python-Applications-Find-Evil---Hackathon\memory"

REM 5. Create the junction — C: path now points at the D: folder
mklink /J "C:\Users\chara\.claude\projects\d--Python-Applications-Find-Evil---Hackathon\memory" "D:\Python Applications\Find Evil - Hackathon\.claude-memory"
```

**Verify:**
```cmd
dir "C:\Users\chara\.claude\projects\d--Python-Applications-Find-Evil---Hackathon\memory"
```
Output should list your memory files and show `<JUNCTION>` in the directory line at the top.

Restart Claude Code. Ask it to read `MEMORY.md` — confirms it can still see everything.

---

## Scenario B — New machine, D:\ drive plugged in

D:\ drive already contains `Find Evil - Hackathon\.claude-memory\` from before. Fresh install of Claude Code on this machine will have created an empty `memory\` folder at the C:\ path.

**Exit Claude Code first.** Then from `cmd.exe`:

```cmd
REM 1. Remove the empty C: folder Claude Code created on first run
rmdir /S /Q "C:\Users\chara\.claude\projects\d--Python-Applications-Find-Evil---Hackathon\memory"

REM 2. Create the junction
mklink /J "C:\Users\chara\.claude\projects\d--Python-Applications-Find-Evil---Hackathon\memory" "D:\Python Applications\Find Evil - Hackathon\.claude-memory"
```

Restart Claude Code. Done.

**If the project slug differs on the new machine** (Claude Code derives the slug from the project path, so if D:\ plugs in as a different drive letter the slug changes) — look under `C:\Users\<user>\.claude\projects\` for the slug Claude Code generated and use that in the mklink command.

---

## Scenario C — Rollback (undo the junction)

If the junction causes any issue, no harm done — just remove the junction (it's just an alias).

```cmd
REM Remove the junction only; real data on D: is untouched
rmdir "C:\Users\chara\.claude\projects\d--Python-Applications-Find-Evil---Hackathon\memory"
```

To restore a standalone C: memory folder:
```cmd
mkdir "C:\Users\chara\.claude\projects\d--Python-Applications-Find-Evil---Hackathon\memory"
robocopy "D:\Python Applications\Find Evil - Hackathon\.claude-memory" "C:\Users\chara\.claude\projects\d--Python-Applications-Find-Evil---Hackathon\memory" /E
```

---

## Notes

- `mklink /J` creates a **directory junction**, not a symbolic link. Junctions don't need admin rights; symlinks do. Functionally equivalent for this use case.
- A junction target must be a **local path** (D:\ counts — external drives are local). Won't work for network shares; use `mklink /D` for those (needs admin).
- Git inside the project won't follow or commit the `.claude-memory\` folder contents unless you explicitly `git add` — the dot-prefix keeps it hidden from default listings. Consider adding `.claude-memory/` to `.gitignore` to prevent accidental commits.
- If you switch Claude accounts, nothing here changes — the memory system is filesystem-based, not account-bound.
