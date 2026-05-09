# Landing page implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `experiments/slice-2-notebook/site/index.html` with a portfolio-grade landing page for nontechnical hiring managers, per the spec at `docs/superpowers/specs/2026-05-09-landing-page-design.md`.

**Architecture:** Single self-contained HTML file with inline `<style>` and `<script>` blocks (matching the `dashboard.html` pattern). Cycling 4-second hero, three content sections (WHAT / HOW / PROOF), one live `/api/learnings` fetch for the "rules promoted" stat, static fallback for the other three stats. The existing `architecture.html` is already byte-identical to the current `index.html`, so the architecture migration is a no-op (verified via `diff -q`).

**Tech Stack:** Plain HTML + inline CSS variables + ~30 lines of vanilla JS. No build step, no framework. Reuses CSS palette tokens already defined in `dashboard.html`.

---

## File structure

| File | Role | Change |
|---|---|---|
| `experiments/slice-2-notebook/site/index.html` | landing page served at `/` | full rewrite |
| `experiments/slice-2-notebook/site/architecture.html` | architecture diagram served at `How it works` nav link | NOT touched, already canonical |

Server route is unchanged: `pipeline/site.py @app.get("/")` already serves `SITE_HTML` which defaults to `/workspace/site/index.html`.

---

## Task 1: HTML skeleton with head, nav, and empty main

**Files:**
- Modify (full rewrite): `experiments/slice-2-notebook/site/index.html`

- [ ] **Step 1: Replace the entire file with the skeleton**

Use the Write tool with this content. The file currently has 3870 lines of architecture; this overwrites it.

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<meta http-equiv="cache-control" content="no-cache, no-store, must-revalidate" />
<title>Sift Sentinel · An AI agent that gets better every night</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0b1020;
    --surface: #111827;
    --surface-2: #172033;
    --line: #334155;
    --line-soft: #243044;
    --text: #f8fafc;
    --text-2: #e2e8f0;
    --muted: #cbd5e1;
    --muted-2: #94a3b8;
    --accent: #60a5fa;
    --green: #34d399;
    --amber: #fbbf24;
    --purple: #a78bfa;
    --cyan: #22d3ee;
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0;
    background:
      radial-gradient(circle at top left, rgba(96,165,250,0.10), transparent 32rem),
      radial-gradient(circle at 80% 10%, rgba(34,211,238,0.06), transparent 28rem),
      var(--bg);
    color: var(--text);
    font: 14px/1.55 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif;
    min-height: 100vh;
  }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  code, pre, .mono { font-family: 'IBM Plex Mono', ui-monospace, Menlo, Consolas, monospace; }
  h1, h2, h3 { letter-spacing: -0.01em; color: var(--text); margin: 0; }
  .fe-nav {
    position: sticky; top: 0; z-index: 100;
    background: var(--bg); border-bottom: 1px solid var(--line);
    padding: 14px 32px;
    display: flex; align-items: center; gap: 4px;
    backdrop-filter: blur(8px);
  }
  .fe-nav .brand { font-weight: 700; color: var(--text); margin-right: 28px; font-size: 15px; text-decoration: none; letter-spacing: -0.01em; }
  .fe-nav a.nav-link { padding: 7px 14px; border-radius: 6px; color: var(--muted); font-size: 13px; text-decoration: none; }
  .fe-nav a.nav-link:hover { color: var(--text); background: var(--surface-2); text-decoration: none; }
  .fe-nav .clock { margin-left: auto; color: var(--muted-2); font-size: 12px; font-family: 'IBM Plex Mono', monospace; }

  .section { max-width: 980px; margin: 0 auto; padding: 56px 48px; border-top: 1px solid var(--line); }
  .section:first-of-type { border-top: none; }
  .section .label { color: var(--muted-2); font-size: 12px; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 10px; }
  .section h3 { font-size: 22px; font-weight: 700; margin: 0 0 14px; }
  .section p.body { color: var(--muted); font-size: 14px; line-height: 1.7; max-width: 720px; }
</style>
</head>
<body>

<nav class="fe-nav">
  <a href="/" class="brand">Sift Sentinel</a>
  <a class="nav-link" href="/site/dashboard.html">Today's run</a>
  <a class="nav-link" href="/viewer/">Past cases</a>
  <a class="nav-link" href="/site/architecture.html">How it works</a>
  <a class="nav-link" href="/site/submission.html">For judges</a>
  <span class="clock" id="now-utc"></span>
</nav>

<main id="main-root">
  <!-- hero, sections, and footer-cta inserted in later tasks -->
</main>

<script>
function fmtUtc() {
  const d = new Date();
  return d.toISOString().slice(0, 19) + ' UTC';
}
document.getElementById('now-utc').textContent = fmtUtc();
</script>

</body>
</html>
```

- [ ] **Step 2: Smoke test that the file parses and serves**

Run:
```
docker exec sift-sentinel /workspace/.venv/bin/python -c "from pathlib import Path; html = Path('/workspace/site/index.html').read_text(encoding='utf-8'); assert 'Sift Sentinel' in html and '<main id=\"main-root\"' in html; print('skeleton OK, length=', len(html))"
```

Expected: `skeleton OK, length= <small number, ~3000>`. Confirms the 3870-line architecture is gone and the skeleton is in place.

- [ ] **Step 3: Commit**

```bash
git add experiments/slice-2-notebook/site/index.html
git commit -m "feat(site): landing page skeleton, retire architecture from /"
```

---

## Task 2: Hero with cycling tagline and CTA

**Files:**
- Modify: `experiments/slice-2-notebook/site/index.html`

- [ ] **Step 1: Insert the hero block inside `<main id="main-root">`**

Use the Edit tool. Replace `<!-- hero, sections, and footer-cta inserted in later tasks -->` with:

```html
  <section class="hero" style="padding: 80px 32px 60px; display: flex; flex-direction: column; align-items: center; text-align: center;">
    <div style="font-size: 11px; color: var(--muted-2); text-transform: uppercase; letter-spacing: 0.14em; margin-bottom: 22px;">SIFT SENTINEL · BUILT BY CHARAN</div>
    <h1 id="hero-tagline" style="font-size: 36px; font-weight: 700; line-height: 1.2; max-width: 700px; margin-bottom: 22px;">An AI agent that gets better every night.</h1>
    <div id="hero-dots" style="display: flex; gap: 8px; margin-bottom: 36px;">
      <span class="tag-dot" data-i="0" onclick="pinTagline(0)" style="width: 28px; height: 3px; background: var(--accent); border-radius: 2px; cursor: pointer;"></span>
      <span class="tag-dot" data-i="1" onclick="pinTagline(1)" style="width: 28px; height: 3px; background: var(--line); border-radius: 2px; cursor: pointer;"></span>
      <span class="tag-dot" data-i="2" onclick="pinTagline(2)" style="width: 28px; height: 3px; background: var(--line); border-radius: 2px; cursor: pointer;"></span>
    </div>
    <a href="/site/dashboard.html" style="background: var(--accent); color: var(--bg); border: none; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 14px; text-decoration: none; display: inline-block;">See last night's run &rarr;</a>
    <div style="margin-top: 8px; font-size: 11px; color: var(--muted-2);">runs nightly at 22:30 UTC, autonomous</div>
  </section>
  <!-- sections-and-footer-cta-anchor -->
```

- [ ] **Step 2: Append the cycling-tagline JS to the existing `<script>` block**

Use the Edit tool. Replace:

```html
<script>
function fmtUtc() {
  const d = new Date();
  return d.toISOString().slice(0, 19) + ' UTC';
}
document.getElementById('now-utc').textContent = fmtUtc();
</script>
```

with:

```html
<script>
function fmtUtc() {
  const d = new Date();
  return d.toISOString().slice(0, 19) + ' UTC';
}
document.getElementById('now-utc').textContent = fmtUtc();

const taglines = [
  'An AI agent that gets better every night.',
  'Hunts attackers on Windows machines, with receipts.',
  'A study in how to make AI agents trustworthy.',
];
let activeTag = 0;
let tagTimer = null;

function setTagline(i) {
  activeTag = i;
  document.getElementById('hero-tagline').textContent = taglines[i];
  document.querySelectorAll('.tag-dot').forEach((d, j) => {
    d.style.background = j === i ? 'var(--accent)' : 'var(--line)';
  });
}
function cycleTagline() {
  setTagline((activeTag + 1) % taglines.length);
}
function pinTagline(i) {
  if (tagTimer) { clearInterval(tagTimer); tagTimer = null; }
  setTagline(i);
}
setTagline(0);
tagTimer = setInterval(cycleTagline, 4000);
</script>
```

- [ ] **Step 3: Smoke test**

Run:
```
docker exec sift-sentinel /workspace/.venv/bin/python -c "from pathlib import Path; html = Path('/workspace/site/index.html').read_text(encoding='utf-8'); assert 'BUILT BY CHARAN' in html and 'pinTagline' in html and 'cycleTagline' in html and 'See last night' in html; print('hero OK, length=', len(html))"
```

Expected: `hero OK, length= <larger>`. Confirms hero markup and JS are present.

- [ ] **Step 4: Commit**

```bash
git add experiments/slice-2-notebook/site/index.html
git commit -m "feat(site): landing hero with cycling tagline, byline, CTA"
```

---

## Task 3: Section WHAT IT DOES

**Files:**
- Modify: `experiments/slice-2-notebook/site/index.html`

- [ ] **Step 1: Insert the WHAT section before the anchor**

Use the Edit tool. Replace `<!-- sections-and-footer-cta-anchor -->` with:

```html
  <section class="section">
    <div class="label">WHAT IT DOES</div>
    <h3>Reads a Windows machine and tells you who broke in.</h3>
    <p class="body">Sift Sentinel takes a forensic image of a compromised Windows computer and works through it the way a human investigator would. It looks at the registry, scheduled tasks, services, and memory. It writes down what it found, with the exact file or registry key as proof. Every claim is cited. Then it grades itself: did it find the real attacker, or did it miss?</p>
    <div style="display: flex; gap: 10px; margin-top: 18px; flex-wrap: wrap;">
      <div style="background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 12px 16px; font-size: 12px; color: var(--muted); flex: 1; min-width: 280px;">
        <div style="color: var(--accent); font-weight: 600; font-size: 11px; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.06em;">EXAMPLE FROM A REAL RUN</div>
        A registry key on a workstation pointing to <code style="color: var(--amber); font-size: 11px;">c:\windows\system32\dllhost\svchost.exe</code>. There is no real folder by that name; the attacker hid a fake svchost there.
      </div>
      <div style="background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 12px 16px; font-size: 12px; color: var(--muted); flex: 1; min-width: 280px;">
        <div style="color: var(--purple); font-weight: 600; font-size: 11px; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.06em;">SAME PATTERN, THREE HOSTS</div>
        Sentinel found the same key on three different Windows machines in the same network. That is independent corroboration of one intrusion.
      </div>
    </div>
  </section>
  <!-- sections-and-footer-cta-anchor -->
```

- [ ] **Step 2: Smoke test**

Run:
```
docker exec sift-sentinel /workspace/.venv/bin/python -c "from pathlib import Path; html = Path('/workspace/site/index.html').read_text(encoding='utf-8'); assert 'WHAT IT DOES' in html and 'dllhost' in html and 'three different Windows machines' in html; print('what OK')"
```

Expected: `what OK`.

- [ ] **Step 3: Commit**

```bash
git add experiments/slice-2-notebook/site/index.html
git commit -m "feat(site): landing WHAT IT DOES section with two real-run callouts"
```

---

## Task 4: Section HOW IT WORKS (5-step loop)

**Files:**
- Modify: `experiments/slice-2-notebook/site/index.html`

- [ ] **Step 1: Insert the HOW section before the anchor**

Use the Edit tool. Replace `<!-- sections-and-footer-cta-anchor -->` with:

```html
  <section class="section">
    <div class="label">HOW IT WORKS</div>
    <h3>A learning loop, run nightly.</h3>
    <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 24px 0; align-items: stretch;">
      <div style="background: var(--surface); border: 1px solid var(--accent); border-radius: 8px; padding: 12px; font-size: 11px; text-align: center; color: var(--muted);">
        <div style="color: var(--accent); font-weight: 700; margin-bottom: 4px;">1. READ</div>
        fresh threat-intel from the public web
      </div>
      <div style="background: var(--surface); border: 1px solid var(--cyan); border-radius: 8px; padding: 12px; font-size: 11px; text-align: center; color: var(--muted);">
        <div style="color: var(--cyan); font-weight: 700; margin-bottom: 4px;">2. PLANT</div>
        synthetic copies of new attacker tradecraft
      </div>
      <div style="background: var(--surface); border: 1px solid var(--green); border-radius: 8px; padding: 12px; font-size: 11px; text-align: center; color: var(--muted);">
        <div style="color: var(--green); font-weight: 700; margin-bottom: 4px;">3. HUNT</div>
        run the agent against the prepared image
      </div>
      <div style="background: var(--surface); border: 1px solid var(--amber); border-radius: 8px; padding: 12px; font-size: 11px; text-align: center; color: var(--muted);">
        <div style="color: var(--amber); font-weight: 700; margin-bottom: 4px;">4. SCORE</div>
        what did it catch, what did it miss
      </div>
      <div style="background: var(--surface); border: 1px solid var(--purple); border-radius: 8px; padding: 12px; font-size: 11px; text-align: center; color: var(--muted);">
        <div style="color: var(--purple); font-weight: 700; margin-bottom: 4px;">5. LEARN</div>
        draft a new rule from each miss; ship it tomorrow
      </div>
    </div>
    <p class="body">The agent is not a static demo. Every night it reads new attacker tradecraft from public sources, plants synthetic copies on a fresh test machine, runs against them, and writes down a candidate rule for every miss. A human reviewer approves the rules. Tomorrow's run picks them up automatically. The system improves while I sleep.</p>
  </section>
  <!-- sections-and-footer-cta-anchor -->
```

- [ ] **Step 2: Smoke test**

Run:
```
docker exec sift-sentinel /workspace/.venv/bin/python -c "from pathlib import Path; html = Path('/workspace/site/index.html').read_text(encoding='utf-8'); 
labels = ['1. READ', '2. PLANT', '3. HUNT', '4. SCORE', '5. LEARN']; 
assert all(L in html for L in labels), [L for L in labels if L not in html]; 
print('how OK')"
```

Expected: `how OK`.

- [ ] **Step 3: Commit**

```bash
git add experiments/slice-2-notebook/site/index.html
git commit -m "feat(site): landing HOW IT WORKS 5-step loop diagram"
```

---

## Task 5: Section PROOF (4 stats + concrete find)

**Files:**
- Modify: `experiments/slice-2-notebook/site/index.html`

- [ ] **Step 1: Insert the PROOF section before the anchor**

Use the Edit tool. Replace `<!-- sections-and-footer-cta-anchor -->` with:

```html
  <section class="section">
    <div class="label">PROOF</div>
    <h3>Real numbers from real runs.</h3>
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 22px;">
      <div style="background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 14px;">
        <div id="stat-runs" style="font-size: 24px; font-weight: 700; color: var(--text);">32</div>
        <div style="color: var(--muted-2); font-size: 11px;">audited runs</div>
      </div>
      <div style="background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 14px;">
        <div id="stat-halluc" style="font-size: 24px; font-weight: 700; color: var(--green);">0</div>
        <div style="color: var(--muted-2); font-size: 11px;">factual hallucinations</div>
      </div>
      <div style="background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 14px;">
        <div id="stat-hosts" style="font-size: 24px; font-weight: 700; color: var(--text);">15+</div>
        <div style="color: var(--muted-2); font-size: 11px;">Windows hosts covered</div>
      </div>
      <div style="background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 14px;">
        <div id="stat-promoted" style="font-size: 24px; font-weight: 700; color: var(--purple);">2</div>
        <div style="color: var(--muted-2); font-size: 11px;">rules promoted into live agent</div>
      </div>
    </div>
    <div style="background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 18px;">
      <div style="font-size: 11px; color: var(--green); font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px;">CONCRETE FIND</div>
      <div style="color: var(--text); font-size: 14px; line-height: 1.6; margin-bottom: 8px;">On a 2026 Windows Server image, Sentinel surfaced a scheduled task using PsExec to push a payload called <code class="mono" style="color: var(--amber); font-size: 12px;">rename.exe</code> to six other workstations with the password <code class="mono" style="color: var(--amber); font-size: 12px;">letmein</code>. A real attacker artifact, with a real citation, on a real disk image.</div>
      <div style="color: var(--muted-2); font-size: 12px;">Backed by a 24-line citation chain to the source disk evidence record.</div>
    </div>
  </section>
  <!-- sections-and-footer-cta-anchor -->
```

- [ ] **Step 2: Smoke test**

Run:
```
docker exec sift-sentinel /workspace/.venv/bin/python -c "from pathlib import Path; html = Path('/workspace/site/index.html').read_text(encoding='utf-8'); 
assert 'PROOF' in html and 'stat-promoted' in html and 'rename.exe' in html and 'letmein' in html; 
print('proof OK')"
```

Expected: `proof OK`.

- [ ] **Step 3: Commit**

```bash
git add experiments/slice-2-notebook/site/index.html
git commit -m "feat(site): landing PROOF section with 4 stats + OpenUni22 concrete find"
```

---

## Task 6: Footer CTA + live promoted-rules fetch

**Files:**
- Modify: `experiments/slice-2-notebook/site/index.html`

- [ ] **Step 1: Replace the anchor with the footer CTA**

Use the Edit tool. Replace `<!-- sections-and-footer-cta-anchor -->` with:

```html
  <section class="section" style="text-align: center; padding: 60px 32px;">
    <div style="color: var(--text); font-size: 18px; font-weight: 600; margin-bottom: 16px;">See last night's findings.</div>
    <a href="/site/dashboard.html" style="background: var(--accent); color: var(--bg); border: none; padding: 14px 30px; border-radius: 8px; font-weight: 600; font-size: 14px; text-decoration: none; display: inline-block;">Open Today's run &rarr;</a>
  </section>
```

- [ ] **Step 2: Append the live promoted-rules fetcher to the JS block**

Use the Edit tool. Replace the closing of the existing `<script>` block. Find:

```javascript
tagTimer = setInterval(cycleTagline, 4000);
</script>
```

and replace with:

```javascript
tagTimer = setInterval(cycleTagline, 4000);

async function loadPromotedCount() {
  try {
    const r = await fetch('/api/learnings');
    if (!r.ok) return;
    const d = await r.json();
    document.getElementById('stat-promoted').textContent = (d.count != null) ? d.count : '2';
  } catch (e) { /* keep static fallback */ }
}
loadPromotedCount();
</script>
```

- [ ] **Step 3: Final smoke test**

Run:
```
docker exec sift-sentinel /workspace/.venv/bin/python -c "from pathlib import Path; html = Path('/workspace/site/index.html').read_text(encoding='utf-8'); 
assert 'Open Today' in html and 'loadPromotedCount' in html and '/api/learnings' in html; 
print('footer + fetch OK, total length=', len(html))"
```

Expected: `footer + fetch OK, total length= <under 8000>`.

- [ ] **Step 4: Commit**

```bash
git add experiments/slice-2-notebook/site/index.html
git commit -m "feat(site): landing footer CTA and live promoted-rules fetch"
```

---

## Task 7: Deploy and live verification

- [ ] **Step 1: Push and deploy**

```bash
git push origin main
ssh -i $HOME/.ssh/id_hetzner sri@46.62.255.66 'cd /opt/find-evil/repo && git pull --ff-only origin main 2>&1 | tail -3'
ssh -i $HOME/.ssh/id_hetzner sri@46.62.255.66 'cd /opt/find-evil/repo/docker && docker compose -f docker-compose.vps.yaml restart sift-sentinel 2>&1 | tail -3'
sleep 6
```

- [ ] **Step 2: HTTP smoke test**

Run:
```
curl -s "https://sentinel.sshub.dev/?cb=$(date +%s)" | grep -E "BUILT BY CHARAN|gets better every night|1\. READ|rename.exe" | head -10
```

Expected: at least 4 matching lines.

- [ ] **Step 3: Architecture link smoke test**

Run:
```
curl -sI https://sentinel.sshub.dev/site/architecture.html 2>&1 | head -3
```

Expected: `HTTP/1.1 200`.

- [ ] **Step 4: Browser visual smoke via Playwright**

Navigate the browser to `https://sentinel.sshub.dev/?cb=fresh`, then in JS evaluate:

```javascript
async () => {
  await new Promise(r => setTimeout(r, 1000));
  const t1 = document.getElementById('hero-tagline').textContent;
  await new Promise(r => setTimeout(r, 4500));
  const t2 = document.getElementById('hero-tagline').textContent;
  return {t1, t2, cycled: t1 !== t2, hasFiveSteps: ['1. READ','2. PLANT','3. HUNT','4. SCORE','5. LEARN'].every(L => document.body.innerText.includes(L))};
}
```

Expected: `{t1: "An AI agent...", t2: "Hunts attackers..." or "A study in how...", cycled: true, hasFiveSteps: true}`.

- [ ] **Step 5: Pin-dot click test**

In the browser, click the second tagline dot (selector: `.tag-dot[data-i="1"]`). Wait 5 seconds. Verify the tagline stays on `Hunts attackers...` (auto-rotation paused).

- [ ] **Step 6: If anything fails, fix inline + recommit**

If the live page is broken, identify the issue from console errors or the smoke test output, fix in place, re-run Step 1 to redeploy. If everything works, no extra commit needed.

---

## Self-review

**Spec coverage:**
- Hero with cycling tagline, 3 dots, byline, CTA → Task 2.
- WHAT IT DOES section with 2 callouts (dllhost masquerade, three-host corroboration) → Task 3.
- HOW IT WORKS 5-step loop diagram → Task 4.
- PROOF section with 4 stats + OpenUni22 concrete find → Task 5.
- Footer CTA → Task 6.
- Live `/api/learnings` fetch for stat-promoted → Task 6.
- Architecture migration → confirmed no-op (architecture.html is byte-identical to the current index.html).
- Top nav with 5 links → Task 1.
- Static fallback for stats → Task 5 (numbers ship in the HTML); Task 6 only updates one (stat-promoted).

**Placeholder scan:** No TBDs, no TODOs, no "implement later", no "similar to Task N", no "add error handling".

**Type / signature consistency:**
- `pinTagline(i)` defined in Task 2; called by `.tag-dot` onclick in Task 2 (same task; no cross-task drift).
- `loadPromotedCount` defined in Task 6; not referenced anywhere else.
- Element ids `hero-tagline`, `tag-dot`, `stat-promoted` are consistent across the tasks that mention them.
- The anchor `<!-- sections-and-footer-cta-anchor -->` is introduced in Task 2 and used by Tasks 3, 4, 5, 6 in sequence; each task replaces it and reinserts it (except Task 6 which removes it).

Out of scope (per spec) and not in any task: drilldowns, animation libraries, mobile breakpoints, contact form, photo / bio block.
