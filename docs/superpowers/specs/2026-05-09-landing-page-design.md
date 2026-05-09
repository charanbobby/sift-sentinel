---
created: 2026-05-09
status: approved
audience: nontechnical hiring manager (primary), curious dev (secondary)
target_url: https://sentinel.sshub.dev/
replaces: experiments/slice-2-notebook/site/index.html (currently the architecture diagram)
---

# Landing page design

## TL;DR

Replace the architecture diagram at `sentinel.sshub.dev/` with a portfolio-grade landing page for nontechnical hiring managers who land on the URL and need to understand what was built in 60 seconds. Cycling 4-second hero presents three framings of the project (engineering story, domain story, AI-trustworthiness story); a single CTA leads into Today's run. Below the hero, three short sections (WHAT IT DOES, HOW IT WORKS, PROOF) give plain-English context plus concrete evidence. The architecture diagram moves to `/site/architecture.html` (already exists at that path) and stays accessible from the top nav. The new top nav includes a "How it works" link pointing at the architecture page.

## Goals

1. A nontechnical hiring manager can read the page in 60 seconds and walk away knowing: this person built an autonomous AI agent that hunts attackers on Windows machines and improves itself nightly.
2. The page conveys engineering rigor (citations, audit trail, zero hallucinations) without using DFIR or LLM-engineering jargon.
3. There is exactly one obvious next step on the page (the CTA into Today's run).
4. The author byline (BUILT BY CHARAN) is unambiguous so the page reads as a portfolio piece, not a product page.

## Non-goals (deferred or out of scope)

- A separate "About" or "Contact" page. The landing carries the personal byline; resume / LinkedIn links live in the footer if needed but are not the focus.
- An animation library. Cycling-tagline rotation is a small inline JS routine, not Framer Motion or similar.
- Drilldowns from the proof stat cards. Stats are display-only; users click the CTA to see the actual run.
- Mobile-first responsive design. Desktop polish first; mobile renders cleanly without explicit breakpoints because the layout is single-column-stacked everywhere.
- Form fields, sign-up, mailing list. None of these on the landing.

## Audience and headline

Primary: nontechnical hiring manager landing on `sentinel.sshub.dev/` with no prior context. Secondary: curious dev or recruiter who wants slightly more depth.

The hero one-liner cycles through three framings of the same project (decision locked during brainstorming as "Show all three; let them pick"):

1. `An AI agent that gets better every night.` (engineering story)
2. `Hunts attackers on Windows machines, with receipts.` (domain story)
3. `A study in how to make AI agents trustworthy.` (discipline story)

Cycle interval: 4 seconds. Three position dots below the headline let the visitor click to pin one frame. After clicking a dot, the auto-rotation pauses.

## Page structure

### 1. Top nav (replace existing)

The current nav on dashboard.html is reused but re-ordered for the landing context:

`Sift Sentinel | Today's run | Past cases | How it works | For judges` plus the right-aligned UTC clock.

`Sift Sentinel` is a link to `/`. `How it works` points to `/site/architecture.html` (the existing 3870-line architecture diagram). `Today's run` points to `/site/dashboard.html`. `Past cases` points to `/viewer/`.

### 2. Hero

- Padding: 80px top, 60px bottom; centered content; subtle blue-tinted radial gradient background.
- Small uppercase byline: `SIFT SENTINEL · BUILT BY CHARAN` in `--muted-2` color.
- Cycling tagline: 36px font, weight 700, color `--text`, max-width 700px, line-height 1.2.
- Three position dots in `--accent` (active) and `--line` (inactive); 28px wide, 3px tall, 2px radius, 8px gap.
- Dots are clickable; clicking pauses auto-rotation and pins that tagline.
- Primary CTA button: `See last night's run -->`. Background `--accent`, color `--bg`, 12px 24px padding, 8px radius, weight 600.
- Sub-line: `runs nightly at 22:30 UTC, autonomous` in `--muted-2`, 11px.

### 3. Section: WHAT IT DOES

- Top spacing: 56px padding, 1px top border.
- Small uppercase label: `WHAT IT DOES`.
- H3: `Reads a Windows machine and tells you who broke in.` (22px, weight 700)
- Paragraph (~80 words, max-width 720px): plain-English explanation. Mentions registry, scheduled tasks, services, memory. Mentions citations explicitly. Mentions that the agent grades itself.
- Two example callout cards in a 2-column grid:
  - `EXAMPLE FROM A REAL RUN`: the dllhost svchost masquerade with the registry path in monospace amber.
  - `SAME PATTERN, THREE HOSTS`: cross-host corroboration narrative.

The two callouts are real artifacts from completed runs (SRL-2015 dllhost masquerade, three-host independent surfacing). The page does not link to the run pages from these callouts; they are display-only.

### 4. Section: HOW IT WORKS

- 56px padding, 1px top border.
- Label: `HOW IT WORKS`.
- H3: `A learning loop, run nightly.`
- Five step-cards in a `repeat(5, 1fr)` grid: READ (blue), PLANT (cyan), HUNT (green), SCORE (amber), LEARN (purple). Each card has a colored top label, then a short caption, ~10 words.
- Caption paragraph (~80 words): explains the loop in plain English. Says "the system improves while I sleep" as a personal touch.

The 5 colors map to the existing palette already used by the dashboard (`--accent`, `--cyan`, `--green`, `--amber`, `--purple`).

### 5. Section: PROOF

- 56px padding, 1px top border.
- Label: `PROOF`.
- H3: `Real numbers from real runs.`
- 4 stat cards in a `repeat(4, 1fr)` grid:
  - 32 audited runs
  - 0 hallucinations (color `--green`)
  - 15+ Windows hosts covered
  - 2 rules promoted into live agent (color `--purple`)
- One concrete-find callout below the stats: `CONCRETE FIND` label + a 2-3 sentence narrative about the OpenUni22 PsExec lateral-movement scheduled task (real finding from the May 8 run). Includes the password "letmein" as a memorable concrete detail.
- "rules promoted" is pulled live from `/api/learnings` (the response's `count` field).
- "audited runs", "hallucinations", and "Windows hosts covered" are hard-coded in the HTML (32, 0, 15+) because there is no live endpoint that counts these. The hallucination-audit work that produced the "32 runs / 0 hallucinations" claim is documented at `out/audit_summary_v2_2026-05-09.md`. The "15+" hosts number is rounded from `viewer/keep_runs.json` keys (currently 33).
- Static-fallback contract: every stat number ships in the HTML with its current value. JS only updates `stat-promoted` from the live `/api/learnings` fetch. If that fetch fails, the static value (`2`) stays visible. No `loadProofNumbers` call is needed for the other three stats; they are intentionally static until a real live counter exists.

### 6. Footer CTA

- 60px padding, 1px top border, centered.
- 18px text: `See last night's findings.`
- Same button as the hero CTA: `Open Today's run -->`.

The footer CTA is the second chance to click into the demo for visitors who scrolled past the first one.

## Architecture migration

The current `/site/index.html` IS the 3870-line architecture page (its `<title>` is `Find Evil - Pipeline Architecture`). To make room for the new landing:

1. Move existing `index.html` content to `/site/architecture.html` (the file already exists at that path, which is a near-duplicate; reconcile by overwriting `architecture.html` with the canonical content from `index.html`, or accept that they are already identical).
2. Replace `/site/index.html` with the new landing page.
3. The unified site server `pipeline/site.py` already has `@app.get("/")` serving `SITE_HTML` (default `/workspace/site/index.html`). No server change needed; the file swap at `index.html` is sufficient.

## Components and isolation

The redesign affects exactly two files:

- `experiments/slice-2-notebook/site/index.html`: full rewrite as the new landing page.
- `experiments/slice-2-notebook/site/architecture.html`: ensure it has the canonical architecture-page content (overwrite from current index.html if needed; verify by diff).

The dashboard, the viewer, and `pipeline/site.py` are not touched.

CSS: reuse the existing `--bg`, `--surface`, `--surface-2`, `--text`, `--text-2`, `--muted`, `--muted-2`, `--accent`, `--green`, `--amber`, `--purple`, `--cyan`, `--line` variables from dashboard.html. Inline `<style>` block in the new index.html (consistent with the dashboard's pattern; no shared external stylesheet).

## Cycling-tagline implementation

Inline JS, ~20 lines:

```javascript
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
```

The dots have `onclick="pinTagline(0)"` etc.

Live promoted-rules fetcher (~10 lines):

```javascript
async function loadPromotedCount() {
  try {
    const r = await fetch('/api/learnings');
    if (!r.ok) return;
    const d = await r.json();
    document.getElementById('stat-promoted').textContent = d.count || '0';
  } catch (e) {}
}
loadPromotedCount();
```

Static fallback: every stat number ships in the HTML with its current value. JS only refreshes `stat-promoted`; the other three are static.

## Error handling

- Missing `/api/learnings` or `/api/proposed-rules/dates`: silently fall back to static numbers in the HTML.
- JS disabled: the cycling tagline shows the first tagline only (since setTagline never fires); proof numbers show the static defaults. Page is still readable.
- Architecture link broken: `How it works` nav item points at `/site/architecture.html`; ensure that file exists.

## Testing

- Static smoke test: `curl -s https://sentinel.sshub.dev/` should return HTML containing `BUILT BY CHARAN`, `gets better every night`, the 5 step labels (READ, PLANT, HUNT, SCORE, LEARN), and the OpenUni22 finding text.
- Browser smoke test via Playwright: load the page, verify hero cycles through 3 taglines (advance 5 seconds, snapshot), click a dot, verify auto-rotation paused.
- Architecture link smoke test: click `How it works`, land on `/site/architecture.html`, see the existing pipeline diagram.

## Out of scope (named here for the spec's audit trail)

- Drilldowns from any element on the landing page.
- A custom illustration in the hero (option B from the brainstorming was declined; gradient background is enough).
- A photo of the author or a personal-bio block (option C declined).
- Mobile-specific layouts.
- Animation libraries.
- A signup form, mailing list, or contact form.
- Auto-refresh of stats every N seconds.

## Open questions

None. Brainstorming locked the audience (nontechnical hiring manager), the hero treatment (cycling 4-second rotation with 3 dots), the page depth (hero + 3 sections + CTA), and the visual style (dark theme matching the dashboard).
