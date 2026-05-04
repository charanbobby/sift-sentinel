# Track 4: Unified Site (sentinel.sshub.dev)

Status: **live in production** at https://sentinel.sshub.dev (2026-05-03 evening)

## What is built

- FastAPI app at `experiments/slice-2-notebook/pipeline/site.py` on port 8081
- Landing page at `experiments/slice-2-notebook/site/index.html`
- Existing run viewer mounted at `/viewer` (preserves all viewer URLs unchanged)
- 4 tabs:
  - **Live**: latest cron run, currently in-flight pipelines, recent commits to pipeline + scripts
  - **Learnings**: promoted rules from `pipeline/learned_rules.jsonl` with provenance
  - **Findings**: iframe to the existing run viewer (temporary; see scope addendum below)
  - **Submit a test**: Chetas-style submission form for tradecraft patterns
- API endpoints:
  - `GET /api/status`: snapshot of cron + in-flight + learnings count + recent commits
  - `GET /api/learnings`: full rules with provenance
  - `GET /api/submissions`: pending submissions
  - `POST /api/submissions`: validated structural intake

## Production deployment (done 2026-05-03 evening)

- VPS `46.62.255.66` runs `docker-compose.vps.yaml`; sentinel container binds `127.0.0.1:8081:8081`
- nginx site at `/etc/nginx/sites-enabled/sentinel.sshub.dev` proxies `127.0.0.1:8081`
- Cloudflare-proxied CNAME `sentinel.sshub.dev` (orange cloud, TTL Auto)
- TLS via Let's Encrypt cert at `/etc/letsencrypt/live/sentinel.sshub.dev/`, expires 2026-08-01
- HTTP to HTTPS redirect via certbot-managed `--redirect`
- Pattern matches the other 6 sshub.dev subdomains (apprentice, approve, claw, monitor, sshub root, maplepulse)

## Scope addendum: surface past results + accepted runs (2026-05-03 evening request)

User feedback: "We also need to create the web page in such a way that it the results of the past ones, and then we should quote our accept runs. ... we should probably use similar formatting for the new ones as well. Keep it consistent. The live ones. And we did have some things that we ran already. Right? We should also attach that."

### What this means

- **Past results visible** on the landing page, not buried inside an iframe
- **"Accepted runs"** (HUMAN_APPROVED + SUCCESS terminal markers) should be highlighted as wins, not just listed
- **Visual consistency** between site and viewer (they both share `--bg`, `--surface`, `--accent`, `--green`, `--teal`, `--purple` from the dark theme already; check spacing, pills, badges)
- **Live tab** should attach "things we ran already" so a visitor sees track record, not just the in-flight count

### Build list (in order)

- [ ] **API** add `GET /api/recent-approved` to `site.py`. Returns the most recent HUMAN_APPROVED + SUCCESS runs across all cases, sorted by approval/commit time desc, capped at ~12 entries. Each entry: `case_id`, `run_id`, `status` (APPROVED/COMMITTED), `n_findings`, `top_classifications` (3 most-confident), `terminal_at`, `viewer_link` (`/viewer/?case=<case_id>`).
- [ ] **Landing page** add new section above "Currently in flight" titled "Recent wins" rendering the new endpoint. Use the same `.panel-row` / `.pill-pass` styling that the cron section uses. Each row links into the viewer for the full evidence.
- [ ] **Findings tab** keep the iframe to `/viewer` for now (full per-case detail), but rename the tab from "Findings" to "Run viewer (full)" so a visitor knows the landing page already has the headlines.
- [ ] **Visual sweep** open both views side-by-side and confirm: header colors match, pill styling matches, panel borders match. Fix anything that drifts.
- [ ] **Empty state** if no approved runs yet, show a placeholder pointing at the in-flight section instead of the empty viewer iframe.
- [ ] **Cache the endpoint** add a 30-second response cache so the landing page does not stat the runs tree on every refresh.

### Why this matters

- A first-time visitor to `sentinel.sshub.dev` should see proof of work in 5 seconds, not have to click into a viewer iframe.
- Approved runs are the strongest signal that the system is doing real work; they are the things to "quote".
- Iframes feel hacky; native rendering with the same CSS tokens makes the site feel like one product, not two stitched together.
- Keeping the viewer reachable (just renamed tab) preserves every existing deep link.

### Out of scope for now

- Server-side rendering or SSG. The current FE is a single static HTML with vanilla JS. Stays that way.
- Pagination beyond 12. If we need history scrolling, we can wire `/viewer` for that.
- Authentication. The site is read-only public except for `POST /api/submissions`, which is rate-limited at the Cloudflare layer.

## Scope addendum 2: dedicated landing with architecture diagram (2026-05-03 evening request)

User feedback: "we should also dedicate a landing page. I think we can use some architecture diagram or something which we put in so much detail. Maybe an average version comfortable on the eyes I like the different boxes that we have. Maybe hold that one. Detail. Probably that's good enough and the rest of them can go away."

### Interpretation

- The site landing should lead with the architecture diagram, not the in-flight cards.
- "I like the different boxes that we have" picks out `docs/planning/architecture.html` (the styled box diagram, 159KB, with sections for pipeline / memory channel / AI-attacker / deployment / critic).
- "Maybe hold that one. Detail." reads as: keep the detailed variant intact; do not strip it down.
- "Rest of them can go away" likely refers to the redundant architecture variants (`architecture-video.html`, the bare `.md` files), not the live/learnings/submit tabs. Confirm before deleting any.

### Build list

- [x] Copy `docs/planning/architecture.html` to `experiments/slice-2-notebook/site/architecture.html` so the existing `/site/` static mount serves it. Self-contained (only external dep is Google Fonts, public CDN). All internal links are `#anchor` so they resolve inside the iframe.
- [x] Add an "Architecture" tab to `site/index.html` as the new default landing. Iframe `/site/architecture.html` at full viewport height. Live, Learnings, Findings, Submit remain reachable from the same nav.
- [ ] Verify visually on https://sentinel.sshub.dev that the iframe scrolls cleanly and internal anchor links work.
- [ ] Ask the user before removing `architecture-video.html` or any other variant. "Rest can go away" is plausible but reversible-only if confirmed.

### Why this matters

- The architecture diagram is the single best artifact for proving "this is a real system, not a single LLM call". Putting it as the landing makes the first impression the strongest one.
- The Live tab is a great second-impression but a bad first one: empty most of the time outside cron windows.
- Reusing the existing diagram avoids rebuilding what already exists.

