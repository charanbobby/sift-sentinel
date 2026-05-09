---
created: 2026-05-09
status: draft, awaiting Charan review
deliverable: 5-minute screencast + voice for SANS hackathon submission
case_spine: srl-2018-base-rd-02-dual (run -002)
voice: Charan's ElevenLabs voice clone
recording: Playwright screencast at sentinel.sshub.dev
stitching: Studio (manual)
---

# 5-minute demo video script

## TL;DR

Five-minute screencast for the SANS Find Evil hackathon submission. Single judge is Rob T. Lee (CAIO SANS), so the script assumes deep DFIR fluency and skips Volatility / NTFS / RegRipper basics. Spine is `srl-2018-base-rd-02-dual` because it offers two paired Windows-service masquerades (`msadvapi2_32` + `msadvapi2_64`), a PEB-walking shellcode signature in a PowerShell process, an INJECTION_QUARANTINE false-positive that shows the defense layer firing, and three Critic escalations: enough self-correction beats for the rubric's tiebreaker without filler. Five beats, hard-locked timings: open 15s, architecture 45s, case walkthrough 3:00, loop closing 45s, URLs and outro 15s. Total 5:00.

## Goals (mapped to rubric)

| Beat | Rubric criterion hit |
|---|---|
| Open hook | criterion 2 IR Accuracy (concrete real-data find) |
| Architecture sketch | criterion 4 Constraint Implementation (architectural vs prompt-based) |
| Case walkthrough | criterion 1 Autonomous Execution Quality (TIEBREAKER), criterion 5 Audit Trail Quality |
| Loop closing | criterion 1 Autonomous Execution Quality, criterion 3 Breadth and Depth |
| URLs and outro | criterion 6 Usability and Documentation |

The hard requirement "≥1 self-correction sequence on real case data" is hit twice: once in the case walkthrough (Critic escalating findings + INJECTION_QUARANTINE on the `T1033` byte substring), once in the loop-closing beat (drafted-rules approve flow promoting a rule live).

## Constraints

- Total length: ≤ 5:00.
- Format: screencast + voice narration. No live-typing terminal demo (too slow, judge attention budget too small).
- Voice: ElevenLabs voice clone. Script lines should be conversational, easy to phrase, no jargon clusters.
- Recording: Playwright captures the dashboard + viewer at sentinel.sshub.dev. Each beat is a Playwright scene with deterministic navigation steps.
- Resolution: 1920x1080 (1080p) at 30fps for clean YouTube upload. Browser viewport set to 1920x1080.
- Stitching: Studio (manual). Audio aligned to scene timestamps.
- Captions: burned into the visuals (hardcoded), NOT a soft SRT track. Generated from the same voiceover text so the caption is the truth. Burning happens BEFORE voice generation so the visuals + captions lock together first.

## Beat-by-beat script

### Beat 1: Open hook (0:00 to 0:15)

**Visual:** Cold open. A still frame of the dashboard hero ("Last night (2026-05-08), Sentinel ran. Tonight it gets better.") with the 4-widget board visible underneath. Static for 2 seconds, then start the voiceover.

**Playwright scene:**
```
navigate https://sentinel.sshub.dev/site/dashboard.html
viewport 1920x1080
wait 2s
hold for 13s
```

**Voiceover (15 sec, ~38 words):**

"Last night, an AI agent I built found a fake Microsoft service hiding on a real Windows server. Then it caught itself making a mistake on the next finding. Then it drafted a rule so it gets the next case right. Here is how."

**Notes:** keep the cold open quiet for the first 2 seconds; let the dashboard animation in. The voiceover starts on the third second. This beat is the hook; if Rob clicks away after 15 seconds, he should still know what the project is.

### Beat 2: Architecture sketch (0:15 to 1:00)

**Visual:** Cut to `sentinel.sshub.dev/site/architecture.html` (the existing architecture diagram). Use the page's natural layout. Hover-highlight the three architectural guardrails as the voiceover names them.

**Playwright scene:**
```
navigate https://sentinel.sshub.dev/site/architecture.html
viewport 1920x1080
wait 1s
hover Capability Token block (label: "MCP boundary")
wait 4s
hover INJECTION_QUARANTINE block (label: "Critic injection scanner")
wait 4s
hover Hash-chained ledger block (label: "Integrity ledger")
wait 4s
slow scroll-down through the diagram
```

**Voiceover (45 sec, ~115 words):**

"Sentinel runs the autonomous incident response loop with three architectural guardrails, not just prompt promises. First: every tool call crosses a capability-token boundary at the MCP server, scoped to the case ID and the allowed paths. Second: an injection scanner sits in the Critic and quarantines tool output that looks adversarial, before that output ever reaches the LLM that interprets findings. Third: every step of every run is hash-chained into an integrity ledger, so a finding can be traced back to the exact tool execution that produced it. The loop itself is six nodes: extract, plan, execute, interpret, critic, and learn. The critic and the learn nodes are where the autonomy lives."

**Notes:** the existing architecture page is dense (3870 lines). For this beat, just slow-scroll past it; the voice carries the meaning. Do not pause to read box labels.

### Beat 3: Case walkthrough (1:00 to 4:00)

This is the longest and highest-stakes beat. The case walks through `srl-2018-base-rd-02-dual` from the viewer.

#### 3a. Findings overview (1:00 to 1:30)

**Visual:** Navigate to the viewer at `sentinel.sshub.dev/viewer/`, open the rd-02-dual-002 case. Show the case header with finding counts, then the first finding card (the msadvapi2_32 Windows service masquerade).

**Playwright scene:**
```
navigate https://sentinel.sshub.dev/viewer/
click case "srl-2018-base-rd-02-dual"
click run "srl-2018-base-rd-02-dual-002"
wait 1s
slow scroll to first finding (msadvapi2_32 service)
hover the "high confidence" pill
wait 2s
```

**Voiceover (30 sec, ~78 words):**

"The case: a Windows server from a 2018 enterprise compromise. The agent ran in dual-channel mode, looking at both the disk image and a memory snapshot in the same run. It produced five findings. The first one is a Windows service called Microsoft Advanced API thirty-two, set to auto-start, running a binary called msadvapi2_32.exe out of Program Files. That product does not exist. The agent flagged it with high confidence."

#### 3b. Audit trail trace (1:30 to 2:15)

**Visual:** Click the cited tool_call_id `3f7dcb35...` on the first finding. Show the underlying evidence record: the full RegRipper output that contains the ImagePath, the timestamp, and the auto-start flag. Then click the second cited record (`79f5484f...`) and show the memory-side pslist confirming the process is running at PID 2292.

**Playwright scene:**
```
click tool_call_id "3f7dcb35-8b1b-4222-9aca-e8631047f8f5" on first finding
wait 2s
slow scroll through the evidence record (RegRipper services output)
wait 4s
click tool_call_id "79f5484f-9a1c-419d-b640-e065199c71ee"
wait 2s
slow scroll to the pslist row showing msadvapi2_32.e PID 2292
wait 3s
go back to findings list
```

**Voiceover (45 sec, ~115 words):**

"Every finding is a citation. Click the citation and you reach the actual tool output that produced it. Here is the RegRipper services dump where the service was registered. ImagePath, type, start mode, all there. Click the second citation, and you are in the memory-side pslist. The same binary, msadvapi2_32, is running right now at PID 2292. Disk says it should be running. Memory confirms it is running. That is what dual-channel means here. Notice the timestamps on the two services. Both installed within eighteen seconds of each other on May eighth, 2018. That is one attacker installation event, not two unrelated services."

#### 3c. The self-correction sequence (2:15 to 3:15)

**Visual:** Scroll to the bottom of the case to the "Critic disagreements" section. Show the three escalation events. Then specifically click into the INJECTION_QUARANTINE event and show the flagged byte substring (`T1033` in raw regf binary noise). Explain why this fired and why the agent escalated to human review instead of silently dropping the finding.

**Playwright scene:**
```
slow scroll to "Critic disagreements" section
wait 2s
zoom-pan to the INJECTION_QUARANTINE event row
wait 3s
click the event to expand the flagged excerpt
wait 4s
zoom-pan to the byte substring "T1033" highlighted
wait 5s
slow scroll to the three "critic_disagreement" escalation events
wait 5s
```

**Voiceover (60 sec, ~155 words):**

"Now the self-correction. While the agent was producing findings, the critic noticed something in one of the tool outputs. A byte sequence in the raw registry hive contained the substring T1033, which matches the pattern the injection scanner uses to detect adversarial prompt content trying to inject MITRE technique IDs. In this case, the substring was random binary noise from a regf hive, not a real injection. But the agent did not silently dismiss it. It quarantined the tool output, escalated to human review, and refused to act on findings that depended on it until a human cleared the quarantine. That is the architectural guardrail firing. A prompt-only system would have let this through, or worse, treated the injected technique IDs as real evidence. Three findings escalated. None were silently approved. That is what auditable autonomy looks like."

#### 3d. Cross-host corroboration (3:15 to 4:00)

**Visual:** Open a second viewer tab to the `srl-2018-base-file` case. Show the same Microsoft Advanced API service masquerade finding on a SECOND host, found independently by a different run. Side-by-side compare the two findings.

**Playwright scene:**
```
open new tab https://sentinel.sshub.dev/viewer/
click case "srl-2018-base-file"
click run "srl-2018-base-file-005"
wait 1s
scroll to the msadvapi2 service finding
arrange both viewer tabs side-by-side
wait 8s
```

**Voiceover (45 sec, ~115 words):**

"One more thing. The agent ran on the file server in the same network, in a separate session, with no shared state. It found the same msadvapi2 kit. Same fake Microsoft naming pattern, same paired thirty-two and sixty-four bit service, same auto-start configuration. That cross-host signal was not engineered. The agent reached it independently on each host, with separate evidence chains, and the audit trail from both runs lines up. For an analyst, this is the strongest evidence we have that the agent is not just confidently wrong. It is confidently right, and the corroboration emerges from the data, not from a heuristic that was pre-baked."

### Beat 4: Loop closing live (4:00 to 4:45)

**Visual:** Cut back to the dashboard at `sentinel.sshub.dev/site/dashboard.html`. Show the 4-widget board, then scroll to the drafted rules section. Pick one rule from the list (recommend `apt28_cve_2026_32202_lnk_spoofing_task` or any unrejected one). Click Approve. The confirm modal opens. Click "Yes, promote." Watch the card disappear, the queued widget decrement, the live widget increment.

**Playwright scene:**
```
navigate https://sentinel.sshub.dev/site/dashboard.html?cb=demo
wait 2s
slow scroll past hero + widgets (so the camera pans down)
wait 1s
arrive at drafted-rules section
hover the apt28_cve_2026_32202 card
wait 2s
click Approve
wait 1s
modal opens with rule preview
wait 3s
click "Yes, promote"
wait 1s
card disappears, queued count decrements, live count increments
wait 2s
```

**Voiceover (45 sec, ~115 words):**

"And the loop closes here. Every night, the cron at 22:30 UTC runs the agent against fresh threat intel from CISA, Rapid7, GitGuardian, the public KEV. When it misses something, a drafter agent synthesizes a candidate rule from the miss and stages it. Today, twelve rules are waiting. I read one, decide it is safe, click approve. The rule is now in the live agent's rule store. Tomorrow night's run picks it up automatically. The widget counts update in front of you. This is not a demo, this is the production system. The whole loop runs on the same dashboard you are watching."

**Notes:** the apt28 rule is a counter_rule, so the audience sees the kind-badge label "teaches INTERPRET to flag this TTP as malicious." Pick it deliberately because the "what this changes" caption is the most legible to a judge.

### Beat 5: URLs and outro (4:45 to 5:00)

**Visual:** Static end-card with three lines stacked: "sentinel.sshub.dev (live)", "github.com/charanbobby/sift-sentinel (code)", "Charan Bobby (linkedin URL)". White text on dark background, IBM Plex Mono.

**Playwright scene:**
```
display end-card image (15 seconds)
```

**Voiceover (15 sec, ~38 words):**

"Sift Sentinel. Live at sentinel.sshub.dev. Code on GitHub at github.com/charanbobby/sift-sentinel. Built by Charan Bobby for the SANS Find Evil hackathon. Thanks for watching."

## Production checklist

**Ordering principle:** visuals first, voice last. ElevenLabs voice generation is the most token-expensive step and the hardest to iterate on, so all other elements (scene recordings, timings, captions, transitions, end-card) get locked before any voice is generated. Probe before each step; do not advance without a verified result.

### Phase A: pre-record probes (no recording yet)

A1. Probe: `curl -sI https://sentinel.sshub.dev/site/dashboard.html` returns 200 and the `last-modified` header is recent. Probe: `curl -s /api/proposed-rules | head` returns the staged rules.
A2. Probe: rd-02-dual-002 appears in `viewer/keep_runs.json` on the VPS (`ssh sri@vps grep srl-2018-base-rd-02-dual /opt/find-evil/repo/.../keep_runs.json`). If missing, fix before recording.
A3. Probe: pick the specific rule to promote in beat 4 by checking the live `/api/proposed-rules` response. Recommend `apt28_cve_2026_32202_lnk_spoofing_task-c99bf8f051` (counter_rule, easy-to-explain ATT&CK tie-in) IF still pending. Confirm it has not been already approved or rejected since the spec was written.
A4. Probe: Playwright server starts and a one-frame screenshot of dashboard.html captures successfully at 1920x1080. This is the cheap fail-fast for the recording rig.

### Phase B: scene recording (silent, no voice yet)

B1. Record each Playwright scene as a separate MP4 at 1920x1080, 30fps, no audio. One file per beat: `scene1_open.mp4` through `scene5_outro.mp4`.
B2. After each recording: probe the file plays cleanly, has the expected scene length, and contains no Cloudflare cache miss frames. Re-record if any frame shows the wrong content.

### Phase C: silent assembly + timing verification

C1. In Studio, place all 5 silent MP4s end-to-end on the visuals track. Total length BEFORE voice should be at most 4:55 (leaving 5 seconds of buffer for the voice to settle).
C2. Probe: read the timeline cursor at each beat boundary. The timestamps should be 0:00, 0:15, 1:00, 4:00, 4:45, 5:00 plus or minus 1 second.
C3. If any beat is over budget: trim the scene (Playwright wait shortened, scroll faster) before moving on. If under budget: accept (silence is fine; voice will fill).
C4. Generate placeholder audio: a silent WAV file matching the locked length of each beat. Drop into Studio audio track 2. This proves the voice slots fit.
C5. Probe: scrub the timeline at 0:15, 1:00, 4:00, 4:45 boundaries. The visuals at each boundary match what the voiceover lines describe. If a visual mismatch exists (e.g., voiceover says "click apt28" but the scene has scrolled past it), fix the scene now, before voice.

### Phase D: captions (burned in, not soft track)

D1. Generate the SRT file from the voiceover text. Keep caption lines under 80 chars per line, max 2 lines on screen at once.
D2. Pick a caption style that reads cleanly over the dashboard's dark background: white text, semi-transparent black box behind, IBM Plex Sans regular, ~24pt at 1080p, anchored to the lower third (avoid covering the dashboard's top nav and the rule cards mid-page).
D3. Drop the SRT into Studio. Render captions as a burned-in overlay on the visuals track, NOT as a soft track. Captions must be part of the rendered video so they show up on Devpost, YouTube, anywhere the file plays, with no viewer-side toggle needed.
D4. Probe: scrub timestamps 0:15, 1:00, 4:00, 4:45. Caption text matches the voiceover line for that moment. Caption does NOT cover dashboard chrome (top nav, hero, widget board labels, rule-card kind badges).
D5. Read every caption line aloud yourself. If a line is awkward to read, change the script HERE (before generating voice). The voiceover line is the line in the burned-in caption, so the caption is the truth and they cannot drift apart later.
D6. Burn the captions into the silent visuals track now (Phase D, before voice). This way the timing of the caption text against the visuals is locked, and Phase E only needs to layer audio on top. Re-burning captions requires a video re-export, which is cheap; re-generating voice burns ElevenLabs tokens, which is not.

### Phase E: voice generation (the expensive step)

E1. Confirm Phase C and Phase D are locked. Do not proceed if any boundary is still being moved.
E2. Generate ElevenLabs audio for each beat as a separate file, one per beat. Name them `voice1_open.mp3` through `voice5_outro.mp3`.
E3. Probe per file: total length matches or is shorter than the beat slot (leave 1-2 sec of breathing room at the end).
E4. If a beat's voice is too long: shorten the script TEXT (not the voice; regenerating burns more tokens). Re-generate that ONE beat only.
E5. Replace the placeholder silent WAV in Studio with the ElevenLabs MP3 per beat.

### Phase F: final assembly + export

F1. Final probe: full timeline plays end to end at 5:00 with no audio gaps, no caption desyncs, no jump cuts mid-voice.
F2. Add a one-frame end-card image (PNG, 1920x1080, dark, IBM Plex Mono) for beat 5.
F3. Export at 1080p H.264, target file size under 200 MB.
F4. Upload to YouTube as unlisted, paste the URL into `docs/submission/devpost-description.md` under the Demo Video field.

### Probe-budget summary

| Phase | Probes | Cost |
|---|---|---|
| A | 4 cheap HTTP + grep checks | $0 |
| B | 5 file integrity checks per recording | $0 |
| C | 5 timeline scrubs | $0 |
| D | 1 SRT validation, manual read-aloud | $0 |
| E | 1 voice gen per beat (5 total), re-gen only the beats that drift | ElevenLabs tokens |
| F | 1 final playthrough, 1 export, 1 upload | $0 |

ElevenLabs voice tokens are the only paid cost in this pipeline. Phase E runs LAST and only on the locked script. Re-generations only happen when a single beat needs a re-cut, never the whole video.

## Out of scope

- Live terminal demo (too slow for 5 minutes; the dashboard scenes carry the same content visually).
- Code walkthrough (covered by the GitHub link).
- Founder interview / talking-head shots (no founder-on-camera segment requested).
- Architecture diagram redesign (use the existing architecture.html as-is for beat 2).

## Open questions

None remaining. Brainstorming closed the audience (Rob T. Lee, single judge), the arc shape (open + arch + case + loop + outro), the case spine (rd-02-dual-002), the recording method (Playwright + ElevenLabs + Studio), and the timing budget. Charan reviews this draft, then writing-plans skill generates the implementation plan (Playwright record commands per beat, ElevenLabs API calls per beat audio, Studio cut-list).
