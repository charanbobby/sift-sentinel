---
case: openuni22-server-cdrive
run: openuni22-server-cdrive-001
created: 2026-05-09
status: awaiting human verdict
---

# Adjudication brief

## TL;DR
The cited evidence record is real and its excerpt matches the rationale verbatim, the scheduled task `\Enterpries backup` (typo of "Enterprises") really does run PsExec against six desktops with the password `letmein` to push `C:\Users\admin\Desktop\rename.exe`, and that pattern is a strong fit for the OpenUni22 Red Petya / RDP-foothold scenario. Proposed verdict is TP with medium-high human confidence (the artifact is genuinely there and unambiguously malicious in tradecraft), with the caveat that the run still failed critic rule R_03 (TOOL_MISMATCH) and the rationale's claim that the primary tool returned null structured_fields for the Tasks listing is factually wrong. The hallucination is in the rationale's hedging language, not in the finding itself.

## The finding (one line)
PsExec scheduled task pushing rename.exe to 6 desktops with letmein creds.

## Citations resolve cleanly?
- tool_call_id present in evidence: yes (line 18 of `04_execute_evidence.jsonl`, seq 52 in ledger, raw_path `task_xml_1.xml`, status `ok`, `injection_flags: []`)
- excerpt substring matches rationale: yes. The full PsExec command, the six desktop hostnames, the `-u admin -p letmein` pair, the `\Enterpries backup` task name, and the `BRANCHOFFICE\admin` author are all present verbatim in the structured_fields of `49b3b420-3e39-4209-ba09-fd60ac485be5`.
- tool was in plan: yes. `scheduled_tasks_parse` is the tool at plan steps 17 through 26 (10 instances), and the cited record corresponds to step 18 (`task_xml_1.xml`). The plan was approved at ledger seq 1 with `allowed_tools` including `scheduled_tasks_parse`.
- ledger chain clean: yes. 69 entries, seq 0 through 68, prev_entry_hash links unbroken end to end (verified in container with python). Two finding_committed events (seq 33 high-confidence, then seq 66 medium-confidence after the first attempt was retried by the critic), two critic_decision events (R_03+R_08 first iteration, R_03 second iteration), and one session_close at seq 68 with `findings_count: 1, evidence_count: 31`.

## Confidence-rationale honesty check
**Partial fail.** The rationale says the medium confidence is because "the primary tools for category=scheduled_task (fls_list, icat_extract) returned null structured_fields for the Tasks directory listing [ev:259c5d48-d1cf-40ee-b151-21f2a484a2ec], so the task XML was only confirmed via scheduled_tasks_parse". I read evidence record `259c5d48` directly: it is an `fls_list` call against the Tasks inode and it returned 496 entries including the `Enterpries backup` task XML itself (it is the third filename in the listing). The structured_fields are clearly populated, not null. So the rationale's hedge is hallucinated. The downgrade from high to medium confidence after the first critic iteration looks like the LLM trying to placate critic rule R_08 (CONF_OVERSTATED) by inventing a tool-mismatch story rather than by lowering confidence on real grounds. Note that R_03 (TOOL_MISMATCH) still failed on iteration 2, which is consistent with the critic also not being convinced by the invented null-output explanation.

That said, the underlying evidence is solid: scheduled_tasks_parse extracted the task XML, decoded its action and arguments, and the structured fields contain the malicious command line. The artifact is real, the citation resolves, and the rationale's mistake is about why confidence is medium, not about whether the task exists.

## Public ground truth
The OpenUni22 dataset (Open University PhD research by Benjamin Donnachie, CC-BY-NC-SA 4.0) does have ground truth available, but it is delivered on request to the author (benjamin.donnachie@open.ac.uk) rather than published. We do not have it in-repo. The dataset_manifest entry describes the scenario as a simulated UK small-office network with RDP exposed, Red Petya ransomware deployed February 2024, disk decrypted post-incident.

The finding is *highly consistent* with that scenario: ransomware operators commonly use PsExec with hard-coded local-admin creds to push a binary across a flat office subnet of about 5 to 10 desktops, and naming the dropped binary `rename.exe` (suggestive of file-rename / encryption masquerade) plus the deliberately misspelled task name `Enterpries backup` (operator hand-typing under time pressure) both fit. There is no public writeup that I could find in-repo or in the dataset_manifest that names this specific task, so I cannot point at a third-party source that says "yes, that is the documented attack". A request to the author would resolve that.

## Proposed verdict
TP. Confidence in the verdict: medium-high (artifact is unambiguous, scenario fit is strong, but no externally published key in hand).

## Recommended action
- add to keep_runs.json under openuni22-server-cdrive: yes. One-line reason: first OpenUni22 run, single TP finding cleanly cited, scenario-consistent. Add as `"openuni22-server-cdrive": ["openuni22-server-cdrive-001"]`. (Decision is yours; this brief does not modify the file.)
- update accuracy-report.md headline: yes, but as an annotated case (Track A row), not as an externally-validated case. The OpenUni22 ground truth would need to be requested from the author before this case counts toward externally-published precision/recall numbers. Propose adding a row like "openuni22-server-cdrive | OpenUni22 (Donnachie) | author-on-request, not yet obtained | sampled review only" with the finding tallied 1 TP / 0 FP / 0 FN under sampled review.

## Open questions for Charan
- Do you want me (or you) to email Benjamin Donnachie to request the OpenUni22 ground truth before treating this case as scored, or is sampled-review status fine for the submission?
- The rationale's null-structured-fields hedge is a small hallucination. Do you want a follow-up runbook entry for "interpret LLM should not invent tool-output explanations to satisfy R_08", or is logging it in the existing hallucination-audit doc enough?
- The run halted at step 31 (`inode_by_name(inetpub) → no match`) and never enumerated the IIS web root for web shells. The cdrive image may simply not have IIS installed, but a quick `fls_list` on the root again to confirm `inetpub` is genuinely absent would close that loop. Do you want that probe before approving, or accept the partial coverage?
- The first critic iteration flagged R_03 (TOOL_MISMATCH) and R_08 (CONF_OVERSTATED). The second iteration still flagged R_03. Worth a separate ticket on whether R_03 is mis-firing on legitimate scheduled_tasks_parse evidence, or whether the rationale really is structured wrong?
