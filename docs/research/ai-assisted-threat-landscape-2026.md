# AI-Assisted Attacker Threat Landscape — 2025-2026 Evidence Review

**Captured:** 2026-04-24
**Purpose:** Ground-truth the project's "attacker uses AI" positioning with published incident reports and threat intel, rather than hand-waving. Primary input for scoping `Step 3b — AI-Assisted Attacker Detection` in the Slice 6 runbook.

---

## Investigative question

> Do AI-assisted attackers leave forensically-recoverable traces on the **victim's** disk — or does their AI use happen entirely on the attacker's own infrastructure?

Answer upfront: **Both**, but the victim-side traces are now confirmed in multiple 2025-2026 in-the-wild samples. The earlier assumption ("AI lives on the attacker's side only") is no longer correct as of Q1 2026.

---

## Confirmed AI-calling malware in the wild

These are samples where the malware itself **calls an LLM API at runtime** from the compromised host. Recoverable forensic artifacts: API endpoints in strings, API keys in config, SDK imports, prompt fragments in memory.

| Sample | Actor / Report | LLM used | What it does |
|---|---|---|---|
| **PROMPTFLUX** | Google GTIG, Jun 2025 ([report](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools), [Help Net Security](https://www.helpnetsecurity.com/2025/11/05/malware-using-llms/)) | Google Gemini | VBScript dropper; calls Gemini API to rewrite its own VBScript obfuscation hourly to evade static detection |
| **PromptSteal / LameHug** | APT28 (Russian GRU, Fancy Bear) | Hugging Face API (Qwen2.5-Coder-32B-Instruct) | Data miner; queries the LLM to generate one-line Windows commands, then executes them for recon + exfil |
| **PromptLock** | Google GTIG | Unspecified LLM | Uses an LLM to dynamically generate and execute malicious Lua scripts at runtime |
| **QuietVault** | Unit 42 ([report](https://unit42.paloaltonetworks.com/ai-use-in-malware/)) | On-host AI CLI tools + LLM prompts | Credential stealer; targets GitHub/NPM tokens AND **uses on-host-installed AI CLI tools** with AI-prompt inputs to hunt additional secrets on the victim |
| **MalTerminal** | Researchers, Sept 2025 ([gbhackers](https://gbhackers.com/malterminal-new-gpt-4/), [THN](https://thehackernews.com/2025/09/researchers-uncover-gpt-4-powered.html)) | OpenAI GPT-4 | Dynamically generates ransomware + reverse-shell code at runtime via GPT-4 API. (Classified as potentially-PoC / not confirmed deployed; pattern is real.) |
| **Akamai-hunt variant** | Akamai Labs ([report](https://www.akamai.com/blog/security-research/new-malware-chat-completions-llm-shadow-ai)) | Unspecified (chat-completions endpoint) | Attempts to hide C2 behind a legitimate LLM API endpoint — Base64-encoded payload in what looks like a chat-completion request |

**QuietVault is the direct forensic analogue of the receptionist example** — it relies on AI tooling already installed on the victim, or installs it as part of the operation. The "AI CLI on a non-dev machine is anomalous" signal has direct threat-intel backing.

---

## Confirmed AI-generated malware (LLM-authored payloads)

Distinct from the above: the attacker used AI to *write* the payload on their side, and the output ends up on the victim with recoverable authorship artifacts.

| Sample | Report | Forensic signal |
|---|---|---|
| **VoidLink** | Check Point Research, 2026 ([report](https://research.checkpoint.com/2026/voidlink-early-ai-generated-malware-framework/)) | TRAE AI-IDE helper files shipped alongside source code via an exposed open directory. Code matched AI's code-standardization instructions. First clear evidence of an AI-assisted malware development environment leaking artifacts. |
| **Slopoly** (deployed by Hive0163) | The Hacker News, Mar 2026 ([report](https://thehackernews.com/2026/03/hive0163-uses-ai-assisted-slopoly.html)) | Ransomware post-exploitation; persistence >1 week. LLM-origin signs: extensive comments, thorough error handling, accurate variable naming, logging throughout — signatures of LLM authorship. |
| **EvilAI operators** | Trend Micro, Sept 2025 ([report](https://www.trendmicro.com/en_us/research/25/i/evilai.html)) | AI-generated code + fake apps used in wide-reach campaigns. |
| **First known AI-powered ransomware** | ESET ([report](https://www.welivesecurity.com/en/ransomware/first-known-ai-powered-ransomware-uncovered-eset-research/)) | First published in-the-wild AI ransomware. |

---

## Aggregate threat-intel reporting

| Report | Published | Key numbers / framing |
|---|---|---|
| **CrowdStrike 2026 Global Threat Report** ([blog](https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-global-threat-report-findings/)) | Feb 2026 | AI-enabled adversary operations **up 89% YoY**. 90+ organizations hit via prompt-injection on sanctioned GenAI tools. eCrime breakout time fell to **29 min average, 27 sec fastest**. 82% malware-free detections. |
| **Mandiant M-Trends 2026** ([report](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026)) | Mar 2026 | Nation-state AND financially-motivated actors using LLMs as "strategic force multiplier". Initial-access-to-handoff window down to 22 seconds. |
| **Anthropic: Detecting and countering misuse** ([Aug 2025](https://www.anthropic.com/news/detecting-countering-misuse-aug-2025)) | Aug 2025 | Provider-side evidence of threat actors using Claude for malware iteration — complements on-disk forensics. |
| **SentinelLabs: Prompts as Code & Embedded Keys** ([report](https://www.sentinelone.com/labs/prompts-as-code-embedded-keys-the-hunt-for-llm-enabled-malware/)) | 2025 | Published hunting playbook for LLM-enabled malware signatures. |
| **"Living Off the LLM"** ([arXiv](https://arxiv.org/html/2510.11398v1)) | Oct 2025 | Academic framing of the emerging tactic class; useful for the Accuracy Report's "Forward Look" section. |

---

## LangChain / LangGraph / Langflow as attack surface

The user's original "receptionist with LangChain" framing has an adjacent angle: **LangChain stacks themselves are now an attack surface.** Multiple CVEs exploited in 2025-2026:

- **CVE-2025-68664 "LangGrinch"** — serialization injection in `langchain-core.dumps()/dumpd()`. Secrets exfil + potential RCE. ([Hacker News](https://thehackernews.com/2025/12/critical-langchain-core-vulnerability.html), [Cyata writeup](https://cyata.ai/blog/langgrinch-langchain-core-cve-2025-68664/))
- **CVE-2026-34070** — path traversal in LangChain prompt-loading module.
- **CVE-2025-67644** — SQL injection in LangGraph SQLite checkpoint implementation.
- **CVE-2026-33017** — unauthenticated RCE in Langflow; exploited within **20 hours of advisory**, no public PoC needed. ([Security Boulevard](https://securityboulevard.com/2026/04/langchain-langflow-litellm-when-ais-foundation-code-becomes-the-attack-surface/))

Implication: finding a compromised LangChain-based agent on an enterprise endpoint is a credible 2026 incident type. Our pipeline detecting unusual LangChain installs on non-dev endpoints is directly on-threat.

---

## What this means for the pipeline

**Forensically-recoverable indicators we should look for in persistence artifacts:**

1. **LLM API endpoints in strings:**
   - `api.openai.com`
   - `api.anthropic.com`
   - `generativelanguage.googleapis.com` (Gemini)
   - `api-inference.huggingface.co`
2. **AI-SDK imports** (especially in scheduled tasks / Run-key payloads / service binaries):
   - `openai`, `anthropic`, `google.generativeai`, `langchain`, `langgraph`, `llama_index`
   - `transformers`, `huggingface_hub`
3. **API keys** in config folders:
   - `%USERPROFILE%\.openai\`, `%USERPROFILE%\.anthropic\`
   - Environment variable fragments: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `HUGGINGFACE_HUB_TOKEN`
4. **Prompt-like strings embedded in payloads:**
   - Long imperative English strings in binaries / scripts
   - "You are a helpful assistant..." style preambles
5. **On-host AI CLI tools on non-developer machines** (QuietVault pattern):
   - `chatgpt`, `claude`, `ollama`, `llm` binaries in PATH
   - ChatGPT/Claude Desktop `AppData` folders

**What this does NOT include:**

- Stylometric code classifiers for "was this written by an LLM?" — still high false-positive rate (Yang et al. 2024; Binoculars Hans et al. 2024). Our pipeline anchors on concrete artifacts (URLs, imports, keys), not writing style, specifically to avoid that false-positive class.

**Policy design: role-dependent expectations.** A developer workstation having `openai` imports is noise. A receptionist machine having them is signal. The pipeline needs a `machine_role` input (hard-coded per case for the hackathon; inferred from AD / OU / hostname conventions post-hackathon).

---

---

## Late-April 2026 refresh (added 2026-04-27)

Three days after the initial capture, four new items materially change the landscape. Captured here rather than rewriting the sections above so the diff is auditable.

### Vercel breach (April 19-20, 2026): AI tool as the supply-chain entry vector

The Vercel platform (used by hundreds of thousands of organizations to deploy web applications) disclosed a security incident on April 19, 2026. Attack chain (per Vercel's KB and Trend Micro analysis):

1. Lumma Stealer infected a Context.ai employee around February 2026 (the employee reportedly downloaded Roblox game exploit scripts).
2. Stolen credentials gave the attacker access to a Vercel employee's individual Google Workspace account, where the employee used Context.ai for productivity.
3. From the Workspace account the attacker pivoted into the employee's Vercel account.
4. Inside Vercel, the attacker enumerated and decrypted non-sensitive environment variables across customer projects.
5. A threat actor (using the "ShinyHunters" name; the real ShinyHunters group denies involvement) listed the data on BreachForums for $2M.

**Why this matters for the project:** Context.ai is an AI productivity tool (meeting / note-taking / context management). The breach is the first widely-reported case of an AI tool being the OAuth supply-chain entry vector into a major platform. It validates the project's premise that "AI tools on a non-developer endpoint are a forensically-recoverable anomalous signal" and adds a second class of indicator: AI-tool OAuth scopes on enterprise SaaS accounts.

**Sources:** [Vercel KB bulletin](https://vercel.com/kb/bulletin/vercel-april-2026-security-incident); [TechCrunch coverage](https://techcrunch.com/2026/04/23/vercel-says-some-of-its-customers-data-was-stolen-prior-to-its-recent-hack/); [BleepingComputer](https://www.bleepingcomputer.com/news/security/vercel-confirms-breach-as-hackers-claim-to-be-selling-stolen-data/); [The Hacker News tying it to Context.ai](https://thehackernews.com/2026/04/vercel-breach-tied-to-context-ai-hack.html); [Trend Micro OAuth supply-chain analysis](https://www.trendmicro.com/en_us/research/26/d/vercel-breach-oauth-supply-chain.html); [Help Net Security weekly review](https://www.helpnetsecurity.com/2026/04/26/week-in-review-claude-mythos-finds-271-firefox-flaws-vercel-breach/).

### CVE-2026-33626 LMDeploy SSRF: 12-hour weaponization window

GitHub published a Server-Side Request Forgery vulnerability in LMDeploy on April 21, 2026. Sysdig's honeypot observed the first exploitation attempt within 12 hours and 31 minutes of the advisory. The attacker used the vision-language image loader as a generic HTTP SSRF primitive to port-scan the internal network behind the model server, hitting AWS Instance Metadata Service, Redis, MySQL, an admin HTTP interface, and an out-of-band DNS exfiltration endpoint, all in an 8-minute session.

**Why this matters for the project:** continues the LangChain / Langflow / LiteLLM pattern of "agent-framework CVEs weaponized in hours, no public PoC needed." The CVE-2026-33017 row above (Langflow, 20-hour weaponization) is now joined by LMDeploy at 12.5 hours. Inference servers are first-class attack surface in 2026.

**Sources:** [Sysdig threat research writeup](https://webflow.sysdig.com/blog/cve-2026-33626-how-attackers-exploited-lmdeploy-llm-inference-engines-in-12-hours).

### LiteLLM PyPI supply chain (March 24, 2026)

`litellm==1.82.7` and `litellm==1.82.8` shipped on PyPI on March 24, 2026 with a multi-stage credential stealer for ~40 minutes before PyPI quarantined them. Attribution under investigation; possible link to TeamPCP, with speculation about a LAPSUS$ relationship. Adds a concrete supply-chain compromise to the LiteLLM CVE class already noted above.

**Sources:** [Sonatype writeup](https://www.sonatype.com/blog/compromised-litellm-pypi-package-delivers-multi-stage-credential-stealer); [LiteLLM official notice](https://docs.litellm.ai/blog/security-update-march-2026).

### Indirect prompt injection in the wild: 10 named payloads (Google + Forcepoint, April 24, 2026)

Google Security Blog and Forcepoint X-Labs each published catalogues of in-the-wild indirect prompt injection (IPI) payloads. Google reports a 32% relative increase in malicious IPI activity between November 2025 and February 2026. Forcepoint's X-Labs collection of 10 named payloads is the most concrete signal yet that IPI is not theoretical:

- A fully specified PayPal transaction payload, designed for AI agents with payment integrations.
- A meta-tag namespace injection combined with a "persuasion amplifier" keyword (`ultrathink`) routing AI-mediated financial actions toward a Stripe donation link.
- "Send me the secret API key" payloads aimed at leaking secrets the agent can access.
- Standard evasion tradecraft: 1-pixel text, near-transparent color, HTML comment burying, metadata smuggling.

**Why this matters for the project:** the pipeline's `INJ_BASE64_LONG` recalibration (decode-then-scan) handles the imperative-ignore + role-marker class. The **persuasion-amplifier class** (`ultrathink`-style keywords that are not directives but are designed to exploit the LLM's reasoning bias) is a new pattern not covered by the current scanner. Documented in `docs/submission/known-limitations.md` as a future-work item: extend the scanner to recognize known persuasion-amplifier tokens beyond the direct-directive vocabulary.

**Sources:** [Google Security Blog landscape report](https://security.googleblog.com/2026/04/ai-threats-in-wild-current-state-of.html); [Help Net Security summary](https://www.helpnetsecurity.com/2026/04/24/indirect-prompt-injection-in-the-wild/); [Infosecurity Magazine on the 10 payloads](https://www.infosecurity-magazine.com/news/researchers-10-wild-indirect/); [Forcepoint X-Labs blog](https://www.forcepoint.com/blog/x-labs/indirect-prompt-injection-payloads); [Unit 42 web-based IPI study](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/).

### Slopoly variant iteration via LLM (IBM X-Force, April 2026)

The Slopoly entry above is updated: IBM X-Force documented active LLM-driven variant iteration where the malware family generated multiple structurally distinct variants within days. Each variant has different variable names, control flow, and obfuscation, but identical payload functionality. Variants are auto-submitted to a sandbox; flagged variants are fed back to the LLM with a prompt to mutate. This is operational AI-evading-AI activity, not a research curiosity.

**Sources:** [IBM Think 2026 trends](https://www.ibm.com/think/insights/more-2026-cyberthreat-trends); [Microsoft "AI tool to attack surface" report](https://www.microsoft.com/en-us/security/blog/2026/04/02/threat-actor-abuse-of-ai-accelerates-from-tool-to-cyberattack-surface/).

### What this means for the synthetic adversary-AI workstation choice

- **LameHug remains the right mimicry target.** Hugging Face Inference API + Qwen2.5-Coder + LLM-generated PowerShell continues to be the most forensically-rich AI-attacker family for an endpoint-forensic demo. None of the new April 2026 items displace it.
- **Add one persuasion-amplifier injection bait to the workstation.** Layer 3 (the mimicry-of-Microsoft Description) is a good place for it: include an `ultrathink`-style keyword in the description text. The current scanner will not catch it (correctly, given the recalibration); the LLM should still classify it as `requires_disambiguation`. This becomes a documented honest miss in the limitations doc, alongside layer 5 nested encoding.
- **Add a "Context.ai-style OAuth indicator" to the AI-tradecraft layer (optional).** A scheduled task or Run key referencing an OAuth callback URL for a hijacked AI productivity tool. Lower priority than the existing 10 findings; consider only if the build session has spare time.

---

## Revision history

- 2026-04-24 — initial capture. Source: WebSearch against April 2026 threat reports; parallel research agent against training data through Jan 2026 (older cutoff, weaker signal). Live-search findings are authoritative; earlier training-data brief was stale and under-counted confirmed in-the-wild samples.
- 2026-04-27 — late-April refresh added: Vercel breach (Context.ai vector), CVE-2026-33626 LMDeploy SSRF, LiteLLM PyPI compromise, Google/Forcepoint 10 IPI payloads, Slopoly LLM variant iteration. Confirms LameHug remains mimicry target. Adds persuasion-amplifier injection class as a known scanner gap.
