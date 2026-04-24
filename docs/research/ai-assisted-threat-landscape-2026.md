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

## Revision history

- 2026-04-24 — initial capture. Source: WebSearch against April 2026 threat reports; parallel research agent against training data through Jan 2026 (older cutoff, weaker signal). Live-search findings are authoritative; earlier training-data brief was stale and under-counted confirmed in-the-wild samples.
