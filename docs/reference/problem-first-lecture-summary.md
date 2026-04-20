Here is a cleaned, structured, and standardized version of your document. I’ve removed repetition, normalized formatting, clarified wording, and made it easier to scan and reuse.

**AI Course – Lecture Summaries (Cleaned Version)**

**Lecture 1: AI Foundations**

**Overview**

Introduces core AI concepts, terminology, and frameworks. Covers LLM training, tokens, evaluation methods, and the shift toward applied AI systems.

**Key Concepts**

**1. Evolution of AI Systems**

- **2023:** Chatbots (basic conversational interfaces)
- **2024:** Assistants (workflow support, integrations)
- **2025:** Teammates (handle ambiguous processes)
- **2026:** Proactive AI (learning, adapting, acting independently)

**Trend:** Shift toward **vertical AI (industry-specific)** and **departmental AI (function-specific)**
**Principle:** Go deep in a niche rather than broad across use cases

**2. AI Hierarchy**

Artificial Intelligence

└── Machine Learning

└── Neural Networks

└── Deep Learning

└── Generative AI

└── Agentic AI

**3. LLM Training Phases**

- **Pre-training** – Large-scale data learning
- **Supervised Fine-Tuning (SFT)** – Instruction alignment
- **RLHF** – Optimization via human feedback

**4. Tokens & Context**

- Tokens ≈ 4 characters
- Context window = max tokens processed
- Larger context = higher cost

**5. Model Evaluation**

- **Model Evals:** Benchmarks (MMLU, GSM8K)
- **Product Evals:** Application-specific performance

**6. Input / Output Framework**

Examples:

- Text → Text (LLMs)
- Text → Image (DALL·E)
- Image → Text (Vision models)
- Multimodal → Multimodal

**7. Key Insight**

**Agentic AI = Generative AI + Tools + Memory + Planning**

**Important Distinctions**

- Training vs Inference
- Base vs Fine-tuned models
- Tokens vs Parameters
- Model vs Product evaluations

**Lecture 2: Building AI Applications**

**Overview**

Explains how AI systems differ from traditional software and introduces design frameworks for building reliable AI products.

**Key Concepts**

**1. Non-Determinism**

- Same input → multiple valid outputs
- Challenge: enterprises need consistent behavior

**2. Agency vs Control**

- Higher autonomy → lower control
- Increase autonomy only with proven reliability

**3. Common AI Issues**

- Hallucinations
- Sycophancy
- Prompt sensitivity
- Bias
- Latency

**Core Framework: Iterative Development**

BUILD → DEPLOY → OBSERVE → IMPROVE

- Continuous Calibration (CC/CD)
- Start with low autonomy, increase gradually

**Model Selection**

Primary factors:

- Cost
- Latency
- Performance

Guideline:

Start with mid-sized hosted models before optimizing

**Data & Context**

- Data defines application design
- Minimum: **50–60 real examples before decisions**

**Design Priorities**

- Effort (prototype fast)
- Performance
- Cost / latency

**Lecture 3: Context & Prompt Engineering**

**Overview**

Focuses on **context engineering** as the core discipline for AI systems, with deep coverage of prompting techniques.

**Context Engineering**

Answers:

- What should the AI do? (instructions)
- What should it know? (data, memory)
- How should it act? (tools)

**Principle:** Context must be **relevant, compact, and structured**

**Prompt Engineering Evolution**

- Level 1: Basic prompting (zero/few-shot)
- Level 2: Techniques (CoT, decomposition, ensembling)
- Level 3: Meta prompting (AI generates prompts)
- Level 4: Automated optimization
- Level 0: Self-reasoning models

**Key Techniques**

- Chain of Thought (step-by-step reasoning)
- Decomposition (plan before execution)
- Ensembling (multiple runs for accuracy)

**Best Practices**

- Keep prompts clear and structured
- Use meta-prompting tools
- Place static instructions at the top (for caching)

**Lecture 4: Workflow Agents & Evals**

**Agent Types**

**Workflow Patterns**

- Prompt chaining
- Routing

Best for:

- Predictable processes
- Low-risk applications

**Evaluation Framework**

**Pre-Deployment**

- Create dataset
- Run system
- Design evals
- Align rubrics
- Human review
- Automate evals

**Post-Deployment Flywheel**

User Signals → Sample Logs → Run Evals → Improve → Repeat

**Key Insight**

- Evals are **dynamic systems**, not static tests

**Lecture 5: RAG Foundations**

**Overview**

Introduces Retrieval-Augmented Generation (RAG) for handling large knowledge bases.

**RAG Pipeline**

- **Ingestion:** chunk + embed data
- **Retrieval:** find relevant chunks
- **Generation:** produce response

**Key Metrics**

**Retrieval**

- Precision
- Recall
- MRR
- NDCG

**Generation**

- Faithfulness
- Relevance
- Fluency

**Key Guidelines**

- Most issues = **retrieval problems (~80%)**
- Chunk size = 5–10× expected answer size
- Avoid embedding structured tables

**Lecture 6: Advanced RAG**

**Diagnosis Framework**

Can a human answer from retrieved data?

→ Yes → Generation issue

→ No → Retrieval issue

**Common Issues**

**Coverage Problems**

- Missing relevant data
- Fix: query expansion, increase retrieval size

**Quality Problems**

- Too much noise
- Fix: re-ranking, filtering

**Advanced Approaches**

- Hybrid search (keyword + semantic)
- Corrective RAG
- Agentic RAG vs Graph RAG

**Memory Systems**

- Working
- Episodic
- Semantic
- Procedural

**Lecture 7: Autonomous Agents & MCP**

**Autonomy Decision Factors**

- Process clarity
- Risk level
- Observability
- Infrastructure
- Cost / latency

**MCP (Model Context Protocol)**

Standard for connecting AI to tools.

**Architecture:**

Host → Client → Server → Tools

**Challenges**

- Context bloat (too many tools)
- Security risks (tool poisoning, permissions)

**Solutions**

- Code execution agents
- Agent skills (modular tool loading)

**Lecture 8: Multi-Agent Systems & Scaling**

**When to Use Multi-Agent Systems**

- Need parallelization
- Single agent overloaded
- Requires critique / validation

**Patterns**

- Hierarchical (recommended)
- Flat (experimental, unstable)

**Stateless Subagents**

- Agents as tools
- Isolated context
- Easy to debug and scale

**Optimization Hierarchy**

- Prompt improvements
- More LLM calls
- Retrieval systems
- Autonomous agents
- Fine-tuning (last resort)

**RAG vs Fine-Tuning**

- **RAG:** external knowledge
- **Fine-tuning:** behavior/style

**Production Principles**

- Track token usage, latency, errors
- Build observability early
- Apply standard engineering practices + AI-specific evals

**Overall Summary**

- AI systems are **non-deterministic**, requiring iterative design
- **Context engineering** is the core discipline
- Start simple: workflows → RAG → agents → multi-agents
- Prioritize **evaluation and calibration over initial build**
- Optimize in stages before moving to complex solutions
