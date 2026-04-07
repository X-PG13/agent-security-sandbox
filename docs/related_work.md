# Related Work

## 1. Prompt Injection Attacks

### 1.1 Direct Prompt Injection
Perez & Ribeiro (2022) first systematically categorized prompt injection as a security vulnerability in LLMs, demonstrating that adversarial instructions embedded in user inputs can override system prompts. Subsequent work by Greshake et al. (2023) extended this to **Indirect Prompt Injection (IPI)**, where malicious instructions are planted in external data sources (emails, web pages, documents) that the LLM processes as context.

### 1.2 Indirect Prompt Injection (IPI)
Our work focuses on IPI in the context of tool-using agents. Key prior works include:

- **Greshake et al. (2023)** — "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection." Demonstrated IPI attacks through web content, emails, and documents against LLM-integrated applications. Our benchmark systematically covers the attack vectors they identified.

- **Zhan et al. (2024)** — **InjecAgent**: Proposed a benchmark of 1,054 test cases evaluating IPI in tool-integrated agents, covering direct and indirect attacks across 17 tools. Our framework differs by: (a) providing pluggable defense strategies rather than focusing solely on attack evaluation, (b) supporting function calling mode in addition to text ReAct, and (c) offering statistical analysis and composition studies of defenses.

- **Yi et al. (2023)** — **BIPIA (Benchmark for Indirect Prompt Injection Attacks)**: Created a benchmark dataset for evaluating indirect prompt injection in various application contexts. Our work builds on BIPIA's categorization of injection techniques while adding tool-gating defenses and automated judging.

### 1.3 Attack Taxonomies
Our benchmark implements 8 attack categories:
| Category | Related Prior Work |
|----------|-------------------|
| Data Exfiltration | Greshake et al. (2023), InjecAgent |
| Task Hijacking | BIPIA, Greshake et al. (2023) |
| Privilege Escalation | InjecAgent (tool misuse scenarios) |
| Denial of Service | Novel in our framework |
| Social Engineering | Greshake et al. (2023) |
| Multi-step Attacks | InjecAgent (indirect attacks) |
| Adaptive/Encoding | BIPIA (encoding variants) |
| **Evasion** (new) | Novel: authority impersonation, encoding, stealth injection |

## 2. Defense Strategies

### 2.1 Prompt-Level Defenses
- **Spotlighting** (Hines et al., 2024): Marking untrusted content with delimiters or encoding to help the LLM distinguish between instructions and data. Our D1 implements three spotlighting variants (delimiter, datamarking, Base64 encoding).

- **Sandwich Defense**: Repeating the user's original goal before and after untrusted content to anchor the model's attention. Our D5 implements this with configurable delimiters and warnings.

- **Instruction Hierarchy** (Wallace et al., 2024): Training models to prioritize system-level instructions over user-level or tool-level content. This is complementary to our approach; we evaluate defense strategies that can be applied without model fine-tuning.

### 2.2 Tool-Level Defenses
- **Policy Gates**: Whitelisting allowed recipients, restricting high-risk operations, and enforcing parameter constraints. Our D2 implements configurable policy gating.

- **Task Alignment** (our D3): Using a secondary LLM call to verify whether a proposed tool call aligns with the original user goal. Related to "self-reflection" approaches in LLM safety literature.

- **Re-execution Verification** (our D4): Running a second LLM instance on the same context without the potentially-injected content to see if it would make the same tool call. Inspired by ensemble-based verification approaches.

### 2.3 Content-Level Defenses (New)
- **Output Filtering** (our D6): Content-based heuristic scanning of outgoing tool parameters for injection echoes, exfiltration patterns, and secret leakage. Extends traditional output filtering to the agent tool-call context.

- **Input Classification** (our D7): Scoring incoming content (tool outputs, email bodies) for injection indicators before it reaches the LLM. Related to:
  - **Prompt Guard** (Meta, 2024): A classifier model for detecting prompt injection and jailbreak attempts. Our D7 uses heuristic scoring rather than a trained classifier, making it model-independent but potentially less accurate.
  - **Rebuff** (2023): An open-source framework for detecting prompt injection using multiple detection layers. Our approach is lighter-weight and integrated into the defense pipeline.

### 2.4 Defense Composition
Our composition study examines how combining multiple defenses affects security-utility tradeoffs. This relates to:
- **Defense in depth** principles from traditional cybersecurity.
- Ensemble approaches in adversarial ML (Tramèr et al., 2020).
- Our novel contribution is measuring **super-additivity** vs. **diminishing returns** when combining IPI defenses.

## 3. Evaluation Frameworks

### 3.1 Agent Benchmarks
| Framework | Cases | Defenses | Judging | Function Calling | Composition Study |
|-----------|-------|----------|---------|-----------------|-------------------|
| **InjecAgent** | 1,054 | 0 | Rule-based | No | No |
| **BIPIA** | ~500 | 0 | Rule + LLM | No | No |
| **AgentDojo** (Debenedetti et al., 2024) | 97 | 0 | Task-specific | Yes | No |
| **PromptBench** (Zhu et al., 2024) | Varies | 0 | Accuracy | No | No |
| **Ours (ASB)** | 565 | 11 (D0-D10) | Rule + LLM + Composite | Yes | Yes |

Key differentiators of our framework:
1. **Defense-centric**: Unlike prior benchmarks that focus on attack evaluation, we provide 11 pluggable defense strategies with standardized evaluation.
2. **Composition analysis**: We systematically study how defense combinations interact.
3. **Dual evaluation mode**: Support for both text ReAct and function calling.
4. **Multi-layer judging**: Rule-based, LLM-based, and composite judges with configurable strictness.
5. **Statistical rigor**: Confidence intervals, McNemar's test for defense comparison, Kendall's tau for agreement analysis.

### 3.2 LLM Safety Evaluation
Our work complements broader LLM safety benchmarks:
- **HarmBench** (Mazeika et al., 2024): Focuses on direct harmful content generation, not tool-use manipulation.
- **TrustLLM** (Sun et al., 2024): Comprehensive trustworthiness evaluation across multiple dimensions, but limited coverage of IPI in tool-using agents.

## 4. Positioning of Our Work

Our contribution occupies a unique position at the intersection of:
1. **IPI attack benchmarking** (extending BIPIA/InjecAgent with more attack types and evasion techniques)
2. **Defense strategy evaluation** (providing a systematic comparison of 11 defense strategies, with a matched 250-case subset for cross-defense fairness)
3. **Defense composition** (novel study of how defenses interact when combined)
4. **Practical agent security** (supporting function calling mode used in production deployments)

We address a gap in the literature: while prior work has extensively cataloged IPI attacks, there has been limited systematic evaluation of defense strategies, especially their composition effects and security-utility tradeoffs.
