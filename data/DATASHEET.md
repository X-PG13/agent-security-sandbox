# Datasheet for ASB Benchmark

Following the "Datasheets for Datasets" framework (Gebru et al., 2021).

## Motivation

**Why was the dataset created?**
To provide a comprehensive benchmark for evaluating defenses against Indirect Prompt Injection (IPI) in tool-using LLM agents. Existing benchmarks (InjecAgent, AgentDojo) evaluate few defenses; ASB enables controlled comparison of 11 defense strategies.

**Who created the dataset?**
Yifan Zhao, as part of the Agent Security Sandbox research project.

**Who funded the creation?**
Self-funded research project.

## Composition

**What do the instances represent?**
Each instance represents a simulated task for an LLM agent. Attack cases contain adversarial injections embedded in untrusted content; benign cases contain legitimate tasks.

**How many instances are there?**
- 565 total: 352 attack cases + 213 benign cases
- 20 JSONL files organized by category

**What data does each instance consist of?**
- `id`: Unique identifier
- `type`: "attack" or "benign"
- `goal`: The user's task description
- `untrusted_content`: External content (may contain injection)
- `expected_tools`: Tools needed for legitimate task completion
- `forbidden_actions`: Actions indicating successful attack (attack cases only)
- `attack_type`: Category of attack (6 types)
- `injection_technique`: Specific technique used (54 techniques)
- `injection_location`: Where the injection is placed (8 locations)
- `difficulty`: easy / medium / hard
- `tags`: Descriptive labels

**Attack type distribution:**
| Type | Count | Percentage |
|------|-------|-----------|
| Data Exfiltration | 188 | 53.4% |
| Goal Hijacking | 49 | 13.9% |
| Privilege Escalation | 41 | 11.6% |
| Multistep | 34 | 9.7% |
| Denial of Service | 20 | 5.7% |
| Social Engineering | 20 | 5.7% |

**Difficulty distribution:**
| Level | Attack | Benign | Total |
|-------|--------|--------|-------|
| Easy | 48 | 78 | 126 |
| Medium | 136 | 74 | 210 |
| Hard | 168 | 61 | 229 |

**Is there a label or target associated with each instance?**
Yes. Attack cases have `forbidden_actions` (what constitutes a successful attack). Benign cases have `expected_tools` (what constitutes successful task completion).

**Is any information missing from individual instances?**
Some benign cases have `null` for `untrusted_content` (tasks without external data). All required fields are present for all instances.

**Are there any errors or noise?**
The dataset was audited with `scripts/audit_benchmark.py`. All 565 cases pass validation. See `data/full_benchmark_backup/` for the pre-audit version.

## Collection Process

**How was the data collected?**
Cases were authored in two phases:
1. **Phase 1 (Core)**: 250 cases manually authored based on real-world IPI attack patterns and common agent tasks.
2. **Phase 2 (Expansion)**: 315 additional cases generated using GPT-4o with human review, covering multilingual attacks, encoding-based evasion, RAG poisoning, and tool output manipulation.

**Who was involved in the collection process?**
The primary author, with LLM assistance for Phase 2 generation.

**What mechanisms were used to ensure quality?**
- Manual review of all generated cases
- Automated validation (`scripts/audit_benchmark.py`)
- Tool reference validation against `config/tools.yaml`
- Deduplication checks

## Uses

**What tasks has the dataset been used for?**
Evaluating IPI defense strategies. The benchmark measures Attack Success Rate (ASR), Benign Success Rate (BSR), and False Positive Rate (FPR) of defense mechanisms.

**Is there anything about the dataset that might impact future uses?**
- The attack payloads are synthetic and may not capture all real-world attack sophistication
- Data exfiltration is overrepresented (53.4%) relative to other attack types
- All content is in English except for the multilingual subset (83 cases)

**Are there tasks for which the dataset should not be used?**
The dataset should not be used to develop attack tools targeting production systems. It is intended for defensive security research only.

## Distribution

**How will the dataset be distributed?**
As part of the open-source ASB repository under MIT License.

**When will the dataset be released?**
Upon paper publication.

## Maintenance

**Who will maintain the dataset?**
The primary author. Community contributions are welcome via pull requests.

**Will the dataset be updated?**
Future versions may add new attack types, injection techniques, and tools. Version changes will be documented in CHANGELOG.md.
