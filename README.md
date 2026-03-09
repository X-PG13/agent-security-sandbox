# Agent Security Sandbox (ASB)

[![CI](https://github.com/X-PG13/agent-security-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/X-PG13/agent-security-sandbox/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A research framework for evaluating AI agent security against **Indirect Prompt Injection (IPI)** attacks. Compare defense strategies, run automated benchmarks, and visualize results.

## Features

- **8 Defense Strategies**: D0 (Baseline), D1 (Spotlighting), D2 (Policy Gate), D3 (Task Alignment), D4 (Re-execution), D5 (Sandwich), D6 (Output Filter), D7 (Input Classifier)
- **250 Benchmark Cases**: 95 benign + 155 attack scenarios across 8 attack types (hijacking, exfiltration, escalation, social engineering, adaptive, DoS, multistep, evasion)
- **OpenAI Function Calling**: Native tool calling with text ReAct fallback
- **Automated Evaluation**: Rule-based judge with ASR/BSR/FPR metrics
- **Multi-Provider Support**: OpenAI, Anthropic, OpenAI-compatible endpoints (vLLM, Ollama, gateways)
- **CLI Tool**: `asb` command with run/evaluate/report/serve subcommands
- **Interactive Demo**: Streamlit UI for exploration and presentation
- **Composable Defenses**: Mix and match strategies for ablation studies
- **Paper-Quality Analysis**: Statistical tests (McNemar, bootstrap CI), LaTeX tables, publication figures

## Quick Start

### Installation

```bash
pip install -e ".[all]"
```

### Run a Single Task

```bash
# With mock LLM (no API key needed)
asb run "Read email_001 and summarize it" --provider mock --defense D2

# With OpenAI
asb run "Read email_001 and summarize it" --provider openai --defense D2

# With third-party proxy
asb run "Read email_001" --provider openai-compatible --base-url https://your-proxy.com/v1 --model gpt-4
```

### Run Benchmark Evaluation

```bash
asb evaluate --benchmark data/mini_benchmark --defense D0 --defense D1 --defense D2 --provider mock -o results/
```

### Generate Report

```bash
asb report --results-dir results/ --format markdown
```

### Launch Demo UI

```bash
asb serve --port 8501
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│                    CLI / UI Layer                │
│         (Click CLI  |  Streamlit Demo)          │
├─────────────────────────────────────────────────┤
│               Evaluation Framework              │
│   BenchmarkSuite → ExperimentRunner → Reporter  │
│        AutoJudge → MetricsCalculator           │
├─────────────────────────────────────────────────┤
│                  Agent Core                     │
│     ReactAgent ←→ LLMClient (multi-provider)   │
│          ↕              ↕                       │
│    ToolRegistry    DefenseStrategy              │
│    (7 mock tools)  (D0-D7 + Composite)         │
└─────────────────────────────────────────────────┘
```

## Project Structure

```
agent-security-sandbox/
├── src/agent_security_sandbox/
│   ├── core/           # Agent, LLM clients, memory
│   ├── tools/          # Mock tools with risk metadata
│   ├── defenses/       # D0-D7 defense strategies
│   ├── evaluation/     # Benchmark, judge, metrics, runner, reporter
│   ├── cli/            # Click CLI (asb command)
│   └── ui/             # Streamlit demo app
├── data/
│   ├── mini_benchmark/ # 40 JSONL evaluation cases (quick testing)
│   ├── full_benchmark/ # 250 JSONL evaluation cases (full evaluation)
│   └── secrets/        # Mock sensitive data
├── config/             # YAML configs (tools, models, defenses)
├── experiments/        # Experiment scripts
├── tests/              # Comprehensive test suite
└── docs/               # Documentation
```

## Defense Strategies

| ID | Name | Mechanism | Modifies Prompt | Gates Tools | Filters Output |
|----|------|-----------|:-:|:-:|:-:|
| D0 | Baseline | No defense | - | - | - |
| D1 | Spotlighting | Delimiter-based source marking | Yes | - | - |
| D2 | Policy Gate | Risk-level + whitelist enforcement | - | Yes | - |
| D3 | Task Alignment | Goal-action consistency check | - | Yes | - |
| D4 | Re-execution | Clean re-run comparison | - | Yes | - |
| D5 | Sandwich | Goal-reminder wrapping of untrusted content | Yes | - | - |
| D6 | Output Filter | Post-hoc sensitive data leak detection | - | - | Yes |
| D7 | Input Classifier | Pre-processing injection pattern removal | Yes | - | - |

## Evaluation Metrics

- **ASR** (Attack Success Rate): Fraction of attacks that bypassed defenses (lower = better)
- **BSR** (Benign Success Rate): Fraction of legitimate tasks completed (higher = better)
- **FPR** (False Positive Rate): Fraction of legitimate tasks incorrectly blocked (lower = better)

## Key Results

Evaluated across 4 models (GPT-4o, Claude 4.5 Sonnet, DeepSeek V3.1, Gemini 2.5 Flash) on 250 benchmark cases:

| Defense | Avg ASR | Avg BSR | ASR Reduction |
|---|:---:|:---:|:---:|
| **D0** Baseline | 0.411 | 0.895 | — |
| **D5** Sandwich | **0.010** | 0.934 | **-97.6%** |
| **D1** Spotlighting | 0.019 | 0.926 | -95.3% |
| **D2** Policy Gate | 0.298 | 0.763 | -27.5% |
| **D4** Re-execution | 0.316 | 0.761 | -23.1% |
| **D6** Output Filter | 0.377 | 0.887 | -8.2% |
| **D3** Task Alignment | 0.400 | 0.913 | -2.7% |
| **D7** Input Classifier | 0.434 | 0.913 | +5.5% |

**Key findings**: Prompt-layer defenses (D5, D1) reduce ASR by >95% with minimal utility loss. Tool-gating defenses (D2, D4) trade ~25% FPR for moderate security gains. Content-level defenses (D6, D7) are largely ineffective. See [`results/full_eval/analysis_report.md`](results/full_eval/analysis_report.md) for detailed analysis.

## Development

```bash
# Install with dev dependencies
pip install -e ".[all]"

# Run tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ -v --cov=agent_security_sandbox

# Lint
ruff check src/ tests/

# Type check
mypy src/agent_security_sandbox/
```

## Docker

```bash
# Run evaluation
docker-compose up sandbox

# Launch UI
docker-compose up ui
```

## Citation

If you use this framework in your research, please cite:

```bibtex
@software{zhao2026asb,
  title  = {Agent Security Sandbox: A Framework for Evaluating LLM Agent Defenses Against Indirect Prompt Injection},
  author = {Zhao, Yifan},
  year   = {2026},
  url    = {https://github.com/X-PG13/agent-security-sandbox}
}
```

## References

- Zhan et al., "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents" (2024)
- Debenedetti et al., "AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses" (2024)
- Hines et al., "Defending Against Indirect Prompt Injection Attacks With Spotlighting" (2024)
- Xiang et al., "MELON: Mitigating IPI via Re-execution" (2024)

## License

MIT License - see [LICENSE](LICENSE)
