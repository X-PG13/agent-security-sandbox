# Agent Security Sandbox (ASB)

[![CI](https://github.com/X-PG13/agent-security-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/X-PG13/agent-security-sandbox/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A research framework for evaluating AI agent security against **Indirect Prompt Injection (IPI)** attacks. Compare defense strategies, run automated benchmarks, and visualize results.

## Features

- **6 Defense Strategies**: D0 (Baseline), D1 (Spotlighting), D2 (Policy Gate), D3 (Task Alignment), D4 (Re-execution), D5 (Sandwich)
- **235 Benchmark Cases**: 95 benign + 140 attack scenarios including adaptive attacks and edge cases
- **Automated Evaluation**: Rule-based judge with ASR/BSR/FPR metrics
- **Multi-Provider Support**: OpenAI, Anthropic, OpenAI-compatible endpoints (vLLM, Ollama, etc.)
- **CLI Tool**: `asb` command with run/evaluate/report/serve subcommands
- **Interactive Demo**: Streamlit UI for exploration and presentation
- **Composable Defenses**: Mix and match strategies for ablation studies

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
│    (7 mock tools)  (D0-D5 + Composite)         │
└─────────────────────────────────────────────────┘
```

## Project Structure

```
agent-security-sandbox/
├── src/agent_security_sandbox/
│   ├── core/           # Agent, LLM clients, memory
│   ├── tools/          # Mock tools with risk metadata
│   ├── defenses/       # D0-D5 defense strategies
│   ├── evaluation/     # Benchmark, judge, metrics, runner, reporter
│   ├── cli/            # Click CLI (asb command)
│   └── ui/             # Streamlit demo app
├── data/
│   ├── mini_benchmark/ # 40 JSONL evaluation cases (quick testing)
│   ├── full_benchmark/ # 235 JSONL evaluation cases (full evaluation)
│   └── secrets/        # Mock sensitive data
├── config/             # YAML configs (tools, models, defenses)
├── experiments/        # Experiment scripts
├── tests/              # Comprehensive test suite
└── docs/               # Documentation
```

## Defense Strategies

| ID | Name | Mechanism | Modifies Prompt | Gates Tools |
|----|------|-----------|:-:|:-:|
| D0 | Baseline | No defense | - | - |
| D1 | Spotlighting | Delimiter-based source marking | Yes | - |
| D2 | Policy Gate | Risk-level + whitelist enforcement | - | Yes |
| D3 | Task Alignment | Goal-action consistency check | - | Yes |
| D4 | Re-execution | Clean re-run comparison | - | Yes |
| D5 | Sandwich | Goal-reminder wrapping of untrusted content | Yes | - |

## Evaluation Metrics

- **ASR** (Attack Success Rate): Fraction of attacks that bypassed defenses
- **BSR** (Benign Success Rate): Fraction of legitimate tasks completed
- **FPR** (False Positive Rate): Fraction of legitimate tasks incorrectly blocked

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

## References

- Zhan et al., "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents" (2024)
- Debenedetti et al., "AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses" (2024)
- Hines et al., "Defending Against Indirect Prompt Injection Attacks With Spotlighting" (2024)
- Xiang et al., "MELON: Mitigating IPI via Re-execution" (2024)

## License

MIT License - see [LICENSE](LICENSE)
