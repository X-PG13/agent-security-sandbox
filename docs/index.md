# Agent Security Sandbox

Agent Security Sandbox (ASB) is a benchmark framework for evaluating defenses against indirect prompt injection in tool-using LLM agents.

## What ASB provides

- A 565-case benchmark spanning attack and benign workflows.
- Eleven defense strategies (`D0`-`D10`) with a shared evaluation interface.
- A CLI, Python API, and Streamlit demo for local experimentation.
- Reproduction scripts for the paper tables and figures.

## Installation paths

### Minimal runtime

```bash
git clone https://github.com/X-PG13/agent-security-sandbox.git
cd agent-security-sandbox
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Runtime extras

```bash
# UI demo + analysis + real-provider integrations
pip install -e ".[all]"
```

### Maintainer setup

```bash
# Tests, release checks, and docs tooling
pip install -e ".[maintainer]"
```

## First commands to run

```bash
asb run "Read email_001 and summarize it" --provider mock --defense D5
asb evaluate --suite mini --provider mock -d D0 -d D5 -d D10 -o results/quick_test
asb report --results-dir results/quick_test --format markdown
```

## Documentation map

- `Getting Started` explains install modes and first commands.
- `Architecture` and `Configuration` describe the runtime model.
- `Defenses` and `Evaluation` cover the benchmark mechanics.
- `Extending` shows how to add defenses and cases.
