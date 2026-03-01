# Contributing to Agent Security Sandbox

Thank you for your interest in contributing! This document explains how to get started.

## Development Environment

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) or pip

### Setup

```bash
# Clone the repository
git clone https://github.com/asb-team/agent-security-sandbox.git
cd agent-security-sandbox

# Create a virtual environment and install dev dependencies
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest tests/ -v
pytest tests/ --cov=agent_security_sandbox --cov-report=term-missing
```

### Code Quality

We enforce zero errors from both linters:

```bash
ruff check src/ tests/
mypy src/
```

Fix auto-fixable lint issues with:

```bash
ruff check --fix src/ tests/
```

## Code Style

- Line length: 100 characters.
- Linting: [ruff](https://docs.astral.sh/ruff/) with rules E, F, I, N, W.
- Type checking: [mypy](https://mypy-lang.org/) with `check_untyped_defs = true`.
- Docstrings: Use triple-quoted docstrings for public modules, classes, and functions.

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. **Write tests** for any new functionality. We target 80%+ code coverage.
3. **Run the full check suite** before submitting:
   ```bash
   pytest tests/ -v
   ruff check src/ tests/
   mypy src/
   ```
4. **Open a pull request** against `main` with a clear description of the change.
5. Ensure CI checks pass. A maintainer will review your PR.

## Reporting Bugs

Open an issue using the **Bug Report** template. Include:

- Steps to reproduce
- Expected vs. actual behaviour
- Python version and OS

## Suggesting Features

Open an issue using the **Feature Request** template describing the use case and proposed solution.
