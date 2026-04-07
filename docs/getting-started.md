# Getting Started

## 1. Clone and install

```bash
git clone https://github.com/X-PG13/agent-security-sandbox.git
cd agent-security-sandbox
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Optional extras:

```bash
# UI demo + analysis + real providers
pip install -e ".[all]"

# Tests + packaging checks + docs tooling
pip install -e ".[maintainer]"
```

## 2. Run a mock-agent smoke test

```bash
asb run "Read email_001 and summarize it" --provider mock --defense D0
asb evaluate --suite mini --provider mock -d D0 -d D5 -o results/test
asb report --results-dir results/test --format markdown
```

## 3. Configure real providers

```bash
cp .env.example .env
```

Then fill in the provider-specific keys you need. The default example uses `gpt-4o` for OpenAI and Claude 4.5 Sonnet for Anthropic.

## 4. Use the Python API

```python
from agent_security_sandbox.core.llm_client import create_llm_client
from agent_security_sandbox.defenses.registry import create_defense
from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite
from agent_security_sandbox.evaluation.runner import ExperimentRunner
from agent_security_sandbox.tools.registry import ToolRegistry

suite = BenchmarkSuite.load_from_directory("data/full_benchmark")
llm = create_llm_client("mock", model="mock")
defense = create_defense("D10", llm_client=llm)

runner = ExperimentRunner(
    llm_client=llm,
    tool_registry_factory=ToolRegistry,
    defense_strategy=defense,
    max_steps=10,
)
result = runner.run_suite(suite)
print(result.metrics.asr, result.metrics.bsr)
```

## 5. Contributor workflow

```bash
pytest tests/ -q
ruff check src/ tests/
mypy src/agent_security_sandbox/
mkdocs build --strict
python -m build
python -m twine check dist/*
```
