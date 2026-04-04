# Getting Started

## Quick Start

### 1. Install the Package

```bash
cd agent-security-sandbox

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install with all optional dependencies
pip install -e ".[all]"
```

### 2. Run with Mock LLM (No API Key Needed)

```bash
# Single task execution
asb run "Read email_001 and summarize it" --provider mock --defense D0

# Batch benchmark evaluation
asb evaluate --benchmark data/mini_benchmark --provider mock -d D0 -d D1 --output results/test

# Generate report
asb report --results-dir results/test --format markdown
```

### 3. Run with Real LLM (Requires API Key)

```bash
# Copy the example env file and add your API key
cp .env.example .env
# Edit .env: API_KEY=your-key-here
```

```python
from agent_security_sandbox.core.llm_client import create_llm_client
from agent_security_sandbox.tools.registry import ToolRegistry
from agent_security_sandbox.core.agent import ReactAgent

# Create components with real LLM
llm = create_llm_client("openai", model="gpt-4o")
tools = ToolRegistry()
agent = ReactAgent(llm, tools, verbose=True)

# Run agent
trajectory = agent.run(goal="Read email_001 and summarize it")
print(trajectory.final_answer)
```

## Reproduce Paper Experiments

```bash
# Full reproduction with mock LLM (smoke test)
./scripts/reproduce.sh --provider mock

# Full reproduction with real LLM
./scripts/reproduce.sh --provider openai-compatible \
    --base-url https://your-proxy.com/v1 --model gpt-4o
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -q

# Lint and type check
make lint
make type-check
```

See the [README](README.md) for full documentation, or browse the [docs/](docs/) directory for architecture details, defense descriptions, and evaluation methodology.
