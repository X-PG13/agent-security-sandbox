# Getting Started

## Project Setup Completed! ✅

The Agent Security Sandbox project structure has been successfully created. Here's what we've built:

### What's Been Implemented

#### 1. Core Components
- **LLM Client** (`src/core/llm_client.py`)
  - Support for OpenAI, Anthropic, and Mock clients
  - Token tracking and cost estimation
  - Flexible factory pattern for easy switching

- **ReAct Agent** (`src/core/agent.py`)
  - Full ReAct (Reasoning + Acting) loop implementation
  - Trajectory recording for evaluation
  - Support for defense strategies
  - Configurable max steps and verbosity

#### 2. Tool System
- **Tool Base Classes** (`src/tools/base.py`)
  - Risk-level classification (low/medium/high/critical)
  - Parameter validation with whitelist support
  - Side-effect tracking
  - OpenAI function schema generation

- **Mock Tools Implemented**:
  - Email tools (`src/tools/email.py`): read_email, send_email, list_emails
  - Search tool (`src/tools/search.py`): search_web
  - File tools (`src/tools/file.py`): read_file, write_file, create_document

- **Tool Registry** (`src/tools/registry.py`)
  - Centralized tool management
  - Risk-based filtering
  - Config-based customization

#### 3. Configuration
- `config/tools.yaml` - Tool definitions with risk levels and whitelists
- `config/models.yaml` - LLM model configurations with cost data
- `config/defenses.yaml` - Defense strategy configurations
- `.env.example` - Environment variable template

#### 4. Testing
- `tests/test_basic.py` - Comprehensive test suite covering:
  - LLM client functionality
  - Tool registry operations
  - Basic agent execution
  - Injection attack scenarios

### Next Steps to Get Running

#### Option 1: Using Mock LLM (No API Key Needed)

The system is already configured to work with a Mock LLM client for testing:

```bash
# Navigate to project
cd "/Users/zhaoyifan/Desktop/prompt injection/agent-security-sandbox"

# Install minimal dependencies
python3 -m pip install --user pydantic pyyaml

# Run tests
python3 tests/test_basic.py
```

#### Option 2: Using Real LLM (Requires API Key)

1. Install full dependencies:
```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install all dependencies
pip install -r requirements.txt
```

2. Set up API keys:
```bash
# Copy the example env file
cp .env.example .env

# Edit .env and add your API key
# OPENAI_API_KEY=your-key-here
```

3. Run with real LLM:
```python
from src.core.llm_client import create_llm_client
from src.tools.registry import ToolRegistry
from src.core.agent import ReactAgent

# Create components with real LLM
llm = create_llm_client("openai", model="gpt-3.5-turbo")
tools = ToolRegistry()
agent = ReactAgent(llm, tools, verbose=True)

# Run agent
trajectory = agent.run(goal="Read email_001 and summarize it")
print(trajectory.final_answer)
```

### Project Structure

```
agent-security-sandbox/
├── src/
│   ├── core/
│   │   ├── llm_client.py      # ✅ LLM wrappers (OpenAI, Anthropic, Mock)
│   │   └── agent.py           # ✅ ReAct Agent implementation
│   ├── tools/
│   │   ├── base.py            # ✅ Tool base classes and metadata
│   │   ├── email.py           # ✅ Mock email tools
│   │   ├── search.py          # ✅ Mock search tool
│   │   ├── file.py            # ✅ Mock file tools
│   │   └── registry.py        # ✅ Tool management
│   ├── defenses/              # 🔜 Defense strategies (D0-D4)
│   ├── evaluation/            # 🔜 Benchmark, judge, metrics
│   └── ui/                    # 🔜 Streamlit demo
├── config/
│   ├── tools.yaml            # ✅ Tool configurations
│   ├── models.yaml           # ✅ Model configurations
│   └── defenses.yaml         # ✅ Defense configurations
├── data/
│   └── mini_benchmark/       # 🔜 Evaluation test cases
├── tests/
│   └── test_basic.py         # ✅ Basic functionality tests
├── requirements.txt          # ✅ Python dependencies
├── .env.example             # ✅ Environment template
├── .gitignore               # ✅ Git ignore rules
└── README.md                # ✅ Project documentation
```

Legend:
- ✅ = Implemented
- 🔜 = Next to implement

### Current Status

**Phase 1 (Complete)**:
- ✅ Project structure
- ✅ Core agent framework
- ✅ Mock tools with risk metadata
- ✅ Basic testing

**Phase 2 (Next)**:
- Implement defense strategies (D0-D4)
- Create mini-benchmark test cases
- Build automatic judge and metrics calculator
- Run baseline experiments

### Testing the System

You can test individual components:

```python
# Test LLM Client (Mock)
python3 -c "
import sys
sys.path.insert(0, 'src')
from core.llm_client import create_llm_client
client = create_llm_client('mock')
response, tokens = client.call([{'role': 'user', 'content': 'Hello'}])
print(f'Response: {response}')
"

# Test Tool Registry
python3 -c "
import sys
sys.path.insert(0, 'src')
from tools.registry import ToolRegistry
registry = ToolRegistry()
print(f'Available tools: {registry.list_tools()}')
result = registry.execute_tool('read_email', email_id='email_001')
print(f'Result: {result}')
"
```

### Key Features Already Working

1. **Multi-provider LLM Support**: Easily switch between OpenAI, Anthropic, or Mock
2. **Risk-Aware Tools**: All tools have risk levels and parameter validation
3. **Whitelist Enforcement**: High-risk tools (send_email) check whitelists automatically
4. **Trajectory Recording**: Every agent execution is fully logged
5. **Mock Data**: Pre-populated emails, files, and secrets for testing

### What Makes This Special

This sandbox is designed for **reproducible security research**:
- All tools are mocked - no real APIs needed for testing
- Risk levels guide defensive strategies
- Trajectory recording enables detailed analysis
- Whitelist enforcement demonstrates policy-based defense

### Troubleshooting

**Import Errors**:
If you see "ModuleNotFoundError", install the missing package:
```bash
python3 -m pip install --user pydantic pyyaml
```

**No API Key**:
Use the Mock LLM client for testing without API keys. It's already set up in `test_basic.py`.

**Permission Errors**:
The sandboxes tools are all mocked and won't actually send emails or write files outside the mock filesystem.

### Next Development Steps

See `docs/development_roadmap.md` for the complete 8-12 week plan.

Immediate next tasks:
1. Install dependencies: `python3 -m pip install --user pydantic pyyaml`
2. Run tests: `python3 tests/test_basic.py`
3. Start implementing defense strategies in `src/defenses/`
4. Create benchmark test cases in `data/mini_benchmark/`

---

**You're ready to start building! The foundation is solid. 🚀**
