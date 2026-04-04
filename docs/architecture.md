# Architecture

## Three-Layer Design

ASB is organized into three layers:

### Layer 1: Agent Core

- **ReactAgent**: Implements the ReAct (Reasoning + Acting) pattern
- **LLMClient**: Abstraction supporting OpenAI, Anthropic, OpenAI-compatible, and Mock providers
- **ToolRegistry**: Centralized tool management with risk metadata
- **ConversationMemory**: Message history management with windowing strategies

### Layer 2: Security & Evaluation

- **DefenseStrategy**: Abstract interface for all defenses (D0-D7)
  - D0: Baseline (no defense), D1: Spotlighting, D2: Policy Gate, D3: Task Alignment
  - D4: Re-execution, D5: Sandwich, D6: Output Filter, D7: Input Classifier
  - `prepare_context()`: Modifies the prompt before sending to LLM
  - `should_allow_tool_call()`: Gates tool execution at runtime
- **CompositeDefense**: Pipeline combining multiple strategies
- **AutoJudge**: Rule-based verdict system (attack_succeeded/blocked, benign_completed/blocked)
- **MetricsCalculator**: Computes ASR, BSR, FPR from judge results
- **ExperimentRunner**: Orchestrates benchmark execution with fresh state per case

### Layer 3: Interface

- **CLI (`asb`)**: Click-based command-line tool with run/evaluate/report/serve commands
- **Streamlit UI**: Interactive demo with agent execution, audit trail, and benchmark visualization

## Data Flow

```
User Goal + Untrusted Content
        ↓
   DefenseStrategy.prepare_context()
        ↓
   ReactAgent.run() loop:
     1. LLM generates thought + action
     2. DefenseStrategy.should_allow_tool_call()
     3. If allowed: Tool executes → observation
        If blocked: "BLOCKED" observation
     4. Repeat until Final Answer or max_steps
        ↓
   AgentTrajectory (full execution trace)
        ↓
   AutoJudge.judge() → JudgeResult
        ↓
   MetricsCalculator → EvaluationMetrics
```

## Tool Risk Classification

| Risk Level | Examples | Policy |
|------------|----------|--------|
| LOW | search_web, create_document | Always allowed |
| MEDIUM | read_email, read_file | Allowed by default |
| HIGH | send_email, write_file | Whitelist enforced |
| CRITICAL | execute_code | Blocked by default |
