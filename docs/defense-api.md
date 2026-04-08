# Defense API

This page documents the extension surface for adding new defenses to ASB.

## Base Interface

Every defense implements `DefenseStrategy` from `src/agent_security_sandbox/defenses/base.py`.

```python
class DefenseStrategy(ABC):
    @abstractmethod
    def prepare_context(self, goal: str, untrusted_content: str) -> str:
        ...

    @abstractmethod
    def should_allow_tool_call(
        self,
        tool: Tool,
        params: dict[str, object],
        context: dict[str, object],
    ) -> tuple[bool, str]:
        ...
```

## Lifecycle

1. `prepare_context()` runs once before the agent starts.
2. The agent proposes tool calls while reasoning.
3. `should_allow_tool_call()` runs before each tool execution.
4. The runner records allow or block decisions in the trajectory and final metrics.

## Design Guidance

- Use `prepare_context()` for prompt-layer defenses such as delimiters, warnings, and goal reminders.
- Use `should_allow_tool_call()` for policy and integrity checks tied to specific tool invocations.
- Return short, reviewer-readable reasons. These reasons surface in results and error analysis.
- Keep configuration serializable so experiment scripts can store and compare runs cleanly.

## Minimal Example

```python
from agent_security_sandbox.defenses.base import DefenseStrategy


class MyDefense(DefenseStrategy):
    def prepare_context(self, goal: str, untrusted_content: str | None = None) -> str:
        if not untrusted_content:
            return goal
        return f"TASK: {goal}\n\nUNTRUSTED CONTENT:\n{untrusted_content}"

    def should_allow_tool_call(self, tool, params, context):
        goal = str(context.get("goal", ""))
        if tool.name == "send_email" and "attacker" in str(params):
            return False, f"Blocked by MyDefense: send_email mismatched with goal {goal!r}"
        return True, "Allowed"
```

## Registration

After adding the new class:

1. Import it in `src/agent_security_sandbox/defenses/registry.py`
2. Add a new ID such as `D11`
3. Add configuration to `config/defenses.yaml` if the defense uses runtime parameters
4. Add tests that cover both benign and attack paths

## Testing Checklist

```bash
pytest tests/ -q
pytest tests/test_defense_registry.py -q
ruff check src/ tests/
mypy src/agent_security_sandbox/
```

If the defense depends on embeddings or a second model, include at least one mock-based test that exercises the branch without network access.
