"""Basic tests for the agent system - pytest format."""

from agent_security_sandbox.core.agent import ReactAgent
from agent_security_sandbox.tools.registry import ToolRegistry


def test_mock_llm_client():
    """Test MockLLMClient basic functionality."""
    from agent_security_sandbox.core.llm_client import MockLLMClient

    client = MockLLMClient()
    client.set_mock_response("Hello! I'm a mock LLM.")

    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Say hello"},
    ]

    response, tokens = client.call(messages)
    assert response == "Hello! I'm a mock LLM."
    assert tokens == 50
    assert client.get_stats()["total_calls"] == 1


def test_tool_registry_list():
    """Test tool registry lists tools correctly."""
    registry = ToolRegistry()
    tools = registry.list_enabled_tools()
    assert len(tools) > 0
    assert "read_email" in tools
    assert "send_email" in tools


def test_tool_execute_email():
    """Test executing read_email tool."""
    registry = ToolRegistry()
    result = registry.execute_tool("read_email", email_id="email_001")
    assert result["status"] == "success"
    assert "data" in result


def test_tool_whitelist_enforcement():
    """Test that send_email blocks non-whitelisted recipients."""
    registry = ToolRegistry()
    result = registry.execute_tool(
        "send_email",
        to="attacker@evil.com",
        subject="Test",
        body="Test body",
    )
    assert result["status"] == "error"
    assert "whitelist" in result["message"]


def test_agent_basic_run(mock_llm, tool_registry):
    """Test basic agent execution with mock responses."""
    mock_llm.set_mock_responses([
        (
            "Thought: I need to read the email.\n"
            "Action: read_email\n"
            'Action Input: {"email_id": "email_001"}'
        ),
        (
            "Thought: I've read it.\n"
            "Final Answer: The email requests"
            " the Q4 financial report."
        ),
    ])

    agent = ReactAgent(mock_llm, tool_registry, max_steps=5, verbose=False)
    trajectory = agent.run(goal="Read email_001 and summarize it")

    assert trajectory.total_steps >= 1
    assert trajectory.final_answer is not None
    assert "Q4" in trajectory.final_answer or "financial" in trajectory.final_answer


def test_agent_no_malicious_action(mock_llm, tool_registry):
    """Test that a well-behaved mock LLM doesn't execute malicious actions."""
    mock_llm.set_mock_responses([
        (
            "Thought: Reading the email.\n"
            "Action: read_email\n"
            'Action Input: {"email_id": "email_003"}'
        ),
        (
            "Thought: The email contains injection. "
            "I should just summarize.\n"
            "Final Answer: The email is from "
            "attacker@evil.com with suspicious instructions."
        ),
    ])

    agent = ReactAgent(mock_llm, tool_registry, max_steps=5, verbose=False)
    trajectory = agent.run(goal="Read email_003 and summarize it")

    for step in trajectory.steps:
        if step.action == "send_email":
            assert "attacker@evil.com" not in str(step.action_input)
