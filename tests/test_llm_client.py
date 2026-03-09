"""Tests for LLM client module."""
import pytest

from agent_security_sandbox.core.llm_client import (
    LLMResponse,
    MockLLMClient,
    ScenarioMockLLMClient,
    create_llm_client,
)


def test_create_mock_client():
    client = create_llm_client("mock")
    assert isinstance(client, ScenarioMockLLMClient)
    assert client.model == "scenario-mock"


def test_mock_response_single():
    client = MockLLMClient()
    client.set_mock_response("hello")
    resp = client.call([{"role": "user", "content": "hi"}])
    assert isinstance(resp, LLMResponse)
    assert resp.content == "hello"
    assert resp.tokens_used == 50


def test_mock_response_queue():
    client = MockLLMClient()
    client.set_mock_responses(["first", "second", "third"])

    r1 = client.call([])
    r2 = client.call([])
    r3 = client.call([])
    r4 = client.call([])  # should fall back to default

    assert r1.content == "first"
    assert r2.content == "second"
    assert r3.content == "third"
    assert r4.content == client.mock_response  # fallback


def test_client_stats_tracking():
    client = create_llm_client("mock")
    assert client.get_stats()["total_calls"] == 0
    assert client.get_stats()["total_tokens"] == 0

    client.call([{"role": "user", "content": "hi"}])
    assert client.get_stats()["total_calls"] == 1
    assert client.get_stats()["total_tokens"] == 50

    client.call([{"role": "user", "content": "hi again"}])
    assert client.get_stats()["total_calls"] == 2
    assert client.get_stats()["total_tokens"] == 100

    client.reset_stats()
    assert client.get_stats()["total_calls"] == 0


def test_create_unknown_provider():
    with pytest.raises(ValueError, match="Unknown provider"):
        create_llm_client("nonexistent")


def test_openai_compatible_requires_base_url():
    """OpenAICompatibleClient should raise if no base_url available."""
    import os
    old_val = os.environ.pop("OPENAI_BASE_URL", None)
    try:
        with pytest.raises(ValueError, match="base_url is required"):
            create_llm_client("openai-compatible", model="test-model")
    finally:
        if old_val:
            os.environ["OPENAI_BASE_URL"] = old_val


def test_openai_compatible_requires_model():
    with pytest.raises(ValueError, match="model is required"):
        create_llm_client("openai-compatible")


# ---------------------------------------------------------------------------
# Function calling mode tests
# ---------------------------------------------------------------------------

def test_scenario_mock_returns_tool_calls_when_tools_provided():
    """ScenarioMockLLMClient should return structured tool_calls when tools are passed."""
    client = ScenarioMockLLMClient()
    tools = [{"type": "function", "function": {"name": "read_email", "parameters": {}}}]
    resp = client.call(
        [{"role": "user", "content": "Read email_001 and summarize it"}],
        tools=tools,
    )
    assert isinstance(resp, LLMResponse)
    assert resp.tool_calls is not None
    assert len(resp.tool_calls) == 1
    tc = resp.tool_calls[0]
    assert tc["type"] == "function"
    assert tc["function"]["name"] == "read_email"


def test_scenario_mock_returns_text_react_when_no_tools():
    """ScenarioMockLLMClient should return text ReAct when tools are not passed."""
    client = ScenarioMockLLMClient()
    resp = client.call(
        [{"role": "user", "content": "Read email_001 and summarize it"}],
    )
    assert isinstance(resp, LLMResponse)
    assert resp.tool_calls is None
    assert "Action:" in resp.content


def test_scenario_mock_final_answer_no_tool_calls():
    """After tool queue is exhausted, ScenarioMockLLMClient emits Final Answer."""
    client = ScenarioMockLLMClient()
    tools = [{"type": "function", "function": {"name": "read_email", "parameters": {}}}]
    # First call: tool call
    resp1 = client.call(
        [{"role": "user", "content": "Read email_001"}],
        tools=tools,
    )
    assert resp1.tool_calls is not None
    # Second call: no more tools -> final answer as text (no tool_calls)
    resp2 = client.call(
        [{"role": "user", "content": "Observation: done"}],
        tools=tools,
    )
    assert resp2.tool_calls is None
    assert resp2.content  # should have final answer text


def test_llm_response_dataclass():
    """Test LLMResponse basic attributes."""
    resp = LLMResponse(content="hello", tokens_used=42)
    assert resp.content == "hello"
    assert resp.tokens_used == 42
    assert resp.tool_calls is None

    resp2 = LLMResponse(
        content="",
        tokens_used=10,
        tool_calls=[{"id": "c1", "type": "function", "function": {"name": "t", "arguments": "{}"}}],
    )
    assert resp2.tool_calls is not None
    assert len(resp2.tool_calls) == 1
