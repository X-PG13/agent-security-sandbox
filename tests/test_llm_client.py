"""Tests for LLM client module."""
import pytest

from agent_security_sandbox.core.llm_client import (
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
    resp, tokens = client.call([{"role": "user", "content": "hi"}])
    assert resp == "hello"
    assert tokens == 50


def test_mock_response_queue():
    client = MockLLMClient()
    client.set_mock_responses(["first", "second", "third"])

    r1, _ = client.call([])
    r2, _ = client.call([])
    r3, _ = client.call([])
    r4, _ = client.call([])  # should fall back to default

    assert r1 == "first"
    assert r2 == "second"
    assert r3 == "third"
    assert r4 == client.mock_response  # fallback


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
