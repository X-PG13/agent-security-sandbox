"""Tests for D8 (Semantic Firewall) and D9 (Dual-LLM) defenses."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agent_security_sandbox.core.llm_client import MockLLMClient
from agent_security_sandbox.defenses.d8_semantic_firewall import (
    SemanticFirewallDefense,
    _cosine_similarity,
    _keyword_overlap,
)
from agent_security_sandbox.defenses.d9_dual_llm import DualLLMDefense
from agent_security_sandbox.defenses.registry import create_defense

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _make_mock_tool(name: str) -> MagicMock:
    tool = MagicMock()
    tool.metadata.name = name
    return tool


# -----------------------------------------------------------------------
# D8 Semantic Firewall
# -----------------------------------------------------------------------

class TestSemanticFirewall:
    def test_cosine_similarity_identical(self):
        vec = [1.0, 0.0, 0.5]
        assert _cosine_similarity(vec, vec) == pytest.approx(1.0)

    def test_cosine_similarity_orthogonal(self):
        a = [1.0, 0.0]
        b = [0.0, 1.0]
        assert _cosine_similarity(a, b) == pytest.approx(0.0)

    def test_keyword_overlap_exact(self):
        assert _keyword_overlap("hello world", "hello world") == pytest.approx(1.0)

    def test_keyword_overlap_partial(self):
        score = _keyword_overlap("read email and summarize", "send email to attacker")
        assert 0.0 < score < 1.0

    def test_keyword_overlap_disjoint(self):
        score = _keyword_overlap("abc def", "xyz uvw")
        assert score == pytest.approx(0.0)

    def test_prepare_context(self):
        d8 = SemanticFirewallDefense()
        ctx = d8.prepare_context("Read email_001", "Some content")
        assert "Read email_001" in ctx
        assert "Some content" in ctx

    def test_allow_related_tool_call(self):
        """A tool call related to the goal should be allowed."""
        llm = MockLLMClient()
        d8 = SemanticFirewallDefense(
            config={"similarity_threshold": 0.1, "use_embedding": True},
            llm_client=llm,
        )
        d8.prepare_context("Read email_001 and summarize", "")
        tool = _make_mock_tool("read_email")
        allowed, reason = d8.should_allow_tool_call(
            tool, {"email_id": "email_001"}, {"goal": "Read email_001", "step": 1},
        )
        # With mock embeddings the result depends on hash similarity,
        # but the test verifies the pipeline runs without error.
        assert isinstance(allowed, bool)
        assert isinstance(reason, str)

    def test_keyword_fallback_when_no_llm(self):
        """Without an LLM client, falls back to keyword overlap."""
        d8 = SemanticFirewallDefense(
            config={"similarity_threshold": 0.05, "use_embedding": True},
            llm_client=None,
        )
        d8.prepare_context("Read email and summarize contents", "")
        tool = _make_mock_tool("read_email")
        allowed, reason = d8.should_allow_tool_call(
            tool, {"email_id": "email_001"}, {},
        )
        # "read" and "email" overlap between goal and action description
        assert allowed is True

    def test_block_unrelated_action(self):
        """An action unrelated to the goal should be blocked with low threshold."""
        d8 = SemanticFirewallDefense(
            config={"similarity_threshold": 0.99},
            llm_client=None,
        )
        d8.prepare_context("Read email_001 and summarize", "")
        tool = _make_mock_tool("post_api")
        allowed, reason = d8.should_allow_tool_call(
            tool, {"endpoint": "/api/hack", "data": "secrets"}, {},
        )
        assert allowed is False
        assert "BLOCKED" in reason

    def test_unmonitored_tool_always_allowed(self):
        d8 = SemanticFirewallDefense(
            config={"monitored_tools": ["send_email"]},
        )
        d8.prepare_context("Read email_001", "")
        tool = _make_mock_tool("read_email")
        allowed, reason = d8.should_allow_tool_call(tool, {}, {})
        assert allowed is True

    def test_create_via_registry(self):
        llm = MockLLMClient()
        d8 = create_defense("D8", llm_client=llm)
        assert isinstance(d8, SemanticFirewallDefense)


# -----------------------------------------------------------------------
# D9 Dual-LLM
# -----------------------------------------------------------------------

class TestDualLLM:
    def test_prepare_context(self):
        d9 = DualLLMDefense()
        ctx = d9.prepare_context("Summarize email", "Email body here")
        assert "Summarize email" in ctx
        assert "Email body here" in ctx

    def test_fast_screen_allows_safe_mock(self):
        """Mock LLM returns generic text; parse_safety_response handles it."""
        llm = MockLLMClient()
        d9 = DualLLMDefense(config={"fast_threshold": 0.0, "deep_threshold": 0.0}, llm_client=llm)
        d9.prepare_context("Read email_001", "")
        tool = _make_mock_tool("read_email")
        allowed, reason = d9.should_allow_tool_call(
            tool, {"email_id": "email_001"}, {"goal": "Read email_001", "step": 1},
        )
        assert isinstance(allowed, bool)
        assert isinstance(reason, str)

    def test_parse_safety_response_json(self):
        import json
        text = json.dumps({"safe": True, "confidence": 0.9, "reason": "Looks fine"})
        result = DualLLMDefense._parse_safety_response(text)
        assert result["safe"] is True
        assert result["confidence"] == pytest.approx(0.9)

    def test_parse_safety_response_fallback(self):
        result = DualLLMDefense._parse_safety_response("This action is safe to proceed")
        assert result["safe"] is True
        assert result["confidence"] > 0.5

    def test_parse_safety_response_unsafe(self):
        result = DualLLMDefense._parse_safety_response("This is unsafe and malicious")
        assert result["safe"] is False

    def test_create_via_registry(self):
        llm = MockLLMClient()
        d9 = create_defense("D9", llm_client=llm)
        assert isinstance(d9, DualLLMDefense)

    def test_blocking_with_high_threshold(self):
        """With very high thresholds, mock responses should fail to pass."""
        llm = MockLLMClient()
        d9 = DualLLMDefense(
            config={"fast_threshold": 0.99, "deep_threshold": 0.99},
            llm_client=llm,
        )
        d9.prepare_context("Read email_001 and summarize", "")
        tool = _make_mock_tool("send_email")
        allowed, reason = d9.should_allow_tool_call(
            tool, {"to": "attacker@evil.com"}, {"step": 1},
        )
        # Mock returns generic text, parsed confidence will be <= 0.8
        assert allowed is False
        assert "BLOCKED" in reason
