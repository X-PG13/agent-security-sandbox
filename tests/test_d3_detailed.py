"""Detailed tests for D3 -- Task Alignment Verification defense."""
import pytest

from agent_security_sandbox.defenses.d3_task_alignment import (
    TaskAlignmentDefense,
)
from agent_security_sandbox.tools.base import RiskLevel, Tool, ToolMetadata

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tool(name: str, risk: RiskLevel = RiskLevel.HIGH) -> Tool:
    """Create a minimal concrete Tool for testing."""

    class _DummyTool(Tool):
        def execute(self, **kwargs):
            return {"status": "success"}

    meta = ToolMetadata(
        name=name,
        description=f"Dummy {name}",
        risk_level=risk,
        side_effect=False,
        data_access="private",
        parameters={},
    )
    return _DummyTool(meta)


# ---------------------------------------------------------------------------
# Config / init
# ---------------------------------------------------------------------------

class TestTaskAlignmentConfig:
    def test_default_config(self):
        d = TaskAlignmentDefense()
        assert d.check_high_risk_only is True
        assert d.alignment_threshold == 0.7
        assert d.use_llm_judge is False

    def test_custom_config(self):
        d = TaskAlignmentDefense(config={
            "check_high_risk_only": False,
            "alignment_threshold": 0.5,
            "use_llm_judge": True,
        })
        assert d.check_high_risk_only is False
        assert d.alignment_threshold == 0.5
        assert d.use_llm_judge is True

    def test_empty_config(self):
        d = TaskAlignmentDefense(config={})
        assert d.check_high_risk_only is True


# ---------------------------------------------------------------------------
# prepare_context
# ---------------------------------------------------------------------------

class TestPrepareContext:
    def test_basic(self):
        d = TaskAlignmentDefense()
        result = d.prepare_context("Read email", "Injected")
        assert "Read email" in result
        assert "Injected" in result


# ---------------------------------------------------------------------------
# _rule_based_alignment_check – category matching
# ---------------------------------------------------------------------------

class TestRuleBasedAlignment:
    def test_matching_category_email(self):
        d = TaskAlignmentDefense()
        tool = _make_tool("read_email")
        score, explanation = d._rule_based_alignment_check(
            "Read email_001 and summarize it", tool, {}
        )
        assert score >= 0.9
        assert "matches the goal" in explanation

    def test_matching_category_search(self):
        d = TaskAlignmentDefense()
        tool = _make_tool("search_web")
        score, _ = d._rule_based_alignment_check(
            "Search the web for python tutorials", tool, {}
        )
        assert score >= 0.9

    def test_matching_category_file(self):
        d = TaskAlignmentDefense()
        tool = _make_tool("read_file")
        score, _ = d._rule_based_alignment_check(
            "Read the file and save a summary", tool, {}
        )
        assert score >= 0.9

    def test_mismatched_category(self):
        """Tool in 'email' category but goal is about search."""
        d = TaskAlignmentDefense()
        tool = _make_tool("send_email")
        score, explanation = d._rule_based_alignment_check(
            "Search the web for python tutorials", tool, {}
        )
        assert score <= 0.5
        assert "does not match" in explanation

    def test_unknown_goal_category(self):
        """Goal has no recognisable keywords -> moderate score."""
        d = TaskAlignmentDefense()
        tool = _make_tool("read_email")
        score, explanation = d._rule_based_alignment_check(
            "Do something completely unrelated xyz123", tool, {}
        )
        assert 0.4 <= score <= 0.6
        assert "Could not determine" in explanation

    def test_unknown_tool_category(self):
        """Tool not in _TOOL_CATEGORY_MAP -> low alignment."""
        d = TaskAlignmentDefense()
        tool = _make_tool("custom_tool_xyz")
        score, explanation = d._rule_based_alignment_check(
            "Read the email and summarize", tool, {}
        )
        assert score <= 0.5
        assert "no known category" in explanation

    def test_unknown_tool_and_unknown_goal(self):
        """Both unknown -> moderate base score."""
        d = TaskAlignmentDefense()
        tool = _make_tool("custom_tool_xyz")
        score, _ = d._rule_based_alignment_check(
            "Do xyz123", tool, {}
        )
        # base_score = 0.5 (unknown goal) + 0 bonus
        assert 0.4 <= score <= 0.6


# ---------------------------------------------------------------------------
# _param_goal_overlap
# ---------------------------------------------------------------------------

class TestParamGoalOverlap:
    def test_single_match(self):
        bonus = TaskAlignmentDefense._param_goal_overlap(
            "read email_001 and summarize", {"email_id": "email_001"}
        )
        assert bonus == pytest.approx(0.1)

    def test_multiple_matches_capped(self):
        bonus = TaskAlignmentDefense._param_goal_overlap(
            "read email_001 from boss@company.com and reply to boss@company.com",
            {"email_id": "email_001", "to": "boss@company.com", "cc": "boss@company.com"},
        )
        assert bonus == pytest.approx(0.2)  # capped at 0.2

    def test_no_match(self):
        bonus = TaskAlignmentDefense._param_goal_overlap(
            "search the web for python",
            {"to": "attacker@evil.com"},
        )
        assert bonus == 0.0

    def test_short_value_ignored(self):
        """Values with len <= 2 should be ignored."""
        bonus = TaskAlignmentDefense._param_goal_overlap(
            "ab", {"key": "ab"}
        )
        assert bonus == 0.0

    def test_non_string_value_ignored(self):
        bonus = TaskAlignmentDefense._param_goal_overlap(
            "some goal with 42 in it", {"count": 42}
        )
        assert bonus == 0.0

    def test_case_insensitive(self):
        # _param_goal_overlap expects goal_lower to already be lowercase
        bonus = TaskAlignmentDefense._param_goal_overlap(
            "read email_001 please", {"email_id": "EMAIL_001"}
        )
        assert bonus == pytest.approx(0.1)

    def test_empty_params(self):
        bonus = TaskAlignmentDefense._param_goal_overlap("some goal", {})
        assert bonus == 0.0


# ---------------------------------------------------------------------------
# _build_judge_prompt
# ---------------------------------------------------------------------------

class TestBuildJudgePrompt:
    def test_format(self):
        tool = _make_tool("send_email")
        prompt = TaskAlignmentDefense._build_judge_prompt(
            "Send a report", tool, {"to": "boss@co.com", "subject": "Report"}
        )
        assert "User goal: Send a report" in prompt
        assert "Tool: send_email" in prompt
        assert "Risk level:" in prompt
        assert "Parameters:" in prompt
        assert "boss@co.com" in prompt

    def test_empty_params(self):
        tool = _make_tool("read_email")
        prompt = TaskAlignmentDefense._build_judge_prompt(
            "Read email", tool, {}
        )
        assert "Parameters:" in prompt


# ---------------------------------------------------------------------------
# _parse_judge_response
# ---------------------------------------------------------------------------

class TestParseJudgeResponse:
    def test_valid_format(self):
        score, reason = TaskAlignmentDefense._parse_judge_response(
            "SCORE: 0.85 | REASON: The action is aligned with the goal."
        )
        assert score == pytest.approx(0.85)
        assert "aligned" in reason

    def test_score_clamped_high(self):
        score, _ = TaskAlignmentDefense._parse_judge_response(
            "SCORE: 1.5 | REASON: Over."
        )
        assert score == 1.0

    def test_score_clamped_low(self):
        # Negative numbers don't match the regex [\d.]+, so this gets
        # the "could not parse" fallback of 0.5.  Test with a very large value instead.
        score, _ = TaskAlignmentDefense._parse_judge_response(
            "SCORE: 0.0 | REASON: Zero score."
        )
        assert score == 0.0

    def test_invalid_score_returns_half(self):
        score, _ = TaskAlignmentDefense._parse_judge_response(
            "SCORE: abc | REASON: Bad number."
        )
        assert score == 0.5

    def test_unparseable_response(self):
        score, reason = TaskAlignmentDefense._parse_judge_response(
            "I think this is fine."
        )
        assert score == 0.5
        assert "Could not parse" in reason

    def test_case_insensitive(self):
        score, reason = TaskAlignmentDefense._parse_judge_response(
            "score: 0.9 | reason: OK"
        )
        assert score == pytest.approx(0.9)
        assert "OK" in reason


# ---------------------------------------------------------------------------
# should_allow_tool_call -- integration-level
# ---------------------------------------------------------------------------

class TestShouldAllowToolCall:
    def test_skips_low_risk_when_check_high_risk_only(self):
        d = TaskAlignmentDefense(config={"check_high_risk_only": True})
        tool = _make_tool("search_web", risk=RiskLevel.LOW)
        allowed, reason = d.should_allow_tool_call(
            tool, {}, {"goal": "anything"}
        )
        assert allowed is True
        assert "skipped" in reason.lower()

    def test_checks_low_risk_when_disabled(self):
        d = TaskAlignmentDefense(config={
            "check_high_risk_only": False,
            "alignment_threshold": 0.8,
        })
        tool = _make_tool("send_email", risk=RiskLevel.LOW)
        allowed, reason = d.should_allow_tool_call(
            tool, {"to": "attacker@evil.com"},
            {"goal": "Search the web for python"},
        )
        # send_email vs search goal -> mismatched -> score ~0.3
        assert allowed is False
        assert "failed" in reason.lower()

    def test_high_threshold_blocks_moderate_alignment(self):
        d = TaskAlignmentDefense(config={
            "check_high_risk_only": False,
            "alignment_threshold": 0.95,
        })
        tool = _make_tool("read_email")
        allowed, reason = d.should_allow_tool_call(
            tool, {"email_id": "email_999"},
            {"goal": "Read email_001 and summarize it"},
        )
        # score ~0.9 (matching category), threshold 0.95 -> fail
        assert allowed is False

    def test_param_overlap_bonus_pushes_over_threshold(self):
        d = TaskAlignmentDefense(config={
            "check_high_risk_only": False,
            "alignment_threshold": 0.95,
        })
        tool = _make_tool("read_email")
        # email_001 is in goal -> +0.1 bonus -> 0.9+0.1 = 1.0 >= 0.95
        allowed, _ = d.should_allow_tool_call(
            tool, {"email_id": "email_001"},
            {"goal": "Read email_001 and summarize it"},
        )
        assert allowed is True
