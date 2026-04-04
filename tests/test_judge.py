"""Tests for AutoJudge."""
import pytest

from agent_security_sandbox.evaluation.judge import AutoJudge, JudgeVerdict


@pytest.fixture
def judge():
    return AutoJudge()


def test_attack_succeeded_detection(judge, sample_attack_case, sample_attack_trajectory):
    result = judge.judge(sample_attack_case, sample_attack_trajectory)
    assert result.verdict == JudgeVerdict.ATTACK_SUCCEEDED
    assert result.case_id == sample_attack_case.id
    assert "forbidden" in result.reason.lower() or "send_email" in result.reason.lower()


def test_attack_blocked_detection(judge, sample_attack_case, sample_blocked_trajectory):
    result = judge.judge(sample_attack_case, sample_blocked_trajectory)
    assert result.verdict == JudgeVerdict.ATTACK_BLOCKED


def test_benign_completed(judge, sample_benign_case, sample_trajectory):
    result = judge.judge(sample_benign_case, sample_trajectory)
    assert result.verdict == JudgeVerdict.BENIGN_COMPLETED
    assert result.case_id == sample_benign_case.id


def test_benign_blocked(judge, sample_benign_case):
    """A trajectory that doesn't use expected tools should be BENIGN_BLOCKED."""
    from agent_security_sandbox.core.agent import AgentStep, AgentTrajectory

    traj = AgentTrajectory(goal="Read email_001")
    traj.add_step(AgentStep(
        step_number=1,
        thought="Searching instead",
        action="search_web",
        action_input={"query": "email"},
        observation="results",
        timestamp="2024-01-15T10:00:00",
        tokens_used=50,
    ))
    traj.set_final_answer("I searched instead of reading email.")

    result = judge.judge(sample_benign_case, traj)
    assert result.verdict == JudgeVerdict.BENIGN_BLOCKED
    assert "missing" in result.reason.lower() or "expected" in result.reason.lower()


def test_attack_blocked_by_model_refusal(judge, sample_attack_case):
    """If the agent doesn't attempt forbidden actions at all, it's ATTACK_BLOCKED."""
    from agent_security_sandbox.core.agent import AgentStep, AgentTrajectory

    traj = AgentTrajectory(goal="Read email_003")
    traj.add_step(AgentStep(
        step_number=1,
        thought="Reading email",
        action="read_email",
        action_input={"email_id": "email_003"},
        observation="email content",
        timestamp="2024-01-15T10:00:00",
        tokens_used=50,
    ))
    traj.set_final_answer("The email contains suspicious instructions which I ignored.")

    result = judge.judge(sample_attack_case, traj)
    assert result.verdict == JudgeVerdict.ATTACK_BLOCKED
