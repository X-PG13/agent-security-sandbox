"""Tests for MetricsCalculator."""
import pytest

from agent_security_sandbox.evaluation.judge import JudgeResult, JudgeVerdict
from agent_security_sandbox.evaluation.metrics import MetricsCalculator


@pytest.fixture
def calculator():
    return MetricsCalculator()


def test_perfect_defense(calculator):
    """All attacks blocked, all benign completed."""
    results = [
        JudgeResult(verdict=JudgeVerdict.ATTACK_BLOCKED, case_id="a1", reason="blocked"),
        JudgeResult(verdict=JudgeVerdict.ATTACK_BLOCKED, case_id="a2", reason="blocked"),
        JudgeResult(verdict=JudgeVerdict.BENIGN_COMPLETED, case_id="b1", reason="ok"),
        JudgeResult(verdict=JudgeVerdict.BENIGN_COMPLETED, case_id="b2", reason="ok"),
    ]
    metrics = calculator.calculate(results, total_tokens=200)
    assert metrics.asr == 0.0
    assert metrics.bsr == 1.0
    assert metrics.fpr == 0.0
    assert metrics.num_cases == 4


def test_no_defense(calculator):
    """All attacks succeed, all benign complete."""
    results = [
        JudgeResult(verdict=JudgeVerdict.ATTACK_SUCCEEDED, case_id="a1", reason="ok"),
        JudgeResult(verdict=JudgeVerdict.ATTACK_SUCCEEDED, case_id="a2", reason="ok"),
        JudgeResult(verdict=JudgeVerdict.BENIGN_COMPLETED, case_id="b1", reason="ok"),
        JudgeResult(verdict=JudgeVerdict.BENIGN_COMPLETED, case_id="b2", reason="ok"),
    ]
    metrics = calculator.calculate(results, total_tokens=200)
    assert metrics.asr == 1.0
    assert metrics.bsr == 1.0
    assert metrics.fpr == 0.0


def test_mixed_results(calculator):
    """Mixed outcomes."""
    results = [
        JudgeResult(verdict=JudgeVerdict.ATTACK_SUCCEEDED, case_id="a1", reason="ok"),
        JudgeResult(verdict=JudgeVerdict.ATTACK_BLOCKED, case_id="a2", reason="blocked"),
        JudgeResult(verdict=JudgeVerdict.BENIGN_COMPLETED, case_id="b1", reason="ok"),
        JudgeResult(verdict=JudgeVerdict.BENIGN_BLOCKED, case_id="b2", reason="fp"),
    ]
    metrics = calculator.calculate(results, total_tokens=400)
    assert metrics.asr == 0.5  # 1/2
    assert metrics.bsr == 0.5  # 1/2
    assert metrics.fpr == 0.5  # 1/2
    assert metrics.total_cost == 400


def test_fpr_calculation(calculator):
    """FPR = benign_blocked / total_benign."""
    results = [
        JudgeResult(verdict=JudgeVerdict.BENIGN_BLOCKED, case_id="b1", reason="fp"),
        JudgeResult(verdict=JudgeVerdict.BENIGN_BLOCKED, case_id="b2", reason="fp"),
        JudgeResult(verdict=JudgeVerdict.BENIGN_COMPLETED, case_id="b3", reason="ok"),
        JudgeResult(verdict=JudgeVerdict.BENIGN_COMPLETED, case_id="b4", reason="ok"),
    ]
    metrics = calculator.calculate(results)
    assert metrics.fpr == 0.5
    assert metrics.bsr == 0.5
    assert metrics.benign_cases == 4


def test_empty_results(calculator):
    metrics = calculator.calculate([])
    assert metrics.asr == 0.0
    assert metrics.bsr == 0.0
    assert metrics.fpr == 0.0
    assert metrics.num_cases == 0
