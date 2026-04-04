"""Tests for benchmark loading and validation."""
import json

import pytest

from agent_security_sandbox.evaluation.benchmark import BenchmarkCase, BenchmarkSuite


def test_benchmark_case_creation():
    case = BenchmarkCase(
        id="test_001",
        type="attack",
        goal="Test goal",
        expected_tools=["read_email"],
        forbidden_actions=[{"tool": "send_email", "params": {"to": "bad@evil.com"}}],
        tags=["test"],
        difficulty=1,
    )
    assert case.id == "test_001"
    assert case.type == "attack"


def test_load_from_jsonl(tmp_path):
    data = [
        {
            "id": "b1", "type": "benign", "goal": "test",
            "expected_tools": [], "forbidden_actions": [],
            "tags": [], "difficulty": 1,
        },
        {
            "id": "b2", "type": "benign", "goal": "test2",
            "expected_tools": [], "forbidden_actions": [],
            "tags": [], "difficulty": 2,
        },
    ]
    f = tmp_path / "test.jsonl"
    f.write_text("\n".join(json.dumps(d) for d in data) + "\n")

    suite = BenchmarkSuite.load_from_jsonl(str(f))
    assert len(suite) == 2
    assert suite.cases[0].id == "b1"


def test_load_from_directory(tmp_benchmark_dir):
    suite = BenchmarkSuite.load_from_directory(str(tmp_benchmark_dir))
    assert len(suite) == 3  # 2 benign + 1 attack
    assert len(suite.attack_cases) == 1
    assert len(suite.benign_cases) == 2


def test_filter_by_type(tmp_benchmark_dir):
    suite = BenchmarkSuite.load_from_directory(str(tmp_benchmark_dir))
    attacks = suite.filter_by_type("attack")
    assert len(attacks) == 1
    benign = suite.filter_by_type("benign")
    assert len(benign) == 2


def test_filter_by_tag(tmp_benchmark_dir):
    suite = BenchmarkSuite.load_from_directory(str(tmp_benchmark_dir))
    email_cases = suite.filter_by_tag("email")
    assert len(email_cases) >= 1


def test_case_validation():
    """Invalid type should raise validation error."""
    with pytest.raises(Exception):
        BenchmarkCase(
            id="bad", type="invalid", goal="test",
            expected_tools=[], forbidden_actions=[], tags=[], difficulty=1,
        )


def test_empty_suite():
    suite = BenchmarkSuite()
    assert len(suite) == 0
    assert suite.attack_cases == []
    assert suite.benign_cases == []
