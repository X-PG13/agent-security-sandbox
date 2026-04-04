"""Tests for the Reporter module."""
from types import SimpleNamespace

import pytest

from agent_security_sandbox.evaluation.judge import JudgeResult, JudgeVerdict
from agent_security_sandbox.evaluation.metrics import EvaluationMetrics
from agent_security_sandbox.evaluation.reporter import Reporter
from agent_security_sandbox.evaluation.runner import ExperimentResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(
    defense_name="D0 (Baseline)",
    asr=0.5,
    bsr=0.9,
    fpr=0.1,
    verdicts=None,
) -> ExperimentResult:
    """Create a minimal ExperimentResult for testing."""
    if verdicts is None:
        verdicts = [
            JudgeResult(
                verdict=JudgeVerdict.ATTACK_SUCCEEDED,
                case_id="attack_001",
                reason="Injection succeeded",
            ),
            JudgeResult(
                verdict=JudgeVerdict.ATTACK_BLOCKED,
                case_id="attack_002",
                reason="Blocked by defense",
            ),
            JudgeResult(
                verdict=JudgeVerdict.BENIGN_COMPLETED,
                case_id="benign_001",
                reason="Task completed",
            ),
        ]
    metrics = EvaluationMetrics(
        asr=asr,
        bsr=bsr,
        fpr=fpr,
        total_cost=1000,
        num_cases=len(verdicts),
        attack_cases=sum(1 for v in verdicts if "attack" in v.case_id),
        benign_cases=sum(1 for v in verdicts if "benign" in v.case_id),
        details={},
    )
    return ExperimentResult(
        defense_name=defense_name,
        results=verdicts,
        metrics=metrics,
        timestamp="2026-03-01T00:00:00",
    )


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

class TestMarkdown:
    def test_empty_results(self):
        reporter = Reporter()
        md = reporter.generate_markdown([])
        assert "No experiment results" in md

    def test_single_result(self):
        reporter = Reporter()
        md = reporter.generate_markdown([_make_result()])
        assert "Evaluation Report" in md
        assert "D0 (Baseline)" in md
        assert "50.00%" in md  # ASR

    def test_multiple_results(self):
        reporter = Reporter()
        r1 = _make_result("D0 (Baseline)", asr=0.5, bsr=0.9)
        r2 = _make_result("D1 (Spotlighting)", asr=0.02, bsr=0.91)
        md = reporter.generate_markdown([r1, r2])
        assert "D0 (Baseline)" in md
        assert "D1 (Spotlighting)" in md

    def test_per_case_verdicts_in_markdown(self):
        reporter = Reporter()
        md = reporter.generate_markdown([_make_result()])
        assert "attack_001" in md
        assert "benign_001" in md

    def test_pipe_in_reason_escaped(self):
        """Pipes in reason text should be escaped for markdown tables."""
        verdicts = [
            JudgeResult(
                verdict=JudgeVerdict.ATTACK_BLOCKED,
                case_id="a1",
                reason="Blocked | reason with pipe",
            ),
        ]
        reporter = Reporter()
        md = reporter.generate_markdown([_make_result(verdicts=verdicts)])
        assert "\\|" in md


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

class TestJSON:
    def test_json_output_valid(self):
        import json
        reporter = Reporter()
        output = reporter.generate_json([_make_result()])
        parsed = json.loads(output)
        assert isinstance(parsed, list)
        assert len(parsed) == 1
        assert parsed[0]["defense_name"] == "D0 (Baseline)"

    def test_json_metrics(self):
        import json
        reporter = Reporter()
        output = reporter.generate_json([_make_result(asr=0.123)])
        parsed = json.loads(output)
        assert parsed[0]["metrics"]["asr"] == pytest.approx(0.123)

    def test_json_results_contain_verdicts(self):
        import json
        reporter = Reporter()
        output = reporter.generate_json([_make_result()])
        parsed = json.loads(output)
        results = parsed[0]["results"]
        assert any(r["verdict"] == "attack_succeeded" for r in results)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

class TestCSV:
    def test_csv_header(self):
        reporter = Reporter()
        csv = reporter.generate_csv([_make_result()])
        lines = csv.strip().split("\n")
        assert "defense_name" in lines[0]
        assert "case_id" in lines[0]

    def test_csv_row_count(self):
        reporter = Reporter()
        csv = reporter.generate_csv([_make_result()])
        lines = csv.strip().split("\n")
        # 1 header + 3 verdict rows
        assert len(lines) == 4

    def test_csv_multiple_defenses(self):
        reporter = Reporter()
        r1 = _make_result("D0")
        r2 = _make_result("D1")
        csv = reporter.generate_csv([r1, r2])
        lines = csv.strip().split("\n")
        # 1 header + 3 + 3 = 7
        assert len(lines) == 7


# ---------------------------------------------------------------------------
# save_report
# ---------------------------------------------------------------------------

class TestSaveReport:
    def test_save_creates_file(self, tmp_path):
        reporter = Reporter()
        filepath = tmp_path / "subdir" / "report.md"
        reporter.save_report("# Test", str(filepath))
        assert filepath.exists()
        assert filepath.read_text() == "# Test"


# ---------------------------------------------------------------------------
# Analysis Markdown
# ---------------------------------------------------------------------------

class TestAnalysisMarkdown:
    def test_analysis_markdown_with_all_sections(self):
        """generate_analysis_markdown should handle all report sections."""
        ci = SimpleNamespace(metric_name="ASR", point=0.5, lower=0.4, upper=0.6, n=100)
        breakdown_slice = SimpleNamespace(
            category_value="hijacking", total=20, successes=10, rate=0.5,
            ci=SimpleNamespace(lower=0.3, upper=0.7),
        )
        breakdown = SimpleNamespace(dimension="attack_type", slices=[breakdown_slice])
        comparison = SimpleNamespace(
            defense_a="D0", defense_b="D1", metric="ASR",
            n_cases=100, a_only=10, b_only=5,
            chi2=3.5, p_value=0.02, significant=True,
        )
        cost_benefit = SimpleNamespace(
            defense_name="D0", asr=0.5, bsr=0.9, fpr=0.1,
            avg_tokens_per_case=200, security_score=0.5, utility_score=0.9,
        )
        report = SimpleNamespace(
            confidence_intervals={"D0": [ci]},
            category_breakdowns={"D0": [breakdown]},
            comparisons=[comparison],
            cost_benefits=[cost_benefit],
        )

        reporter = Reporter()
        md = reporter.generate_analysis_markdown(report)
        assert "Statistical Analysis Report" in md
        assert "Confidence Intervals" in md
        assert "Category Breakdowns" in md
        assert "McNemar" in md
        assert "Cost-Benefit" in md

    def test_analysis_markdown_empty_comparisons(self):
        """Should handle empty comparisons list."""
        report = SimpleNamespace(
            confidence_intervals={},
            category_breakdowns={},
            comparisons=[],
            cost_benefits=[],
        )
        reporter = Reporter()
        md = reporter.generate_analysis_markdown(report)
        assert "Statistical Analysis Report" in md
        assert "McNemar" not in md  # section skipped
