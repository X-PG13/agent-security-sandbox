"""Tests for the statistical analysis module."""

import pytest

from agent_security_sandbox.evaluation.analysis import (
    AnalysisReport,
    CategoryBreakdown,
    CategoryMetrics,
    ComparisonResult,
    ConfidenceInterval,
    CostBenefit,
    StatisticalAnalyzer,
    mcnemar_test,
    wilson_score_interval,
)
from agent_security_sandbox.evaluation.benchmark import BenchmarkCase
from agent_security_sandbox.evaluation.judge import JudgeResult, JudgeVerdict
from agent_security_sandbox.evaluation.metrics import EvaluationMetrics
from agent_security_sandbox.evaluation.reporter import Reporter
from agent_security_sandbox.evaluation.runner import ExperimentResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_attack_result(case_id: str, succeeded: bool) -> JudgeResult:
    verdict = JudgeVerdict.ATTACK_SUCCEEDED if succeeded else JudgeVerdict.ATTACK_BLOCKED
    return JudgeResult(verdict=verdict, case_id=case_id, reason="test")


def _make_benign_result(case_id: str, completed: bool) -> JudgeResult:
    verdict = JudgeVerdict.BENIGN_COMPLETED if completed else JudgeVerdict.BENIGN_BLOCKED
    return JudgeResult(verdict=verdict, case_id=case_id, reason="test")


def _make_attack_case(case_id: str, attack_type: str = "data_exfiltration",
                      injection_location: str = "email_body",
                      injection_technique: str = "direct_override",
                      difficulty: str = "easy") -> BenchmarkCase:
    return BenchmarkCase(
        id=case_id, type="attack",
        goal="Test goal", untrusted_content="injection",
        attack_type=attack_type, injection_location=injection_location,
        injection_technique=injection_technique, difficulty=difficulty,
        forbidden_actions=[{"tool": "send_email", "params": {"to": "evil@bad.com"}}],
    )


def _make_benign_case(case_id: str, difficulty: str = "easy") -> BenchmarkCase:
    return BenchmarkCase(
        id=case_id, type="benign", goal="Benign task",
        expected_tools=["read_email"], difficulty=difficulty,
    )


def _make_experiment(name: str, attack_results, benign_results,
                     attack_cases=None, benign_cases=None,
                     total_tokens=1000) -> ExperimentResult:
    results = attack_results + benign_results
    cases = (attack_cases or []) + (benign_cases or [])

    n_attack = len(attack_results)
    n_benign = len(benign_results)
    n_atk_succ = sum(1 for r in attack_results if r.verdict == JudgeVerdict.ATTACK_SUCCEEDED)
    n_ben_comp = sum(1 for r in benign_results if r.verdict == JudgeVerdict.BENIGN_COMPLETED)
    n_ben_block = n_benign - n_ben_comp

    asr = n_atk_succ / n_attack if n_attack > 0 else 0.0
    bsr = n_ben_comp / n_benign if n_benign > 0 else 0.0
    fpr = n_ben_block / n_benign if n_benign > 0 else 0.0

    return ExperimentResult(
        defense_name=name,
        results=results,
        cases=cases,
        metrics=EvaluationMetrics(
            asr=asr, bsr=bsr, fpr=fpr,
            total_cost=total_tokens,
            num_cases=len(results),
            attack_cases=n_attack,
            benign_cases=n_benign,
        ),
    )


# ---------------------------------------------------------------------------
# Tests: Wilson Score Interval
# ---------------------------------------------------------------------------

class TestWilsonScoreInterval:
    def test_zero_trials(self):
        p, lo, hi = wilson_score_interval(0, 0)
        assert p == 0.0
        assert lo == 0.0
        assert hi == 0.0

    def test_all_success(self):
        p, lo, hi = wilson_score_interval(10, 10)
        assert p == 1.0
        assert lo > 0.5
        assert hi == 1.0

    def test_no_success(self):
        p, lo, hi = wilson_score_interval(0, 10)
        assert p == 0.0
        assert lo == 0.0
        assert hi < 0.5

    def test_half_success(self):
        p, lo, hi = wilson_score_interval(50, 100)
        assert abs(p - 0.5) < 1e-9
        assert lo < 0.5
        assert hi > 0.5
        # CI should be roughly [0.40, 0.60] for n=100
        assert lo > 0.35
        assert hi < 0.65

    def test_bounds_are_valid(self):
        for n in [5, 20, 100]:
            for k in range(n + 1):
                p, lo, hi = wilson_score_interval(k, n)
                assert -1e-9 <= lo <= p + 1e-9
                assert p - 1e-9 <= hi <= 1.0 + 1e-9

    def test_different_confidence(self):
        _, lo_95, hi_95 = wilson_score_interval(50, 100, confidence=0.95)
        _, lo_99, hi_99 = wilson_score_interval(50, 100, confidence=0.99)
        # 99% CI should be wider
        assert (hi_99 - lo_99) > (hi_95 - lo_95)


# ---------------------------------------------------------------------------
# Tests: McNemar's Test
# ---------------------------------------------------------------------------

class TestMcNemarTest:
    def test_no_discordant(self):
        chi2, p = mcnemar_test(0, 0)
        assert chi2 == 0.0
        assert p == 1.0

    def test_symmetric_discordant(self):
        chi2, p = mcnemar_test(5, 5)
        # Continuity-corrected: (|5-5| - 1)^2 / 10 = 1/10 = 0.1
        assert abs(chi2 - 0.1) < 1e-6
        assert p > 0.05  # not significant

    def test_asymmetric_discordant(self):
        chi2, p = mcnemar_test(20, 2)
        # (|2-20| - 1)^2 / 22 = 17^2/22 = 289/22 ≈ 13.14
        expected_chi2 = (17 ** 2) / 22
        assert abs(chi2 - expected_chi2) < 0.01
        assert p < 0.01  # significant

    def test_returns_floats(self):
        chi2, p = mcnemar_test(3, 7)
        assert isinstance(chi2, float)
        assert isinstance(p, float)
        assert 0 <= p <= 1


# ---------------------------------------------------------------------------
# Tests: StatisticalAnalyzer
# ---------------------------------------------------------------------------

class TestStatisticalAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return StatisticalAnalyzer()

    @pytest.fixture
    def experiment_d0(self):
        """Baseline: ASR=0.6, BSR=1.0"""
        atk_results = [
            _make_attack_result(f"atk_{i:03d}", succeeded=(i < 6))
            for i in range(10)
        ]
        ben_results = [
            _make_benign_result(f"ben_{i:03d}", completed=True)
            for i in range(5)
        ]
        atk_cases = [
            _make_attack_case(f"atk_{i:03d}",
                              attack_type="data_exfiltration" if i < 5 else "goal_hijacking",
                              injection_technique="direct_override" if i < 7 else "persona_hijack",
                              difficulty="easy" if i < 4 else "hard")
            for i in range(10)
        ]
        ben_cases = [_make_benign_case(f"ben_{i:03d}") for i in range(5)]
        return _make_experiment("no_defense", atk_results, ben_results,
                                atk_cases, ben_cases, total_tokens=1500)

    @pytest.fixture
    def experiment_d1(self):
        """D1: ASR=0.2, BSR=0.8"""
        atk_results = [
            _make_attack_result(f"atk_{i:03d}", succeeded=(i < 2))
            for i in range(10)
        ]
        ben_results = [
            _make_benign_result(f"ben_{i:03d}", completed=(i < 4))
            for i in range(5)
        ]
        atk_cases = [
            _make_attack_case(f"atk_{i:03d}",
                              attack_type="data_exfiltration" if i < 5 else "goal_hijacking",
                              injection_technique="direct_override" if i < 7 else "persona_hijack",
                              difficulty="easy" if i < 4 else "hard")
            for i in range(10)
        ]
        ben_cases = [_make_benign_case(f"ben_{i:03d}") for i in range(5)]
        return _make_experiment("SpotlightingDefense", atk_results, ben_results,
                                atk_cases, ben_cases, total_tokens=2000)

    def test_analyze_single_defense(self, analyzer, experiment_d0):
        report = analyzer.analyze([experiment_d0])

        assert "no_defense" in report.confidence_intervals
        cis = report.confidence_intervals["no_defense"]
        assert len(cis) == 3  # ASR, BSR, FPR

        asr_ci = cis[0]
        assert asr_ci.metric_name == "ASR"
        assert abs(asr_ci.point - 0.6) < 1e-9
        assert asr_ci.n == 10

        bsr_ci = cis[1]
        assert bsr_ci.metric_name == "BSR"
        assert abs(bsr_ci.point - 1.0) < 1e-9

        fpr_ci = cis[2]
        assert fpr_ci.metric_name == "FPR"
        assert abs(fpr_ci.point - 0.0) < 1e-9

    def test_analyze_category_breakdowns(self, analyzer, experiment_d0):
        report = analyzer.analyze([experiment_d0])
        breakdowns = report.category_breakdowns.get("no_defense", [])
        assert len(breakdowns) > 0

        # Check attack_type breakdown exists
        dim_names = [bd.dimension for bd in breakdowns]
        assert "attack_type" in dim_names
        assert "difficulty" in dim_names

    def test_analyze_attack_type_slices(self, analyzer, experiment_d0):
        report = analyzer.analyze([experiment_d0])
        breakdowns = report.category_breakdowns["no_defense"]
        atk_type_bd = next(bd for bd in breakdowns if bd.dimension == "attack_type")

        # We have data_exfiltration (indices 0-4) and goal_hijacking (5-9)
        assert len(atk_type_bd.slices) == 2
        vals = {s.category_value for s in atk_type_bd.slices}
        assert "data_exfiltration" in vals
        assert "goal_hijacking" in vals

    def test_analyze_pairwise_comparison(self, analyzer, experiment_d0, experiment_d1):
        report = analyzer.analyze([experiment_d0, experiment_d1])
        assert len(report.comparisons) == 1

        comp = report.comparisons[0]
        assert comp.defense_a == "no_defense"
        assert comp.defense_b == "SpotlightingDefense"
        assert comp.metric == "attack_blocked"
        assert comp.n_cases == 10

    def test_analyze_cost_benefit(self, analyzer, experiment_d0, experiment_d1):
        report = analyzer.analyze([experiment_d0, experiment_d1])
        assert len(report.cost_benefits) == 2

        cb0 = report.cost_benefits[0]
        assert cb0.defense_name == "no_defense"
        assert abs(cb0.asr - 0.6) < 1e-9
        assert abs(cb0.security_score - 0.4) < 1e-9
        assert cb0.avg_tokens_per_case == 1500 / 15

        cb1 = report.cost_benefits[1]
        assert cb1.defense_name == "SpotlightingDefense"
        assert abs(cb1.security_score - 0.8) < 1e-9

    def test_analyze_empty_results(self, analyzer):
        report = analyzer.analyze([])
        assert report.confidence_intervals == {}
        assert report.comparisons == []
        assert report.cost_benefits == []

    def test_analyze_no_cases_field(self, analyzer):
        """ExperimentResult without cases should still compute CIs."""
        er = ExperimentResult(
            defense_name="test",
            results=[
                _make_attack_result("a1", True),
                _make_attack_result("a2", False),
                _make_benign_result("b1", True),
            ],
            metrics=EvaluationMetrics(
                asr=0.5, bsr=1.0, fpr=0.0,
                total_cost=100, num_cases=3,
                attack_cases=2, benign_cases=1,
            ),
        )
        report = analyzer.analyze([er])
        assert "test" in report.confidence_intervals
        # No breakdowns since no cases
        assert report.category_breakdowns.get("test", []) == []

    def test_mcnemar_direction(self, analyzer):
        """When D0 has more attacks succeeding than D1, a_only should reflect that."""
        # D0: all 10 attacks succeed
        d0_results = [_make_attack_result(f"a{i}", True) for i in range(10)]
        d0_ben = [_make_benign_result(f"b{i}", True) for i in range(5)]
        d0 = _make_experiment("D0", d0_results, d0_ben, total_tokens=500)

        # D1: all 10 attacks blocked
        d1_results = [_make_attack_result(f"a{i}", False) for i in range(10)]
        d1_ben = [_make_benign_result(f"b{i}", True) for i in range(5)]
        d1 = _make_experiment("D1", d1_results, d1_ben, total_tokens=500)

        report = analyzer.analyze([d0, d1])
        comp = report.comparisons[0]
        # D1 blocked all 10 that D0 didn't -> b_only=10
        assert comp.b_only == 10
        assert comp.a_only == 0
        assert comp.significant  # should be significant


# ---------------------------------------------------------------------------
# Tests: Reporter analysis markdown
# ---------------------------------------------------------------------------

class TestReporterAnalysis:
    def test_generate_analysis_markdown(self):
        report = AnalysisReport(
            confidence_intervals={
                "D0": [
                    ConfidenceInterval("ASR", 0.6, 0.3, 0.85, 10),
                    ConfidenceInterval("BSR", 1.0, 0.7, 1.0, 5),
                    ConfidenceInterval("FPR", 0.0, 0.0, 0.3, 5),
                ],
            },
            category_breakdowns={
                "D0": [
                    CategoryBreakdown(
                        dimension="attack_type",
                        slices=[
                            CategoryMetrics(
                                "attack_type", "data_exfiltration",
                                5, 3, 0.6,
                                ConfidenceInterval(
                                    "attack_type_data_exfiltration",
                                    0.6, 0.2, 0.9, 5,
                                ),
                            ),
                        ],
                    ),
                ],
            },
            comparisons=[
                ComparisonResult("D0", "D1", "attack_blocked", 10, 2, 8, 3.6, 0.058, False),
            ],
            cost_benefits=[
                CostBenefit("D0", 0.6, 1.0, 0.0, 100.0, 0.4, 1.0),
            ],
        )

        reporter = Reporter()
        md = reporter.generate_analysis_markdown(report)

        assert "Statistical Analysis Report" in md
        assert "Confidence Intervals" in md
        assert "D0" in md
        assert "ASR" in md
        assert "Category Breakdowns" in md
        assert "data_exfiltration" in md
        assert "McNemar" in md
        assert "Cost-Benefit" in md

    def test_empty_report(self):
        report = AnalysisReport()
        reporter = Reporter()
        md = reporter.generate_analysis_markdown(report)
        assert "Statistical Analysis Report" in md


# ---------------------------------------------------------------------------
# Tests: Difficulty Analysis
# ---------------------------------------------------------------------------

class TestDifficultyAnalysis:
    def test_difficulty_analysis_present(self):
        """analyze() should populate difficulty_analysis."""
        cases = [
            _make_attack_case("a1", difficulty="easy"),
            _make_attack_case("a2", difficulty="easy"),
            _make_attack_case("a3", difficulty="hard"),
            _make_attack_case("a4", difficulty="hard"),
        ]
        results = [
            _make_attack_result("a1", True),   # easy, succeeded
            _make_attack_result("a2", False),  # easy, blocked
            _make_attack_result("a3", True),   # hard, succeeded
            _make_attack_result("a4", True),   # hard, succeeded
        ]
        er = _make_experiment(
            "D0", results, [],
            attack_cases=cases, benign_cases=[],
        )
        analyzer = StatisticalAnalyzer()
        report = analyzer.analyze([er])

        da = report.difficulty_analysis
        assert da is not None
        assert "easy" in da.difficulty_levels
        assert "hard" in da.difficulty_levels
        assert "D0" in da.rows

        cells = da.rows["D0"]
        easy_cell = next(c for c in cells if c.difficulty == "easy")
        hard_cell = next(c for c in cells if c.difficulty == "hard")

        assert easy_cell.n_attack == 2
        assert easy_cell.n_succeeded == 1
        assert abs(easy_cell.asr - 0.5) < 1e-9

        assert hard_cell.n_attack == 2
        assert hard_cell.n_succeeded == 2
        assert abs(hard_cell.asr - 1.0) < 1e-9

    def test_difficulty_analysis_multiple_defenses(self):
        """Cross-table should have rows for each defence."""
        cases = [
            _make_attack_case("a1", difficulty="easy"),
            _make_attack_case("a2", difficulty="hard"),
        ]
        d0 = _make_experiment(
            "D0",
            [_make_attack_result("a1", True),
             _make_attack_result("a2", True)],
            [], attack_cases=cases, benign_cases=[],
        )
        d1 = _make_experiment(
            "D1",
            [_make_attack_result("a1", False),
             _make_attack_result("a2", True)],
            [], attack_cases=cases, benign_cases=[],
        )

        analyzer = StatisticalAnalyzer()
        report = analyzer.analyze([d0, d1])

        da = report.difficulty_analysis
        assert "D0" in da.rows
        assert "D1" in da.rows

        # D0: easy ASR=1.0, hard ASR=1.0
        d0_easy = next(
            c for c in da.rows["D0"] if c.difficulty == "easy"
        )
        assert abs(d0_easy.asr - 1.0) < 1e-9

        # D1: easy ASR=0.0 (blocked), hard ASR=1.0
        d1_easy = next(
            c for c in da.rows["D1"] if c.difficulty == "easy"
        )
        assert abs(d1_easy.asr - 0.0) < 1e-9

    def test_difficulty_analysis_empty(self):
        """Empty results should produce empty difficulty analysis."""
        analyzer = StatisticalAnalyzer()
        report = analyzer.analyze([])
        da = report.difficulty_analysis
        assert da is not None
        assert da.difficulty_levels == []
        assert da.rows == {}

    def test_difficulty_cell_has_ci(self):
        """Each DifficultyCell should have a confidence interval."""
        cases = [_make_attack_case("a1", difficulty="medium")]
        results = [_make_attack_result("a1", True)]
        er = _make_experiment(
            "D0", results, [],
            attack_cases=cases, benign_cases=[],
        )
        analyzer = StatisticalAnalyzer()
        report = analyzer.analyze([er])

        cell = report.difficulty_analysis.rows["D0"][0]
        assert cell.ci is not None
        assert cell.ci.metric_name == "ASR_medium"
        assert cell.ci.n == 1
