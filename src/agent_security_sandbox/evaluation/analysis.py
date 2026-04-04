"""
Statistical analysis for evaluation results.

Provides:
- :class:`ConfidenceInterval` — Wilson score confidence intervals.
- :class:`CategoryBreakdown` — per-category (attack_type, injection_location,
  injection_technique, difficulty) metric breakdowns.
- :class:`ComparisonResult` — pairwise defence comparison via McNemar's test.
- :class:`StatisticalAnalyzer` — high-level analysis pipeline.
- :class:`AnalysisReport` — structured container for all analysis outputs.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from ..evaluation.benchmark import BenchmarkCase
from ..evaluation.judge import JudgeResult, JudgeVerdict
from ..evaluation.runner import ExperimentResult

# ── Wilson Score Confidence Interval ─────────────────────────────────────────

@dataclass
class ConfidenceInterval:
    """A proportion with Wilson score confidence interval.

    Attributes:
        metric_name: Name of the metric (e.g. ``"ASR"``).
        point: Point estimate (proportion).
        lower: Lower bound of the CI.
        upper: Upper bound of the CI.
        n: Sample size.
        confidence: Confidence level (default 0.95).
    """
    metric_name: str
    point: float
    lower: float
    upper: float
    n: int
    confidence: float = 0.95


def wilson_score_interval(
    successes: int, n: int, confidence: float = 0.95,
) -> Tuple[float, float, float]:
    """Compute the Wilson score confidence interval for a proportion.

    Args:
        successes: Number of successes.
        n: Total trials.
        confidence: Confidence level (0.95 for 95% CI).

    Returns:
        ``(point, lower, upper)`` — the proportion and its CI bounds.
    """
    if n == 0:
        return 0.0, 0.0, 0.0

    p_hat = successes / n

    # z-value for the given confidence level (two-tailed)
    # Common values: 0.90 -> 1.645, 0.95 -> 1.96, 0.99 -> 2.576
    z_map = {0.90: 1.645, 0.95: 1.96, 0.99: 2.576}
    z = z_map.get(confidence, 1.96)

    denominator = 1 + z * z / n
    centre = p_hat + z * z / (2 * n)
    spread = z * math.sqrt((p_hat * (1 - p_hat) + z * z / (4 * n)) / n)

    lower = max(0.0, (centre - spread) / denominator)
    upper = min(1.0, (centre + spread) / denominator)

    return p_hat, lower, upper


# ── Category Breakdown ───────────────────────────────────────────────────────

@dataclass
class CategoryMetrics:
    """Metrics for a single category slice.

    Attributes:
        category_name: The category dimension (e.g. ``"attack_type"``).
        category_value: The value within that dimension (e.g. ``"data_exfiltration"``).
        total: Number of cases in this slice.
        successes: Number of "successful" outcomes (attack_succeeded for attacks,
            benign_completed for benign).
        rate: Success rate (proportion).
        ci: Confidence interval for the rate.
    """
    category_name: str
    category_value: str
    total: int
    successes: int
    rate: float
    ci: ConfidenceInterval


@dataclass
class CategoryBreakdown:
    """Breakdown of metrics across a categorical dimension."""
    dimension: str
    slices: List[CategoryMetrics] = field(default_factory=list)


# ── McNemar's Test ───────────────────────────────────────────────────────────

@dataclass
class ComparisonResult:
    """Pairwise comparison between two defences via McNemar's test.

    McNemar's test compares paired binary outcomes. For each case we
    compare whether defence A blocked the attack and defence B did not
    (or vice versa).

    Attributes:
        defense_a: Name of the first defence.
        defense_b: Name of the second defence.
        metric: Which metric is being compared (e.g. ``"attack_blocked"``).
        n_cases: Number of paired cases.
        a_only: Cases where only A succeeded/blocked.
        b_only: Cases where only B succeeded/blocked.
        chi2: McNemar's chi-squared statistic.
        p_value: Approximate p-value.
        significant: Whether the difference is significant at alpha=0.05.
    """
    defense_a: str
    defense_b: str
    metric: str
    n_cases: int
    a_only: int
    b_only: int
    chi2: float
    p_value: float
    significant: bool


def mcnemar_test(
    a_only: int, b_only: int,
) -> Tuple[float, float]:
    """Compute McNemar's chi-squared test statistic and p-value.

    Uses the standard McNemar's formula: chi2 = (|b - c| - 1)^2 / (b + c)
    with continuity correction.

    Args:
        a_only: Discordant pairs where only A succeeded.
        b_only: Discordant pairs where only B succeeded.

    Returns:
        ``(chi2, p_value)`` — the test statistic and approximate p-value
        based on the chi-squared distribution with 1 degree of freedom.
    """
    total_discordant = a_only + b_only
    if total_discordant == 0:
        return 0.0, 1.0

    # McNemar's with continuity correction
    numerator = (abs(b_only - a_only) - 1) ** 2
    if numerator < 0:
        numerator = 0
    chi2 = numerator / total_discordant

    # Approximate p-value using chi2(1) survival function
    # Using the simple approximation: p ≈ erfc(sqrt(chi2/2))
    # For more accuracy we'd use scipy, but we avoid the dependency.
    p_value = _chi2_sf(chi2, df=1)

    return chi2, p_value


def _chi2_sf(x: float, df: int = 1) -> float:
    """Survival function (1 - CDF) for chi-squared distribution.

    Simple approximation for df=1 using the complementary error function.
    """
    if x <= 0:
        return 1.0
    if df != 1:
        # Fallback: very rough approximation for other df
        return math.exp(-x / 2)
    # For df=1: chi2 CDF = 2 * Phi(sqrt(x)) - 1
    # So SF = 2 * (1 - Phi(sqrt(x))) = erfc(sqrt(x/2))
    return math.erfc(math.sqrt(x / 2))


# ── Cost-Benefit Analysis ────────────────────────────────────────────────────

@dataclass
class CostBenefit:
    """Cost-benefit summary for a defence strategy.

    Attributes:
        defense_name: Defence strategy name.
        asr: Attack Success Rate.
        bsr: Benign Success Rate.
        fpr: False Positive Rate.
        avg_tokens_per_case: Average token cost per case.
        security_score: Composite security score (lower ASR = better).
        utility_score: Composite utility score (higher BSR, lower FPR = better).
    """
    defense_name: str
    asr: float
    bsr: float
    fpr: float
    avg_tokens_per_case: float
    security_score: float
    utility_score: float


# ── Analysis Report ──────────────────────────────────────────────────────────

@dataclass
class DifficultyCell:
    """ASR at a single difficulty level for one defence."""
    difficulty: str
    n_attack: int
    n_succeeded: int
    asr: float
    ci: ConfidenceInterval


@dataclass
class DifficultyAnalysis:
    """Cross-tabulation of ASR by difficulty × defence.

    ``rows`` is keyed by defence name; each value is a list of
    :class:`DifficultyCell` sorted by difficulty level.
    """
    difficulty_levels: List[str]
    rows: Dict[str, List[DifficultyCell]] = field(default_factory=dict)


@dataclass
class AnalysisReport:
    """Structured container for all analysis outputs.

    Attributes:
        confidence_intervals: Per-defence CIs for ASR, BSR, FPR.
        category_breakdowns: Per-defence breakdowns by category.
        comparisons: Pairwise defence comparisons.
        cost_benefits: Per-defence cost-benefit summaries.
        difficulty_analysis: ASR by difficulty × defence cross-table.
    """
    confidence_intervals: Dict[str, List[ConfidenceInterval]] = field(
        default_factory=dict
    )
    category_breakdowns: Dict[str, List[CategoryBreakdown]] = field(
        default_factory=dict
    )
    comparisons: List[ComparisonResult] = field(default_factory=list)
    cost_benefits: List[CostBenefit] = field(default_factory=list)
    difficulty_analysis: DifficultyAnalysis | None = None


# ── StatisticalAnalyzer ──────────────────────────────────────────────────────

class StatisticalAnalyzer:
    """High-level analysis pipeline for experiment results.

    Usage::

        analyzer = StatisticalAnalyzer()
        report = analyzer.analyze([result_d0, result_d1, result_d2])
    """

    def analyze(
        self,
        experiment_results: List[ExperimentResult],
        confidence: float = 0.95,
    ) -> AnalysisReport:
        """Run full statistical analysis on experiment results.

        Args:
            experiment_results: List of :class:`ExperimentResult` (one per defence).
            confidence: Confidence level for CIs (default 0.95).

        Returns:
            A comprehensive :class:`AnalysisReport`.
        """
        report = AnalysisReport()

        for er in experiment_results:
            name = er.defense_name

            # Confidence intervals
            report.confidence_intervals[name] = self._compute_cis(er, confidence)

            # Category breakdowns
            report.category_breakdowns[name] = self._compute_breakdowns(
                er, confidence
            )

            # Cost-benefit
            report.cost_benefits.append(self._compute_cost_benefit(er))

        # Pairwise comparisons
        if len(experiment_results) >= 2:
            report.comparisons = self._compute_comparisons(
                experiment_results
            )

        # Difficulty × defence cross-analysis
        report.difficulty_analysis = self._compute_difficulty_analysis(
            experiment_results, confidence
        )

        return report

    # ── Internal: Confidence Intervals ────────────────────────────────────

    @staticmethod
    def _compute_cis(
        er: ExperimentResult, confidence: float,
    ) -> List[ConfidenceInterval]:
        """Compute CIs for ASR, BSR, FPR."""
        cis: List[ConfidenceInterval] = []
        attack_results = [
            r for r in er.results
            if r.verdict in (JudgeVerdict.ATTACK_SUCCEEDED, JudgeVerdict.ATTACK_BLOCKED)
        ]
        benign_results = [
            r for r in er.results
            if r.verdict in (JudgeVerdict.BENIGN_COMPLETED, JudgeVerdict.BENIGN_BLOCKED)
        ]

        # ASR
        n_attack = len(attack_results)
        n_succeeded = sum(
            1 for r in attack_results if r.verdict == JudgeVerdict.ATTACK_SUCCEEDED
        )
        point, lower, upper = wilson_score_interval(n_succeeded, n_attack, confidence)
        cis.append(ConfidenceInterval(
            metric_name="ASR", point=point, lower=lower, upper=upper,
            n=n_attack, confidence=confidence,
        ))

        # BSR
        n_benign = len(benign_results)
        n_completed = sum(
            1 for r in benign_results if r.verdict == JudgeVerdict.BENIGN_COMPLETED
        )
        point, lower, upper = wilson_score_interval(n_completed, n_benign, confidence)
        cis.append(ConfidenceInterval(
            metric_name="BSR", point=point, lower=lower, upper=upper,
            n=n_benign, confidence=confidence,
        ))

        # FPR
        n_blocked = sum(
            1 for r in benign_results if r.verdict == JudgeVerdict.BENIGN_BLOCKED
        )
        point, lower, upper = wilson_score_interval(n_blocked, n_benign, confidence)
        cis.append(ConfidenceInterval(
            metric_name="FPR", point=point, lower=lower, upper=upper,
            n=n_benign, confidence=confidence,
        ))

        return cis

    # ── Internal: Category Breakdowns ─────────────────────────────────────

    @staticmethod
    def _compute_breakdowns(
        er: ExperimentResult, confidence: float,
    ) -> List[CategoryBreakdown]:
        """Compute breakdowns by attack_type, injection_location,
        injection_technique, difficulty."""
        breakdowns: List[CategoryBreakdown] = []

        if not er.cases:
            return breakdowns

        # Pair cases with results
        paired = list(zip(er.cases, er.results))

        dimensions = [
            ("attack_type", lambda c: getattr(c, "attack_type", None)),
            ("injection_location", lambda c: getattr(c, "injection_location", None)),
            ("injection_technique", lambda c: getattr(c, "injection_technique", None)),
            ("difficulty", lambda c: str(getattr(c, "difficulty", None))),
        ]

        for dim_name, getter in dimensions:
            groups: Dict[str, List[Tuple[BenchmarkCase, JudgeResult]]] = defaultdict(list)
            for case, result in paired:
                val = getter(case)
                if val is not None:
                    groups[val].append((case, result))

            if not groups:
                continue

            bd = CategoryBreakdown(dimension=dim_name)
            for val, items in sorted(groups.items()):
                total = len(items)
                successes = sum(
                    1 for _, r in items
                    if r.verdict in (
                        JudgeVerdict.ATTACK_SUCCEEDED,
                        JudgeVerdict.BENIGN_COMPLETED,
                    )
                )
                rate, lower, upper = wilson_score_interval(successes, total, confidence)
                ci = ConfidenceInterval(
                    metric_name=f"{dim_name}_{val}",
                    point=rate, lower=lower, upper=upper,
                    n=total, confidence=confidence,
                )
                bd.slices.append(CategoryMetrics(
                    category_name=dim_name,
                    category_value=val,
                    total=total,
                    successes=successes,
                    rate=rate,
                    ci=ci,
                ))
            breakdowns.append(bd)

        return breakdowns

    # ── Internal: Pairwise Comparisons ────────────────────────────────────

    @staticmethod
    def _compute_comparisons(
        results: List[ExperimentResult],
    ) -> List[ComparisonResult]:
        """Pairwise McNemar's test on attack blocking between defences."""
        comparisons: List[ComparisonResult] = []

        for i in range(len(results)):
            for j in range(i + 1, len(results)):
                a = results[i]
                b = results[j]

                # Build case_id -> verdict maps
                a_map = {r.case_id: r.verdict for r in a.results}
                b_map = {r.case_id: r.verdict for r in b.results}

                # Find common attack cases
                common_ids = set(a_map.keys()) & set(b_map.keys())
                attack_ids = [
                    cid for cid in common_ids
                    if a_map[cid] in (JudgeVerdict.ATTACK_SUCCEEDED, JudgeVerdict.ATTACK_BLOCKED)
                    and b_map[cid] in (JudgeVerdict.ATTACK_SUCCEEDED, JudgeVerdict.ATTACK_BLOCKED)
                ]

                if not attack_ids:
                    continue

                # Discordant pairs for attack blocking
                a_blocked_only = sum(
                    1 for cid in attack_ids
                    if a_map[cid] == JudgeVerdict.ATTACK_BLOCKED
                    and b_map[cid] == JudgeVerdict.ATTACK_SUCCEEDED
                )
                b_blocked_only = sum(
                    1 for cid in attack_ids
                    if b_map[cid] == JudgeVerdict.ATTACK_BLOCKED
                    and a_map[cid] == JudgeVerdict.ATTACK_SUCCEEDED
                )

                chi2, p_value = mcnemar_test(a_blocked_only, b_blocked_only)

                comparisons.append(ComparisonResult(
                    defense_a=a.defense_name,
                    defense_b=b.defense_name,
                    metric="attack_blocked",
                    n_cases=len(attack_ids),
                    a_only=a_blocked_only,
                    b_only=b_blocked_only,
                    chi2=chi2,
                    p_value=p_value,
                    significant=p_value < 0.05,
                ))

        return comparisons

    # ── Internal: Cost-Benefit ────────────────────────────────────────────

    @staticmethod
    def _compute_cost_benefit(er: ExperimentResult) -> CostBenefit:
        """Compute cost-benefit summary for a single defence."""
        m = er.metrics
        n = m.num_cases or 1
        avg_tokens = m.total_cost / n

        # security_score: 1 - ASR (higher = more secure)
        security_score = 1.0 - m.asr

        # utility_score: BSR * (1 - FPR) (higher = more useful)
        utility_score = m.bsr * (1.0 - m.fpr)

        return CostBenefit(
            defense_name=er.defense_name,
            asr=m.asr,
            bsr=m.bsr,
            fpr=m.fpr,
            avg_tokens_per_case=avg_tokens,
            security_score=security_score,
            utility_score=utility_score,
        )

    # ── Internal: Difficulty × Defence Cross-Analysis ──────────────────

    @staticmethod
    def _compute_difficulty_analysis(
        results: List[ExperimentResult],
        confidence: float,
    ) -> DifficultyAnalysis:
        """Compute ASR broken down by difficulty for each defence.

        Returns a :class:`DifficultyAnalysis` with one row per defence
        and one column per difficulty level.
        """
        # Collect all difficulty levels across all experiments
        all_difficulties: set[str] = set()
        for er in results:
            if not er.cases:
                continue
            for case in er.cases:
                diff = getattr(case, "difficulty", None)
                if diff is not None:
                    all_difficulties.add(str(diff))

        difficulty_levels = sorted(all_difficulties)
        analysis = DifficultyAnalysis(difficulty_levels=difficulty_levels)

        for er in results:
            if not er.cases:
                continue

            name = er.defense_name
            # Group attack cases by difficulty
            diff_groups: Dict[str, List[Tuple[BenchmarkCase, JudgeResult]]] = (
                defaultdict(list)
            )
            for case, result in zip(er.cases, er.results):
                if result.verdict not in (
                    JudgeVerdict.ATTACK_SUCCEEDED,
                    JudgeVerdict.ATTACK_BLOCKED,
                ):
                    continue
                diff = str(getattr(case, "difficulty", "unknown"))
                diff_groups[diff].append((case, result))

            cells: List[DifficultyCell] = []
            for level in difficulty_levels:
                items = diff_groups.get(level, [])
                n_attack = len(items)
                n_succeeded = sum(
                    1 for _, r in items
                    if r.verdict == JudgeVerdict.ATTACK_SUCCEEDED
                )
                asr, lower, upper = wilson_score_interval(
                    n_succeeded, n_attack, confidence
                )
                ci = ConfidenceInterval(
                    metric_name=f"ASR_{level}",
                    point=asr, lower=lower, upper=upper,
                    n=n_attack, confidence=confidence,
                )
                cells.append(DifficultyCell(
                    difficulty=level,
                    n_attack=n_attack,
                    n_succeeded=n_succeeded,
                    asr=asr,
                    ci=ci,
                ))
            analysis.rows[name] = cells

        return analysis
