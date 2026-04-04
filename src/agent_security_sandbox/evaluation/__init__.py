"""Evaluation framework for benchmark testing."""

from .analysis import AnalysisReport, StatisticalAnalyzer
from .benchmark import BenchmarkCase, BenchmarkSuite
from .composite_judge import CompositeJudge
from .human_eval import HumanAnnotation, HumanEvalSession, InterAnnotatorAgreement
from .interpretability import (
    AttentionAnalyzer,
    DefenseVisualization,
    InjectionHeatmapAnalyzer,
)
from .judge import AutoJudge, JudgeResult, JudgeVerdict
from .llm_judge import LLMJudge
from .metrics import EvaluationMetrics, MetricsCalculator
from .reporter import Reporter
from .runner import ExperimentResult, ExperimentRunner

__all__ = [
    "AnalysisReport",
    "AttentionAnalyzer",
    "BenchmarkCase",
    "BenchmarkSuite",
    "AutoJudge",
    "CompositeJudge",
    "DefenseVisualization",
    "HumanAnnotation",
    "HumanEvalSession",
    "InjectionHeatmapAnalyzer",
    "InterAnnotatorAgreement",
    "JudgeVerdict",
    "JudgeResult",
    "LLMJudge",
    "MetricsCalculator",
    "EvaluationMetrics",
    "ExperimentRunner",
    "ExperimentResult",
    "Reporter",
    "StatisticalAnalyzer",
]
