"""
Experiment runner for executing benchmark suites against defence strategies.

The :class:`ExperimentRunner` wires together the agent, tools, defence, and
judge to run each :class:`BenchmarkCase`, collect trajectories, and compute
aggregate metrics.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional, Tuple

from ..core.agent import AgentTrajectory, ReactAgent
from ..core.llm_client import LLMClient
from ..defenses.base import DefenseStrategy
from ..tools.registry import ToolRegistry
from .benchmark import BenchmarkCase, BenchmarkSuite
from .judge import AutoJudge, JudgeResult
from .metrics import EvaluationMetrics, MetricsCalculator


@dataclass
class ExperimentResult:
    """Aggregated result of running a full benchmark suite.

    Attributes:
        defense_name: Human-readable name of the defence strategy (or
            ``"no_defense"`` for the baseline).
        results: Per-case :class:`JudgeResult` list.
        trajectories: Per-case :class:`AgentTrajectory` list (same order as
            *results*).
        metrics: Aggregated :class:`EvaluationMetrics`.
        timestamp: ISO-formatted timestamp of when the experiment finished.
        cases: Per-case :class:`BenchmarkCase` list (same order as *results*).
        token_details: Optional breakdown of prompt vs completion tokens.
    """

    defense_name: str
    results: List[JudgeResult] = field(default_factory=list)
    trajectories: List[AgentTrajectory] = field(default_factory=list)
    metrics: EvaluationMetrics = field(default_factory=EvaluationMetrics)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    cases: List[BenchmarkCase] = field(default_factory=list)
    token_details: dict = field(default_factory=dict)


class ExperimentRunner:
    """Run benchmark cases through an agent with an optional defence.

    Args:
        llm_client: The LLM client used by the agent.
        tool_registry_factory: A **callable** that returns a fresh
            :class:`ToolRegistry` each time it is invoked.  This ensures
            tool state is reset between benchmark cases.
        defense_strategy: Optional defence strategy.  When ``None``, the
            agent runs undefended.
        max_steps: Maximum number of ReAct steps per case.
        verbose: Whether the underlying agent should print step-by-step output.
    """

    def __init__(
        self,
        llm_client: LLMClient,
        tool_registry_factory: Callable[[], ToolRegistry],
        defense_strategy: Optional[DefenseStrategy] = None,
        max_steps: int = 10,
        verbose: bool = False,
        judge: Optional[object] = None,
    ) -> None:
        self.llm_client = llm_client
        self.tool_registry_factory = tool_registry_factory
        self.defense_strategy = defense_strategy
        self.max_steps = max_steps
        self.verbose = verbose
        self._judge = judge if judge is not None else AutoJudge()
        self._metrics_calc = MetricsCalculator()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_case(
        self, case: BenchmarkCase
    ) -> Tuple[AgentTrajectory, JudgeResult]:
        """Run a single benchmark case.

        A fresh :class:`ToolRegistry` is created via the factory so that
        tool state does not leak between cases.

        Args:
            case: The benchmark case to evaluate.

        Returns:
            A tuple ``(trajectory, judge_result)``.
        """
        # Reset LLM client session state (e.g. call counters) between cases
        if hasattr(self.llm_client, "reset_session"):
            self.llm_client.reset_session()

        # Build a fresh tool registry for isolation
        tool_registry = self.tool_registry_factory()

        # Create the agent
        agent = ReactAgent(
            llm_client=self.llm_client,
            tool_registry=tool_registry,
            max_steps=self.max_steps,
            verbose=self.verbose,
        )

        # Execute
        trajectory = agent.run(
            goal=case.goal,
            untrusted_content=case.untrusted_content,
            defense_strategy=self.defense_strategy,
        )

        # Judge
        result = self._judge.judge(case, trajectory)
        return trajectory, result

    def run_suite(
        self,
        suite: BenchmarkSuite,
        progress_callback: Optional[Callable[[int, int, BenchmarkCase], None]] = None,
    ) -> ExperimentResult:
        """Run all cases in a benchmark suite.

        Args:
            suite: The suite of benchmark cases.
            progress_callback: Optional callback invoked before each case
                with ``(current_index, total_cases, case)``.  Useful for
                progress bars or logging.

        Returns:
            An :class:`ExperimentResult` containing all trajectories,
            judge results, and aggregated metrics.
        """
        all_results: List[JudgeResult] = []
        all_trajectories: List[AgentTrajectory] = []
        total_tokens = 0
        cases = suite.cases
        total = len(cases)

        # Capture LLM stats before the suite to compute deltas
        pre_stats = self.llm_client.get_stats()

        for idx, case in enumerate(cases):
            if progress_callback is not None:
                progress_callback(idx, total, case)

            trajectory, result = self.run_case(case)
            all_results.append(result)
            all_trajectories.append(trajectory)
            total_tokens += trajectory.total_tokens

        # Compute aggregate metrics
        metrics = self._metrics_calc.calculate(all_results, total_tokens=total_tokens)

        # Collect prompt/completion token breakdown
        post_stats = self.llm_client.get_stats()
        token_details = {
            "total_tokens": total_tokens,
            "prompt_tokens": post_stats.get("prompt_tokens", 0) - pre_stats.get("prompt_tokens", 0),
            "completion_tokens": post_stats.get("completion_tokens", 0) - pre_stats.get("completion_tokens", 0),
            "total_calls": post_stats.get("total_calls", 0) - pre_stats.get("total_calls", 0),
        }

        # Determine defence name
        if self.defense_strategy is not None:
            defense_name = type(self.defense_strategy).__name__
        else:
            defense_name = "no_defense"

        return ExperimentResult(
            defense_name=defense_name,
            results=all_results,
            trajectories=all_trajectories,
            metrics=metrics,
            timestamp=datetime.now().isoformat(),
            cases=cases,
            token_details=token_details,
        )
