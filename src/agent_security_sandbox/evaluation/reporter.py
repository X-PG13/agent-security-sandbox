"""
Report generation for experiment results.

The :class:`Reporter` can produce Markdown, JSON, and CSV reports that
compare multiple defence strategies side-by-side.
"""

import csv
import io
import json
from pathlib import Path
from typing import Any, Dict, List

from .runner import ExperimentResult


class Reporter:
    """Generate comparison reports from one or more :class:`ExperimentResult` instances."""

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------

    def generate_markdown(self, results: List[ExperimentResult]) -> str:
        """Generate a Markdown comparison table.

        The table has one row per defence strategy and columns for ASR,
        BSR, FPR, total token cost, and case counts.

        Args:
            results: Experiment results to include (one per defence).

        Returns:
            A string containing the full Markdown report.
        """
        lines: List[str] = []
        lines.append("# Evaluation Report")
        lines.append("")

        if not results:
            lines.append("No experiment results to report.")
            return "\n".join(lines)

        # Summary section
        lines.append("## Summary")
        lines.append("")
        lines.append(
            "| Defense | ASR | BSR | FPR | Tokens | "
            "Attack Cases | Benign Cases | Total |"
        )
        lines.append(
            "|---------|-----|-----|-----|--------|"
            "--------------|--------------|-------|"
        )

        for result in results:
            m = result.metrics
            lines.append(
                f"| {result.defense_name} "
                f"| {m.asr:.2%} "
                f"| {m.bsr:.2%} "
                f"| {m.fpr:.2%} "
                f"| {m.total_cost:,} "
                f"| {m.attack_cases} "
                f"| {m.benign_cases} "
                f"| {m.num_cases} |"
            )

        lines.append("")

        # Per-defence detail sections
        for result in results:
            lines.append(f"## {result.defense_name}")
            lines.append("")
            lines.append(f"- **Timestamp:** {result.timestamp}")
            lines.append(f"- **ASR:** {result.metrics.asr:.2%}")
            lines.append(f"- **BSR:** {result.metrics.bsr:.2%}")
            lines.append(f"- **FPR:** {result.metrics.fpr:.2%}")
            lines.append(f"- **Total tokens:** {result.metrics.total_cost:,}")
            lines.append("")

            if result.results:
                lines.append("### Per-case verdicts")
                lines.append("")
                lines.append("| Case ID | Verdict | Reason |")
                lines.append("|---------|---------|--------|")
                for jr in result.results:
                    # Escape pipes in reason text
                    safe_reason = jr.reason.replace("|", "\\|")
                    lines.append(
                        f"| {jr.case_id} | {jr.verdict.value} | {safe_reason} |"
                    )
                lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def generate_json(self, results: List[ExperimentResult]) -> str:
        """Generate a JSON report.

        Args:
            results: Experiment results to serialize.

        Returns:
            A pretty-printed JSON string.
        """
        payload: List[Dict[str, Any]] = []

        for result in results:
            entry: Dict[str, Any] = {
                "defense_name": result.defense_name,
                "timestamp": result.timestamp,
                "metrics": {
                    "asr": result.metrics.asr,
                    "bsr": result.metrics.bsr,
                    "fpr": result.metrics.fpr,
                    "total_cost": result.metrics.total_cost,
                    "num_cases": result.metrics.num_cases,
                    "attack_cases": result.metrics.attack_cases,
                    "benign_cases": result.metrics.benign_cases,
                    "details": result.metrics.details,
                },
                "results": [
                    {
                        "case_id": jr.case_id,
                        "verdict": jr.verdict.value,
                        "reason": jr.reason,
                        "details": jr.details,
                    }
                    for jr in result.results
                ],
            }
            payload.append(entry)

        return json.dumps(payload, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------

    def generate_csv(self, results: List[ExperimentResult]) -> str:
        """Generate a CSV report with one row per (defence, case) pair.

        Columns: defense_name, case_id, verdict, reason, asr, bsr, fpr,
        total_cost.

        Args:
            results: Experiment results to include.

        Returns:
            A CSV-formatted string (including header row).
        """
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "defense_name",
            "case_id",
            "verdict",
            "reason",
            "asr",
            "bsr",
            "fpr",
            "total_cost",
        ])

        for result in results:
            m = result.metrics
            for jr in result.results:
                writer.writerow([
                    result.defense_name,
                    jr.case_id,
                    jr.verdict.value,
                    jr.reason,
                    f"{m.asr:.4f}",
                    f"{m.bsr:.4f}",
                    f"{m.fpr:.4f}",
                    m.total_cost,
                ])

        return output.getvalue()

    # ------------------------------------------------------------------
    # Analysis Markdown
    # ------------------------------------------------------------------

    def generate_analysis_markdown(self, report: Any) -> str:
        """Generate a Markdown report from a :class:`AnalysisReport`.

        Includes sections for confidence intervals, category breakdowns,
        pairwise comparisons, and cost-benefit analysis.

        Args:
            report: An :class:`AnalysisReport` from :class:`StatisticalAnalyzer`.

        Returns:
            A Markdown string with the full analysis.
        """
        lines: List[str] = []
        lines.append("# Statistical Analysis Report")
        lines.append("")

        # -- Confidence Intervals ------------------------------------------
        lines.append("## Confidence Intervals (95%)")
        lines.append("")
        lines.append("| Defense | Metric | Point | Lower | Upper | N |")
        lines.append("|---------|--------|-------|-------|-------|---|")

        for defense_name, cis in report.confidence_intervals.items():
            for ci in cis:
                lines.append(
                    f"| {defense_name} "
                    f"| {ci.metric_name} "
                    f"| {ci.point:.3f} "
                    f"| {ci.lower:.3f} "
                    f"| {ci.upper:.3f} "
                    f"| {ci.n} |"
                )
        lines.append("")

        # -- Category Breakdowns -------------------------------------------
        lines.append("## Category Breakdowns")
        lines.append("")

        for defense_name, breakdowns in report.category_breakdowns.items():
            if not breakdowns:
                continue
            lines.append(f"### {defense_name}")
            lines.append("")

            for bd in breakdowns:
                lines.append(f"#### By {bd.dimension}")
                lines.append("")
                lines.append(
                    "| Value | Total | Successes | Rate | CI Lower | CI Upper |"
                )
                lines.append(
                    "|-------|-------|-----------|------|----------|----------|"
                )
                for s in bd.slices:
                    lines.append(
                        f"| {s.category_value} "
                        f"| {s.total} "
                        f"| {s.successes} "
                        f"| {s.rate:.3f} "
                        f"| {s.ci.lower:.3f} "
                        f"| {s.ci.upper:.3f} |"
                    )
                lines.append("")

        # -- Pairwise Comparisons ------------------------------------------
        if report.comparisons:
            lines.append("## Pairwise Comparisons (McNemar's Test)")
            lines.append("")
            lines.append(
                "| Defense A | Defense B | Metric | N | A-only | B-only "
                "| Chi2 | p-value | Significant |"
            )
            lines.append(
                "|-----------|-----------|--------|---|--------|--------"
                "|------|---------|-------------|"
            )

            for c in report.comparisons:
                sig = "Yes" if c.significant else "No"
                lines.append(
                    f"| {c.defense_a} "
                    f"| {c.defense_b} "
                    f"| {c.metric} "
                    f"| {c.n_cases} "
                    f"| {c.a_only} "
                    f"| {c.b_only} "
                    f"| {c.chi2:.3f} "
                    f"| {c.p_value:.4f} "
                    f"| {sig} |"
                )
            lines.append("")

        # -- Cost-Benefit Analysis -----------------------------------------
        if report.cost_benefits:
            lines.append("## Cost-Benefit Analysis")
            lines.append("")
            lines.append(
                "| Defense | ASR | BSR | FPR | Avg Tokens | "
                "Security Score | Utility Score |"
            )
            lines.append(
                "|---------|-----|-----|-----|------------|"
                "----------------|---------------|"
            )

            for cb in report.cost_benefits:
                lines.append(
                    f"| {cb.defense_name} "
                    f"| {cb.asr:.3f} "
                    f"| {cb.bsr:.3f} "
                    f"| {cb.fpr:.3f} "
                    f"| {cb.avg_tokens_per_case:.0f} "
                    f"| {cb.security_score:.3f} "
                    f"| {cb.utility_score:.3f} |"
                )
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Save helper
    # ------------------------------------------------------------------

    @staticmethod
    def save_report(content: str, filepath: str) -> None:
        """Write report content to a file, creating parent directories as needed.

        Args:
            content: The report content (Markdown, JSON, CSV, etc.).
            filepath: Destination file path.
        """
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
