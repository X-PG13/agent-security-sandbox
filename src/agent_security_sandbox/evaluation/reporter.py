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
