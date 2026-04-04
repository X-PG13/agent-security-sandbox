#!/usr/bin/env python3
"""Interpretability analysis of defense behaviour.

Generates heatmaps, defense decision breakdowns, and logprob analysis
from evaluation results.

Usage:
    python experiments/interpretability_analysis.py \
        --results-dir results/full_eval \
        --benchmark-dir data/mini_benchmark \
        --output-dir figures/interpretability
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite  # noqa: E402
from agent_security_sandbox.evaluation.interpretability import (  # noqa: E402
    DefenseVisualization,
    InjectionHeatmapAnalyzer,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Interpretability analysis of defense decisions.",
    )
    parser.add_argument(
        "--results-dir",
        type=str,
        default=str(_PROJECT_ROOT / "results" / "full_eval"),
    )
    parser.add_argument(
        "--benchmark-dir",
        type=str,
        default=str(_PROJECT_ROOT / "data" / "mini_benchmark"),
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(_PROJECT_ROOT / "figures" / "interpretability"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load benchmark cases for heatmap analysis.
    suite = BenchmarkSuite.load_from_directory(args.benchmark_dir)
    print(f"Loaded {len(suite)} benchmark cases")

    # 1. Injection heatmap analysis
    print("\n--- Injection Heatmap Analysis ---")
    heatmap = InjectionHeatmapAnalyzer()
    heatmap_results = []

    for case in suite.attack_cases[:10]:
        if not case.untrusted_content:
            continue
        scores = heatmap.analyze(
            goal=case.goal,
            untrusted_content=case.untrusted_content,
        )
        html = heatmap.to_html(scores)
        heatmap_results.append({
            "case_id": case.id,
            "html": html,
            "top_tokens": [
                {"token": s.token, "score": s.score}
                for s in sorted(scores, key=lambda x: x.score, reverse=True)[:5]
            ],
        })
        print(f"  {case.id}: top token = "
              f"{scores[0].token if scores else 'N/A'} "
              f"(score={scores[0].score:.2f})" if scores else "")

    # Save heatmap HTML
    html_path = output_dir / "injection_heatmaps.html"
    with open(html_path, "w") as fh:
        fh.write("<html><body>\n")
        fh.write("<h1>Injection Heatmap Analysis</h1>\n")
        for item in heatmap_results:
            fh.write(f"<h3>{item['case_id']}</h3>\n")
            fh.write(f"<p>{item['html']}</p>\n")
        fh.write("</body></html>\n")
    print(f"  Heatmaps saved to {html_path}")

    # 2. Defense decision analysis (if results available)
    results_dir = Path(args.results_dir)
    if results_dir.exists():
        print("\n--- Defense Decision Analysis ---")
        viz = DefenseVisualization()

        result_files = list(results_dir.glob("*.json"))
        results_data = []
        for rf in result_files:
            if rf.name == "experiment_config.json":
                continue
            try:
                with open(rf) as fh:
                    data = json.load(fh)
                if isinstance(data, dict) and "_meta" in data:
                    results_data.append(data)
            except (json.JSONDecodeError, Exception):
                continue

        if results_data:
            stats = viz.aggregate(results_data)
            summary = viz.generate_summary(stats)
            summary_path = output_dir / "defense_decisions.md"
            with open(summary_path, "w") as fh:
                fh.write(summary)
            print(f"  Decision summary saved to {summary_path}")
        else:
            print("  No valid result files found.")
    else:
        print(f"  Results directory not found: {results_dir}")

    # 3. Save combined analysis report
    report = {
        "num_cases_analyzed": len(heatmap_results),
        "heatmap_results": [
            {k: v for k, v in item.items() if k != "html"}
            for item in heatmap_results
        ],
    }
    report_path = output_dir / "interpretability_report.json"
    with open(report_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\nFull report saved to {report_path}")


if __name__ == "__main__":
    main()
