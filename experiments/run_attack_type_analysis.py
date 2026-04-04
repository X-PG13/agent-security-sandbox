#!/usr/bin/env python3
"""Per-attack-type analysis of defense effectiveness.

Cross-references evaluation results with benchmark metadata to compute
ASR per (defense, attack_type) pair with Wilson score confidence intervals.

Outputs:
  - attack_type_matrix.json: ASR matrix (defense × attack_type)
  - attack_type_table.tex:   LaTeX table for the paper
  - attack_type_summary.json: Summary with CIs

Usage:
    python experiments/run_attack_type_analysis.py \
        --results-dir results/full_eval \
        --benchmark-dir data/full_benchmark \
        --output-dir results/attack_type_analysis
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite  # noqa: E402


def wilson_score_interval(
    successes: int, total: int, z: float = 1.96,
) -> Tuple[float, float]:
    """Compute Wilson score 95% confidence interval for a proportion."""
    if total == 0:
        return (0.0, 0.0)
    p_hat = successes / total
    denom = 1 + z**2 / total
    centre = (p_hat + z**2 / (2 * total)) / denom
    spread = z * math.sqrt((p_hat * (1 - p_hat) + z**2 / (4 * total)) / total) / denom
    return (max(0.0, centre - spread), min(1.0, centre + spread))


def load_benchmark_metadata(benchmark_dir: str) -> Dict[str, Dict[str, Any]]:
    """Load benchmark cases and build a case_id -> metadata mapping."""
    suite = BenchmarkSuite.load_from_directory(benchmark_dir)
    metadata = {}
    for case in suite.cases:
        metadata[case.id] = {
            "type": case.type,
            "attack_type": getattr(case, "attack_type", None),
            "difficulty": getattr(case, "difficulty", None),
            "injection_location": getattr(case, "injection_location", None),
            "injection_technique": getattr(case, "injection_technique", None),
            "threat_level": getattr(case, "threat_level", None),
        }
    return metadata


def load_results(results_dir: str) -> Dict[str, Any]:
    """Load all result JSON files from the results directory."""
    results_path = Path(results_dir)
    all_results = {}

    # Try combined file first
    combined = results_path / "all_results.json"
    if combined.exists():
        with open(combined) as f:
            return json.load(f)

    # Fall back to individual files
    for json_file in sorted(results_path.glob("*.json")):
        if json_file.name in ("experiment_config.json", "all_results.json"):
            continue
        with open(json_file) as f:
            data = json.load(f)
            all_results[json_file.stem] = data

    return all_results


def compute_attack_type_matrix(
    all_results: Dict[str, Any],
    case_metadata: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Compute ASR per (defense, attack_type) with Wilson CIs.

    Returns:
        Nested dict: defense -> attack_type -> {asr, ci_lo, ci_hi, succeeded, total}
    """
    # Collect per-case verdicts grouped by (defense, attack_type)
    counts: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: {"succeeded": 0, "total": 0})
    )

    for run_key, run_data in all_results.items():
        meta = run_data.get("_meta", {})
        defense_id = meta.get("defense_id", "unknown")

        case_results = run_data.get("results", [])
        if isinstance(case_results, dict):
            case_results = list(case_results.values())

        for case_result in case_results:
            case_id = case_result.get("case_id", case_result.get("id", ""))
            verdict = case_result.get("verdict", "")

            # Only count attack cases
            case_meta = case_metadata.get(case_id, {})
            if case_meta.get("type") != "attack":
                continue

            attack_type = case_meta.get("attack_type", "unknown")
            if attack_type is None:
                attack_type = "unknown"

            counts[defense_id][attack_type]["total"] += 1
            if verdict in ("attack_succeeded", "ATTACK_SUCCEEDED"):
                counts[defense_id][attack_type]["succeeded"] += 1

    # Compute ASR and CIs
    matrix: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for defense_id, attack_types in counts.items():
        matrix[defense_id] = {}
        for attack_type, c in attack_types.items():
            succ = c["succeeded"]
            total = c["total"]
            asr = succ / total if total > 0 else 0.0
            ci_lo, ci_hi = wilson_score_interval(succ, total)
            matrix[defense_id][attack_type] = {
                "asr": round(asr, 4),
                "ci_lo": round(ci_lo, 4),
                "ci_hi": round(ci_hi, 4),
                "succeeded": succ,
                "total": total,
            }

    return matrix


def generate_latex_table(
    matrix: Dict[str, Dict[str, Dict[str, Any]]],
    output_path: Path,
) -> None:
    """Generate a LaTeX table of defense × attack_type ASR."""
    # Collect all attack types
    all_attack_types = sorted({
        at for defense_data in matrix.values() for at in defense_data.keys()
    })

    # Sort defenses
    defense_order = ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"]
    defenses = [d for d in defense_order if d in matrix]

    # Abbreviate attack types for column headers
    type_abbrevs = {
        "data_exfiltration": "Exfil",
        "task_hijacking": "Hijack",
        "privilege_escalation": "Escal",
        "social_engineering": "Social",
        "adaptive": "Adapt",
        "denial_of_service": "DoS",
        "multistep": "Multi",
        "evasion": "Evasion",
        "unknown": "Other",
    }

    ncols = len(all_attack_types)
    col_spec = "l" + "r" * ncols

    lines = [
        "\\begin{table*}[t]",
        "\\centering",
        "\\small",
        "\\caption{ASR by defense and attack type (averaged across models and runs). "
        "Lower is better. Best per column in \\textbf{bold}.}",
        "\\label{tab:attack_type}",
        f"\\begin{{tabular}}{{{col_spec}}}",
        "\\toprule",
    ]

    # Header row
    header = "Defense"
    for at in all_attack_types:
        header += f" & {type_abbrevs.get(at, at[:6])}"
    header += " \\\\"
    lines.append(header)
    lines.append("\\midrule")

    # Find best (lowest) ASR per attack type
    best_per_type: Dict[str, float] = {}
    for at in all_attack_types:
        vals = []
        for d in defenses:
            if d == "D0":
                continue
            entry = matrix.get(d, {}).get(at, {})
            if entry.get("total", 0) > 0:
                vals.append(entry["asr"])
        best_per_type[at] = min(vals) if vals else 1.0

    # Data rows
    for defense in defenses:
        row = defense
        for at in all_attack_types:
            entry = matrix.get(defense, {}).get(at, {})
            if entry.get("total", 0) > 0:
                asr = entry["asr"]
                val_str = f"{asr:.2f}"
                if defense != "D0" and abs(asr - best_per_type[at]) < 0.005:
                    val_str = f"\\textbf{{{val_str}}}"
                row += f" & {val_str}"
            else:
                row += " & ---"
        row += " \\\\"
        lines.append(row)

    lines.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table*}",
    ])

    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  LaTeX table saved to {output_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Per-attack-type defense analysis.")
    parser.add_argument(
        "--results-dir",
        default=str(_PROJECT_ROOT / "results" / "full_eval"),
    )
    parser.add_argument(
        "--benchmark-dir",
        default=str(_PROJECT_ROOT / "data" / "full_benchmark"),
    )
    parser.add_argument(
        "--output-dir",
        default=str(_PROJECT_ROOT / "results" / "attack_type_analysis"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Loading benchmark metadata...")
    case_metadata = load_benchmark_metadata(args.benchmark_dir)
    print(f"  {len(case_metadata)} cases loaded")

    # Show attack type distribution
    attack_types = defaultdict(int)
    for meta in case_metadata.values():
        if meta["type"] == "attack":
            at = meta.get("attack_type", "unknown")
            attack_types[at or "unknown"] += 1
    print("  Attack type distribution:")
    for at, count in sorted(attack_types.items()):
        print(f"    {at}: {count}")

    print("\nLoading results...")
    all_results = load_results(args.results_dir)
    print(f"  {len(all_results)} result entries loaded")

    print("\nComputing attack-type matrix...")
    matrix = compute_attack_type_matrix(all_results, case_metadata)

    # Save matrix
    matrix_path = output_dir / "attack_type_matrix.json"
    with open(matrix_path, "w") as f:
        json.dump(matrix, f, indent=2)
    print(f"  Matrix saved to {matrix_path}")

    # Generate LaTeX table
    latex_path = output_dir / "attack_type_table.tex"
    generate_latex_table(matrix, latex_path)

    # Print summary
    print("\n" + "=" * 80)
    print("ATTACK TYPE ANALYSIS SUMMARY")
    print("=" * 80)

    all_at = sorted({at for dd in matrix.values() for at in dd.keys()})
    defense_order = ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"]
    defenses = [d for d in defense_order if d in matrix]

    # Print header
    header = f"{'Defense':<10}"
    for at in all_at:
        header += f" {at[:8]:>8}"
    print(header)
    print("-" * (10 + 9 * len(all_at)))

    for defense in defenses:
        row = f"{defense:<10}"
        for at in all_at:
            entry = matrix.get(defense, {}).get(at, {})
            if entry.get("total", 0) > 0:
                row += f" {entry['asr']:>8.3f}"
            else:
                row += f" {'---':>8}"
        print(row)

    # Save summary with CI
    summary = {
        "matrix": matrix,
        "attack_types": dict(attack_types),
        "defenses": defenses,
        "benchmark_dir": args.benchmark_dir,
        "results_dir": args.results_dir,
    }
    summary_path = output_dir / "attack_type_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSummary saved to {summary_path}")


if __name__ == "__main__":
    main()
