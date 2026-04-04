#!/usr/bin/env python3
"""Cross-benchmark ASR/BSR correlation analysis.

Compares defense effectiveness across ASB native benchmark and external
benchmarks (InjecAgent, AgentDojo) to validate that findings generalise.

Usage:
    python experiments/compare_benchmarks.py \
        --asb-results results/full_eval/all_results.json \
        --external-results results/external/injecagent_results.json \
        --output results/comparison
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


def load_asb_results(path: str) -> Dict[str, Dict[str, float]]:
    """Load ASB results and extract per-defense metrics."""
    with open(path) as fh:
        raw = json.load(fh)

    per_defense: Dict[str, Dict[str, float]] = {}
    for key, data in raw.items():
        meta = data.get("_meta", {})
        defense_id = meta.get("defense_id", key.split("_")[1] if "_" in key else key)
        metrics = data.get("metrics", {})
        if defense_id not in per_defense:
            per_defense[defense_id] = {
                "asr": metrics.get("asr", 0),
                "bsr": metrics.get("bsr", 0),
            }
    return per_defense


def load_external_results(path: str) -> Dict[str, Dict[str, float]]:
    """Load external benchmark results."""
    with open(path) as fh:
        return json.load(fh)


def compute_correlation(
    asb: Dict[str, Dict[str, float]],
    external: Dict[str, Dict[str, float]],
    metric: str = "asr",
) -> float:
    """Compute Pearson correlation between ASB and external metric values."""
    common = sorted(set(asb) & set(external))
    if len(common) < 2:
        return float("nan")

    x = [asb[d].get(metric, 0) for d in common]
    y = [external[d].get(metric, 0) for d in common]

    n = len(x)
    mx = sum(x) / n
    my = sum(y) / n
    cov = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y)) / n
    sx = (sum((xi - mx) ** 2 for xi in x) / n) ** 0.5
    sy = (sum((yi - my) ** 2 for yi in y) / n) ** 0.5
    if sx == 0 or sy == 0:
        return float("nan")
    return cov / (sx * sy)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cross-benchmark correlation analysis."
    )
    parser.add_argument("--asb-results", type=str, required=True)
    parser.add_argument("--external-results", type=str, required=True)
    parser.add_argument(
        "--output", type=str, default=str(_PROJECT_ROOT / "results" / "comparison"),
    )
    args = parser.parse_args()
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    asb = load_asb_results(args.asb_results)
    ext = load_external_results(args.external_results)

    print("ASB Defenses:", sorted(asb))
    print("External Defenses:", sorted(ext))

    common = sorted(set(asb) & set(ext))
    print(f"Common defenses: {common}")

    if common:
        asr_corr = compute_correlation(asb, ext, "asr")
        bsr_corr = compute_correlation(asb, ext, "bsr")
        print(f"\nASR Pearson correlation: {asr_corr:.4f}")
        print(f"BSR Pearson correlation: {bsr_corr:.4f}")

        # Save comparison table.
        table = []
        for d in common:
            table.append({
                "defense": d,
                "asb_asr": asb[d].get("asr", 0),
                "ext_asr": ext[d].get("asr", 0),
                "asb_bsr": asb[d].get("bsr", 0),
                "ext_bsr": ext[d].get("bsr", 0),
            })

        report = {
            "common_defenses": common,
            "asr_correlation": asr_corr,
            "bsr_correlation": bsr_corr,
            "comparison_table": table,
        }
        report_path = output_dir / "benchmark_comparison.json"
        with open(report_path, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nReport saved to {report_path}")
    else:
        print("No common defenses found between benchmarks.")


if __name__ == "__main__":
    main()
