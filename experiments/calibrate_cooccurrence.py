#!/usr/bin/env python3
"""Calibrate tool co-occurrence matrix from benign benchmark cases.

Scans all benign cases in the benchmark and computes empirical tool
co-occurrence frequencies:

    P(tool_j in same task | tool_i in same task)

The output can be used to update ``_TOOL_COOCCURRENCE`` in ``d10_civ.py``.

Usage:
    python experiments/calibrate_cooccurrence.py \
        --benchmark-dir data/full_benchmark \
        --output results/cooccurrence_matrix.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
for _p in (_PROJECT_ROOT, _PROJECT_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Calibrate tool co-occurrence matrix from benign benchmark cases.",
    )
    parser.add_argument(
        "--benchmark-dir", type=str,
        default=str(_PROJECT_ROOT / "data" / "full_benchmark"),
        help="Path to the benchmark directory.",
    )
    parser.add_argument(
        "--output", type=str,
        default=str(_PROJECT_ROOT / "results" / "cooccurrence_matrix.json"),
        help="Output path for the JSON co-occurrence matrix.",
    )
    parser.add_argument(
        "--min-freq", type=float, default=0.05,
        help="Minimum co-occurrence frequency to include (default: 0.05).",
    )
    return parser.parse_args()


def extract_expected_tools(case: Any) -> Set[str]:
    """Extract the set of expected tools from a benchmark case."""
    tools: Set[str] = set()
    # Try various attribute names used in the benchmark
    for attr in ("expected_tools", "tools", "expected_actions"):
        val = getattr(case, attr, None)
        if val:
            if isinstance(val, (list, tuple)):
                for item in val:
                    if isinstance(item, str):
                        tools.add(item)
                    elif isinstance(item, dict):
                        name = item.get("tool") or item.get("name") or item.get("action")
                        if name:
                            tools.add(str(name))
            break
    return tools


def compute_cooccurrence(
    tool_sets: List[Set[str]], min_freq: float = 0.05,
) -> Dict[str, Dict[str, float]]:
    """Compute P(tool_j | tool_i) from a list of tool sets."""
    # Count occurrences
    tool_count: Dict[str, int] = defaultdict(int)
    pair_count: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for tools in tool_sets:
        for t in tools:
            tool_count[t] += 1
            for other in tools:
                if other != t:
                    pair_count[t][other] += 1

    # Compute conditional probabilities
    matrix: Dict[str, Dict[str, float]] = {}
    for tool_i, count_i in sorted(tool_count.items()):
        if count_i < 2:
            continue
        row: Dict[str, float] = {}
        for tool_j, count_ij in sorted(pair_count[tool_i].items()):
            freq = count_ij / count_i
            if freq >= min_freq:
                row[tool_j] = round(freq, 3)
        if row:
            matrix[tool_i] = row

    return matrix


def main() -> None:
    args = parse_args()
    benchmark_dir = args.benchmark_dir

    print(f"Loading benchmark from {benchmark_dir}")
    suite = BenchmarkSuite.load_from_directory(benchmark_dir)
    benign_cases = suite.benign_cases
    print(f"Found {len(benign_cases)} benign cases")

    # Extract expected tool sets
    tool_sets: List[Set[str]] = []
    empty_count = 0
    for case in benign_cases:
        tools = extract_expected_tools(case)
        if tools:
            tool_sets.append(tools)
        else:
            empty_count += 1

    print(f"Cases with expected_tools: {len(tool_sets)}")
    if empty_count:
        print(f"Cases without expected_tools (skipped): {empty_count}")

    if not tool_sets:
        print("ERROR: No tool sets found. Check benchmark format.")
        sys.exit(1)

    # Compute co-occurrence
    matrix = compute_cooccurrence(tool_sets, min_freq=args.min_freq)

    # Print matrix
    print(f"\nCo-occurrence matrix (min_freq={args.min_freq}):")
    print("-" * 60)
    for tool_i, row in matrix.items():
        print(f"  {tool_i}:")
        for tool_j, freq in row.items():
            print(f"    {tool_j}: {freq:.3f}")

    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(matrix, f, indent=2, ensure_ascii=False)
    print(f"\nMatrix saved to {output_path}")

    # Print summary stats
    all_tools = set()
    for ts in tool_sets:
        all_tools.update(ts)
    print(f"\nSummary:")
    print(f"  Unique tools: {len(all_tools)}")
    print(f"  Tools: {sorted(all_tools)}")
    print(f"  Pairs in matrix: {sum(len(row) for row in matrix.values())}")


if __name__ == "__main__":
    main()
