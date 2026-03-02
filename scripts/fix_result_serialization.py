#!/usr/bin/env python3
"""Fix legacy result files that used str() serialization instead of proper JSON.

Parses the Python repr strings in results/*.json and converts them to
structured JSON compatible with the analysis pipeline (run_full_evaluation.py format).
"""

import json
import re
import sys
from pathlib import Path


def find_matching_brace(text: str, start: int) -> int:
    """Find the index of the closing brace matching the opening brace at start."""
    depth = 0
    in_string = False
    string_char = None
    i = start
    while i < len(text):
        ch = text[i]
        if in_string:
            if ch == "\\" and i + 1 < len(text):
                i += 2  # skip escaped char
                continue
            if ch == string_char:
                in_string = False
        else:
            if ch in ("'", '"'):
                in_string = True
                string_char = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def extract_balanced(text: str, open_ch: str = "(", close_ch: str = ")") -> int:
    """Find closing paren/bracket matching the first open_ch, respecting strings."""
    depth = 0
    in_string = False
    string_char = None
    for i, ch in enumerate(text):
        if in_string:
            if ch == "\\" and i + 1 < len(text):
                continue
            if ch == string_char and (i == 0 or text[i - 1] != "\\"):
                in_string = False
        else:
            if ch in ("'", '"'):
                in_string = True
                string_char = ch
            elif ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    return i
    return -1


def parse_judge_result(text: str) -> dict:
    """Parse a single JudgeResult repr string into a dict."""
    import ast

    # Extract verdict
    verdict_m = re.search(r"verdict=<JudgeVerdict\.(\w+):\s*'(\w+)'>", text)
    verdict = verdict_m.group(2) if verdict_m else "unknown"

    # Extract case_id
    case_id_m = re.search(r"case_id='([^']*)'", text)
    case_id = case_id_m.group(1) if case_id_m else "unknown"

    # Extract reason: find "reason=" then parse the string value
    reason_idx = text.find("reason=")
    reason = ""
    if reason_idx >= 0:
        after = text[reason_idx + 7:]  # after "reason="
        if after.startswith("'"):
            # Find matching closing quote (not escaped)
            # Use: find ", details=" as terminator
            details_marker = ", details="
            dm_idx = after.find(details_marker)
            if dm_idx > 0:
                reason_raw = after[1:dm_idx]
                # Remove trailing quote
                if reason_raw.endswith("'"):
                    reason_raw = reason_raw[:-1]
                reason = reason_raw.replace("\\'", "'")
        elif after.startswith('"'):
            details_marker = ", details="
            dm_idx = after.find(details_marker)
            if dm_idx > 0:
                reason_raw = after[1:dm_idx]
                if reason_raw.endswith('"'):
                    reason_raw = reason_raw[:-1]
                reason = reason_raw.replace('\\"', '"')

    # Extract details dict using balanced brace matching
    details = {}
    details_idx = text.find(", details=")
    if details_idx >= 0:
        brace_start = text.find("{", details_idx)
        if brace_start >= 0:
            brace_end = find_matching_brace(text, brace_start)
            if brace_end > 0:
                details_str = text[brace_start : brace_end + 1]
                try:
                    details = ast.literal_eval(details_str)
                except (ValueError, SyntaxError):
                    details = {}

    return {
        "verdict": verdict,
        "case_id": case_id,
        "reason": reason,
        "details": details,
    }


def parse_metrics(text: str) -> dict:
    """Parse EvaluationMetrics repr string."""
    metrics = {}
    for field in ["asr", "bsr", "fpr", "total_cost", "num_cases", "attack_cases", "benign_cases"]:
        m = re.search(rf"{field}=([\d.]+)", text)
        if m:
            val = m.group(1)
            metrics[field] = float(val) if "." in val else int(val)

    # Extract details dict
    details_m = re.search(r"details=(\{'[^}]+\})", text)
    if details_m:
        try:
            import ast
            metrics["details"] = ast.literal_eval(details_m.group(1))
        except (ValueError, SyntaxError):
            metrics["details"] = {}
    else:
        metrics["details"] = {}

    return metrics


def parse_experiment_result(repr_str: str) -> dict:
    """Parse full ExperimentResult repr string into structured dict."""
    # Extract defense_name
    defense_name_m = re.search(r"defense_name='([^']*)'", repr_str)
    defense_name = defense_name_m.group(1) if defense_name_m else "unknown"

    # Extract timestamp
    timestamp_m = re.search(r"timestamp='([^']*)'", repr_str)
    timestamp = timestamp_m.group(1) if timestamp_m else ""

    # Extract metrics section
    metrics_m = re.search(r"metrics=EvaluationMetrics\((.*?)\),\s*timestamp=", repr_str, re.DOTALL)
    metrics = parse_metrics(metrics_m.group(1)) if metrics_m else {}

    # Extract individual JudgeResult entries using bracket-balanced splitting
    results = []
    # Cut off at "], trajectories=" to avoid parsing trajectory objects
    traj_idx = repr_str.find("], trajectories=")
    search_str = repr_str[:traj_idx] if traj_idx > 0 else repr_str

    # Split by "JudgeResult(" and use balanced paren matching
    parts = search_str.split("JudgeResult(")
    for part in parts[1:]:  # skip first part (before any JudgeResult)
        # Find matching closing paren using balanced approach
        end_idx = extract_balanced("(" + part, "(", ")")
        if end_idx > 0:
            judge_text = "JudgeResult(" + part[:end_idx]
        else:
            judge_text = "JudgeResult(" + part
        try:
            result = parse_judge_result(judge_text)
            if result["case_id"] != "unknown":
                results.append(result)
        except Exception as e:
            continue

    return {
        "defense_name": defense_name,
        "results": results,
        "metrics": metrics,
        "timestamp": timestamp,
    }


def convert_file(input_path: Path, output_path: Path, model: str = "gpt-4o", run: int = 1):
    """Convert a single legacy result file to proper JSON."""
    with open(input_path) as f:
        data = json.load(f)

    defense = data.get("defense", "unknown")
    repr_str = data.get("results", "")

    if not isinstance(repr_str, str):
        print(f"  {input_path.name}: already structured, skipping")
        return False

    parsed = parse_experiment_result(repr_str)

    # Output in the same flat format as run_full_evaluation.py
    output = {
        "defense_name": parsed["defense_name"],
        "results": parsed["results"],
        "metrics": parsed["metrics"],
        "timestamp": parsed["timestamp"],
        "_meta": {
            "model": model,
            "defense_id": defense,
            "run_id": run,
            "provider": "openai",
            "benchmark_dir": "data/mini_benchmark",
            "num_cases": len(parsed["results"]),
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    n_results = len(parsed["results"])
    asr = parsed["metrics"].get("asr", "?")
    bsr = parsed["metrics"].get("bsr", "?")
    print(f"  {input_path.name} -> {output_path.name}: {n_results} cases, ASR={asr}, BSR={bsr}")
    return True


def main():
    project_root = Path(__file__).parent.parent

    # Convert results/ (first run)
    results_dir = project_root / "results"
    output_dir = project_root / "results" / "gpt4o_structured"

    print("=== Converting results/ (run 1) ===")
    for f in sorted(results_dir.glob("results_D*.json")):
        out_name = f.name.replace("results_", "gpt-4o_").replace(".json", "_run1.json")
        convert_file(f, output_dir / out_name, model="gpt-4o", run=1)

    # Convert results/gpt4o/ (second run)
    gpt4o_dir = results_dir / "gpt4o"
    if gpt4o_dir.exists():
        print("\n=== Converting results/gpt4o/ (run 2) ===")
        for f in sorted(gpt4o_dir.glob("results_D*.json")):
            out_name = f.name.replace("results_", "gpt-4o_").replace(".json", "_run2.json")
            convert_file(f, output_dir / out_name, model="gpt-4o", run=2)

    # Create all_results.json combining both runs
    all_results = []
    for f in sorted(output_dir.glob("*.json")):
        if f.name == "all_results.json":
            continue
        with open(f) as fh:
            all_results.append(json.load(fh))

    all_path = output_dir / "all_results.json"
    with open(all_path, "w") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    print(f"\n=== Combined {len(all_results)} result files -> {all_path} ===")

    # Print summary table
    print("\nModel          Defense  Run     ASR     BSR     FPR   Tokens")
    print("-" * 65)
    for r in all_results:
        meta = r.get("_meta", {})
        m = r.get("metrics", {})
        print(
            f"{meta.get('model', '?'):<15s}{meta.get('defense_id', '?'):<9s}{meta.get('run_id', 0):>3d}"
            f"  {m.get('asr', 0):>6.1%}  {m.get('bsr', 0):>6.1%}"
            f"  {m.get('fpr', 0):>6.1%}  {m.get('total_cost', 0):>6d}"
        )


if __name__ == "__main__":
    main()
