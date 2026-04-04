#!/usr/bin/env python3
"""Unify experiment results across different benchmark sizes.

Problem: D0-D7 were evaluated on 250 cases, D8-D10 on 565 cases.
Solution: Filter D8-D10 results to the 250-case subset for fair comparison.
Also produce 565-case extended results for D8-D10.

Outputs:
  - paper/tables/main_results_unified.tex  (all defenses on 250 cases)
  - paper/tables/extended_results_565.tex   (D8-D10 on full 565 cases)
  - results/stats/unified_metrics.json      (machine-readable)
"""

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"
FULL_EVAL = RESULTS_DIR / "full_eval"
FULL_EVAL_V2 = RESULTS_DIR / "full_eval_v2"
TABLES_DIR = PROJECT_ROOT / "paper" / "tables"
STATS_DIR = RESULTS_DIR / "stats"

# 4 main models (exclude gpt-4o-mini which only has 1 run for D0-D7)
MAIN_MODELS = [
    "gpt-4o",
    "claude-sonnet-4-5-20250929",
    "deepseek-v3-1-250821",
    "gemini-2.5-flash",
]

DEFENSES = [f"D{i}" for i in range(11)]

DEFENSE_NAMES = {
    "D0": "Baseline (No Defense)",
    "D1": "Spotlighting",
    "D2": "Policy Gate",
    "D3": "Task Alignment Check",
    "D4": "Re-execution Consistency",
    "D5": "Sandwich Defense",
    "D6": "Output Filter",
    "D7": "Input Classifier",
    "D8": "Semantic Firewall",
    "D9": "Dual-LLM Verification",
    "D10": "CIV (Multi-signal)",
}

DEFENSE_CATEGORIES = {
    "D0": "No defense",
    "D1": "Prompt-level",
    "D2": "Prompt-level",
    "D3": "Prompt-level",
    "D4": "Verification",
    "D5": "Prompt-level",
    "D6": "Output filtering",
    "D7": "Input filtering",
    "D8": "Prompt-level",
    "D9": "Verification",
    "D10": "Multi-signal",
}


def load_result_file(filepath):
    """Load a single result JSON file."""
    with open(filepath) as f:
        return json.load(f)


def get_250_case_ids():
    """Get the set of 250 case IDs used in D0-D7 evaluation."""
    # Use any D0 run to get the IDs
    for model in MAIN_MODELS:
        filepath = FULL_EVAL / f"{model}_D0_run1.json"
        if filepath.exists():
            data = load_result_file(filepath)
            return set(r["case_id"] for r in data["results"])
    raise FileNotFoundError("Cannot find any D0 result file")


def compute_metrics(results, case_ids=None):
    """Compute ASR/BSR/FPR from a list of result entries.

    If case_ids is provided, filter to only those cases.
    """
    if case_ids is not None:
        results = [r for r in results if r["case_id"] in case_ids]

    attack_succeeded = sum(1 for r in results if r["verdict"] == "attack_succeeded")
    attack_blocked = sum(1 for r in results if r["verdict"] == "attack_blocked")
    benign_completed = sum(1 for r in results if r["verdict"] == "benign_completed")
    benign_blocked = sum(1 for r in results if r["verdict"] == "benign_blocked")

    total_attack = attack_succeeded + attack_blocked
    total_benign = benign_completed + benign_blocked

    asr = attack_succeeded / total_attack if total_attack > 0 else 0.0
    bsr = benign_completed / total_benign if total_benign > 0 else 0.0
    fpr = benign_blocked / total_benign if total_benign > 0 else 0.0

    return {
        "asr": asr,
        "bsr": bsr,
        "fpr": fpr,
        "attack_succeeded": attack_succeeded,
        "attack_blocked": attack_blocked,
        "benign_completed": benign_completed,
        "benign_blocked": benign_blocked,
        "total_attack": total_attack,
        "total_benign": total_benign,
        "total": total_attack + total_benign,
    }


def find_result_files(model, defense, max_runs=3):
    """Find result files for a model-defense pair, preferring full_eval_v2 for D8+."""
    files = []

    # For D8-D10, prefer full_eval_v2 if available
    if defense in ("D8", "D9", "D10"):
        for run in range(1, max_runs + 1):
            v2_path = FULL_EVAL_V2 / f"{model}_{defense}_run{run}.json"
            v1_path = FULL_EVAL / f"{model}_{defense}_run{run}.json"
            if v2_path.exists():
                files.append(v2_path)
            elif v1_path.exists():
                files.append(v1_path)
    else:
        for run in range(1, max_runs + 1):
            path = FULL_EVAL / f"{model}_{defense}_run{run}.json"
            if path.exists():
                files.append(path)

    return files[:max_runs]  # Cap at max_runs


def aggregate_runs(metrics_list):
    """Average metrics across multiple runs."""
    if not metrics_list:
        return None

    n = len(metrics_list)
    avg = {}
    for key in ["asr", "bsr", "fpr"]:
        values = [m[key] for m in metrics_list]
        avg[key] = sum(values) / n
        avg[f"{key}_std"] = (sum((v - avg[key]) ** 2 for v in values) / n) ** 0.5
        avg[f"{key}_min"] = min(values)
        avg[f"{key}_max"] = max(values)

    avg["num_runs"] = n
    avg["total"] = metrics_list[0]["total"]
    return avg


def collect_all_metrics(case_ids_250):
    """Collect metrics for all defenses × models.

    Returns:
        dict: {defense: {model: {250: metrics, 565: metrics_or_None}}}
    """
    all_metrics = {}

    for defense in DEFENSES:
        all_metrics[defense] = {}
        for model in MAIN_MODELS:
            files = find_result_files(model, defense)
            if not files:
                print(f"  WARNING: No files found for {model} × {defense}")
                continue

            # Compute 250-case metrics
            run_metrics_250 = []
            run_metrics_565 = []

            for f in files:
                data = load_result_file(f)
                results = data["results"]
                num_cases = data["metrics"]["num_cases"]

                # 250-case subset
                m250 = compute_metrics(results, case_ids_250)
                run_metrics_250.append(m250)

                # Full 565 (only if data has 565 cases)
                if num_cases == 565:
                    m565 = compute_metrics(results)
                    run_metrics_565.append(m565)

            all_metrics[defense][model] = {
                "250": aggregate_runs(run_metrics_250),
                "565": aggregate_runs(run_metrics_565) if run_metrics_565 else None,
            }

    return all_metrics


def cross_model_average(defense_metrics, case_key="250"):
    """Average metrics across all models for a defense."""
    values = {"asr": [], "bsr": [], "fpr": []}
    for model in MAIN_MODELS:
        if model in defense_metrics:
            m = defense_metrics[model].get(case_key)
            if m:
                values["asr"].append(m["asr"])
                values["bsr"].append(m["bsr"])
                values["fpr"].append(m["fpr"])

    if not values["asr"]:
        return None

    n = len(values["asr"])
    return {
        "asr": sum(values["asr"]) / n,
        "bsr": sum(values["bsr"]) / n,
        "fpr": sum(values["fpr"]) / n,
        "num_models": n,
    }


def generate_main_table(all_metrics):
    """Generate the unified main results LaTeX table (250 cases)."""
    lines = []
    lines.append(r"\begin{table*}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{Main results: all 11 defenses evaluated on the 250-case core benchmark "
                 r"(155 attack + 95 benign), averaged across 4 models $\times$ 3 runs. "
                 r"$\Delta$ASR is relative to the D0 baseline.}")
    lines.append(r"\label{tab:main_results}")
    lines.append(r"\small")
    lines.append(r"\begin{tabular}{llcccc}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{ID} & \textbf{Defense} & \textbf{ASR $\downarrow$} "
                 r"& \textbf{BSR $\uparrow$} & \textbf{FPR $\downarrow$} "
                 r"& \textbf{$\Delta$ASR} \\")
    lines.append(r"\midrule")

    # Get baseline ASR for delta computation
    baseline = cross_model_average(all_metrics["D0"], "250")
    baseline_asr = baseline["asr"] if baseline else 0.0

    # Group by category
    categories = [
        ("No defense", ["D0"]),
        ("Prompt-level", ["D1", "D2", "D3", "D5", "D8"]),
        ("Verification", ["D4", "D9"]),
        ("Filtering", ["D6", "D7"]),
        ("Multi-signal", ["D10"]),
    ]

    first_category = True
    for cat_name, defense_ids in categories:
        if not first_category:
            lines.append(r"\midrule")
        first_category = False
        lines.append(f"\\multicolumn{{6}}{{l}}{{\\textit{{{cat_name}}}}} \\\\")

        for did in defense_ids:
            avg = cross_model_average(all_metrics[did], "250")
            if avg is None:
                continue

            delta = (avg["asr"] - baseline_asr) / baseline_asr * 100 if baseline_asr > 0 else 0
            delta_str = f"{delta:+.1f}\\%"
            if did == "D0":
                delta_str = "---"

            name = DEFENSE_NAMES[did]
            if did == "D10":
                name += " (ours)"

            # Bold best ASR and BSR
            asr_str = f"{avg['asr']:.3f}"
            bsr_str = f"{avg['bsr']:.3f}"
            fpr_str = f"{avg['fpr']:.3f}"

            lines.append(
                f"{did} & {name} & {asr_str} & {bsr_str} & {fpr_str} & {delta_str} \\\\"
            )

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table*}")

    return "\n".join(lines)


def generate_extended_table(all_metrics):
    """Generate extended 565-case results table for D8-D10."""
    lines = []
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{Extended evaluation: D8--D10 on the full 565-case benchmark "
                 r"(352 attack + 213 benign), averaged across 4 models $\times$ 3 runs. "
                 r"Core-250 results shown for comparison.}")
    lines.append(r"\label{tab:extended_results}")
    lines.append(r"\small")
    lines.append(r"\begin{tabular}{lcccccc}")
    lines.append(r"\toprule")
    lines.append(r"& \multicolumn{3}{c}{\textbf{Core 250}} "
                 r"& \multicolumn{3}{c}{\textbf{Full 565}} \\")
    lines.append(r"\cmidrule(lr){2-4} \cmidrule(lr){5-7}")
    lines.append(r"\textbf{Defense} & ASR & BSR & FPR & ASR & BSR & FPR \\")
    lines.append(r"\midrule")

    for did in ["D8", "D9", "D10"]:
        avg_250 = cross_model_average(all_metrics[did], "250")
        avg_565 = cross_model_average(all_metrics[did], "565")

        name = DEFENSE_NAMES[did]
        if did == "D10":
            name += " (ours)"

        if avg_250 and avg_565:
            lines.append(
                f"{name} & {avg_250['asr']:.3f} & {avg_250['bsr']:.3f} & {avg_250['fpr']:.3f} "
                f"& {avg_565['asr']:.3f} & {avg_565['bsr']:.3f} & {avg_565['fpr']:.3f} \\\\"
            )

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")

    return "\n".join(lines)


def generate_per_model_table(all_metrics):
    """Generate per-model breakdown table."""
    lines = []
    lines.append(r"\begin{table*}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{Per-model ASR (\%) on the 250-case core benchmark (3 runs averaged). "
                 r"Lower is better.}")
    lines.append(r"\label{tab:per_model}")
    lines.append(r"\small")

    short_names = {
        "gpt-4o": "GPT-4o",
        "claude-sonnet-4-5-20250929": "Claude 4.5",
        "deepseek-v3-1-250821": "DeepSeek V3.1",
        "gemini-2.5-flash": "Gemini 2.5",
    }

    cols = "l" + "c" * len(MAIN_MODELS) + "c"
    lines.append(f"\\begin{{tabular}}{{{cols}}}")
    lines.append(r"\toprule")
    header = r"\textbf{Defense}"
    for m in MAIN_MODELS:
        header += f" & \\textbf{{{short_names[m]}}}"
    header += r" & \textbf{Avg.} \\"
    lines.append(header)
    lines.append(r"\midrule")

    for did in DEFENSES:
        row = f"{did}"
        model_asrs = []
        for model in MAIN_MODELS:
            if model in all_metrics[did]:
                m = all_metrics[did][model]["250"]
                if m:
                    asr_pct = m["asr"] * 100
                    row += f" & {asr_pct:.1f}"
                    model_asrs.append(asr_pct)
                else:
                    row += " & ---"
            else:
                row += " & ---"
        if model_asrs:
            avg_asr = sum(model_asrs) / len(model_asrs)
            row += f" & {avg_asr:.1f}"
        else:
            row += " & ---"
        row += r" \\"
        lines.append(row)

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table*}")

    return "\n".join(lines)


def print_summary(all_metrics):
    """Print a human-readable summary."""
    print("\n" + "=" * 80)
    print("UNIFIED RESULTS SUMMARY (250-case core benchmark)")
    print("=" * 80)

    baseline = cross_model_average(all_metrics["D0"], "250")
    baseline_asr = baseline["asr"] if baseline else 0.0

    for did in DEFENSES:
        avg = cross_model_average(all_metrics[did], "250")
        if avg is None:
            print(f"  {did}: NO DATA")
            continue
        delta = (avg["asr"] - baseline_asr) / baseline_asr * 100 if baseline_asr > 0 else 0
        print(
            f"  {did:3s} {DEFENSE_NAMES[did]:30s} "
            f"ASR={avg['asr']:.3f}  BSR={avg['bsr']:.3f}  "
            f"FPR={avg['fpr']:.3f}  ΔASR={delta:+.1f}%"
        )

    # Extended 565 for D8-D10
    print("\n" + "-" * 80)
    print("EXTENDED RESULTS (565-case full benchmark, D8-D10 only)")
    print("-" * 80)
    for did in ["D8", "D9", "D10"]:
        avg = cross_model_average(all_metrics[did], "565")
        if avg:
            print(
                f"  {did:3s} {DEFENSE_NAMES[did]:30s} "
                f"ASR={avg['asr']:.3f}  BSR={avg['bsr']:.3f}  "
                f"FPR={avg['fpr']:.3f}"
            )


def save_json_metrics(all_metrics):
    """Save metrics as JSON for further analysis."""
    STATS_DIR.mkdir(parents=True, exist_ok=True)

    output = {"250_case": {}, "565_case": {}, "per_model_250": {}}

    for did in DEFENSES:
        avg = cross_model_average(all_metrics[did], "250")
        if avg:
            output["250_case"][did] = avg

        avg_565 = cross_model_average(all_metrics[did], "565")
        if avg_565:
            output["565_case"][did] = avg_565

        output["per_model_250"][did] = {}
        for model in MAIN_MODELS:
            if model in all_metrics[did] and all_metrics[did][model]["250"]:
                m = all_metrics[did][model]["250"]
                output["per_model_250"][did][model] = {
                    "asr": m["asr"],
                    "bsr": m["bsr"],
                    "fpr": m["fpr"],
                    "num_runs": m["num_runs"],
                }

    outpath = STATS_DIR / "unified_metrics.json"
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved: {outpath}")


def main():
    print("Loading 250-case ID set...")
    case_ids_250 = get_250_case_ids()
    print(f"  Found {len(case_ids_250)} case IDs")

    print("\nCollecting metrics for all defenses × models...")
    all_metrics = collect_all_metrics(case_ids_250)

    print_summary(all_metrics)

    # Generate LaTeX tables
    TABLES_DIR.mkdir(parents=True, exist_ok=True)

    main_table = generate_main_table(all_metrics)
    main_path = TABLES_DIR / "main_results_unified.tex"
    with open(main_path, "w") as f:
        f.write(main_table)
    print(f"\nSaved: {main_path}")

    ext_table = generate_extended_table(all_metrics)
    ext_path = TABLES_DIR / "extended_results_565.tex"
    with open(ext_path, "w") as f:
        f.write(ext_table)
    print(f"Saved: {ext_path}")

    model_table = generate_per_model_table(all_metrics)
    model_path = TABLES_DIR / "per_model_asr.tex"
    with open(model_path, "w") as f:
        f.write(model_table)
    print(f"Saved: {model_path}")

    save_json_metrics(all_metrics)

    print("\nDone!")


if __name__ == "__main__":
    main()
