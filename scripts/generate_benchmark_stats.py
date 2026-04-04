#!/usr/bin/env python3
"""Generate benchmark statistics and visualizations for the ASB paper."""

import json
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

BENCHMARK_DIR = Path(__file__).parent.parent / "data" / "full_benchmark"
OUTPUT_DIR = Path(__file__).parent.parent / "figures" / "benchmark_stats"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Color palette
COLORS = {
    'attack': '#e74c3c',
    'benign': '#27ae60',
    'easy': '#2ecc71',
    'medium': '#f39c12',
    'hard': '#e74c3c',
}

ATTACK_TYPE_LABELS = {
    'data_exfiltration': 'Data Exfiltration',
    'goal_hijacking': 'Goal Hijacking',
    'privilege_escalation': 'Privilege Escalation',
    'multistep': 'Multi-step',
    'denial_of_service': 'Denial of Service',
    'social_engineering': 'Social Engineering',
}

ATTACK_COLORS = ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#3498db', '#9b59b6']


def load_cases():
    cases = []
    for fpath in sorted(BENCHMARK_DIR.glob("*.jsonl")):
        with open(fpath) as f:
            for line in f:
                c = json.loads(line.strip())
                c['_source'] = fpath.stem
                cases.append(c)
    return cases


def fig1_attack_type_distribution(cases):
    """Pie chart of attack types."""
    attack_cases = [c for c in cases if c.get('type') == 'attack']
    types = Counter(c.get('attack_type', 'unknown') for c in attack_cases)

    labels = []
    sizes = []
    colors = []
    for i, (at, count) in enumerate(types.most_common()):
        labels.append(f"{ATTACK_TYPE_LABELS.get(at, at)}\n({count})")
        sizes.append(count)
        colors.append(ATTACK_COLORS[i % len(ATTACK_COLORS)])

    fig, ax = plt.subplots(1, 1, figsize=(8, 6))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors,
        autopct='%1.1f%%', startangle=140,
        textprops={'fontsize': 10}
    )
    for t in autotexts:
        t.set_fontsize(9)
    ax.set_title('Attack Type Distribution (352 cases)', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'attack_type_distribution.pdf', bbox_inches='tight', dpi=300)
    plt.savefig(OUTPUT_DIR / 'attack_type_distribution.png', bbox_inches='tight', dpi=300)
    plt.close()
    print("  Generated: attack_type_distribution.pdf")


def fig2_difficulty_distribution(cases):
    """Bar chart of difficulty by type."""
    attack_cases = [c for c in cases if c.get('type') == 'attack']
    benign_cases = [c for c in cases if c.get('type') == 'benign']

    atk_diff = Counter(c.get('difficulty', 'unknown') for c in attack_cases)
    ben_diff = Counter(c.get('difficulty', 'unknown') for c in benign_cases)

    difficulties = ['easy', 'medium', 'hard']
    atk_vals = [atk_diff.get(d, 0) for d in difficulties]
    ben_vals = [ben_diff.get(d, 0) for d in difficulties]

    x = np.arange(len(difficulties))
    width = 0.35

    fig, ax = plt.subplots(figsize=(7, 5))
    bars1 = ax.bar(x - width/2, atk_vals, width, label='Attack', color=COLORS['attack'], alpha=0.85)
    bars2 = ax.bar(x + width/2, ben_vals, width, label='Benign', color=COLORS['benign'], alpha=0.85)

    ax.set_xlabel('Difficulty', fontsize=12)
    ax.set_ylabel('Number of Cases', fontsize=12)
    ax.set_title('Case Difficulty Distribution', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels([d.capitalize() for d in difficulties])
    ax.legend()

    for bar in bars1:
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 2,
                str(int(bar.get_height())), ha='center', va='bottom', fontsize=10)
    for bar in bars2:
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 2,
                str(int(bar.get_height())), ha='center', va='bottom', fontsize=10)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'difficulty_distribution.pdf', bbox_inches='tight', dpi=300)
    plt.savefig(OUTPUT_DIR / 'difficulty_distribution.png', bbox_inches='tight', dpi=300)
    plt.close()
    print("  Generated: difficulty_distribution.pdf")


def fig3_tool_usage(cases):
    """Horizontal bar chart of tool usage frequency."""
    tool_counts = Counter()
    for c in cases:
        for t in c.get('expected_tools', []):
            tool_counts[t] += 1
        for fa in c.get('forbidden_actions', []):
            tool_counts[fa.get('tool', '')] += 1

    # Sort by count
    sorted_tools = tool_counts.most_common()
    tools = [t for t, _ in sorted_tools]
    counts = [c for _, c in sorted_tools]

    fig, ax = plt.subplots(figsize=(8, 6))
    y_pos = np.arange(len(tools))
    bars = ax.barh(y_pos, counts, color='#3498db', alpha=0.85)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(tools, fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel('Frequency', fontsize=12)
    ax.set_title('Tool Usage Frequency Across Benchmark', fontsize=14, fontweight='bold')

    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 3, bar.get_y() + bar.get_height()/2.,
                str(count), ha='left', va='center', fontsize=9)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'tool_usage.pdf', bbox_inches='tight', dpi=300)
    plt.savefig(OUTPUT_DIR / 'tool_usage.png', bbox_inches='tight', dpi=300)
    plt.close()
    print("  Generated: tool_usage.pdf")


def fig4_injection_location(cases):
    """Bar chart of injection locations."""
    attack_cases = [c for c in cases if c.get('type') == 'attack']
    locations = Counter(c.get('injection_location', 'unknown') for c in attack_cases)

    sorted_locs = locations.most_common()
    locs = [loc for loc, _ in sorted_locs]
    counts = [cnt for _, cnt in sorted_locs]

    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(locs))
    bars = ax.bar(x, counts, color='#e67e22', alpha=0.85)
    ax.set_xticks(x)
    ax.set_xticklabels(
        [loc.replace('_', '\n') for loc in locs], fontsize=9, rotation=0
    )
    ax.set_ylabel('Number of Cases', fontsize=12)
    ax.set_title('Injection Location Distribution', fontsize=14, fontweight='bold')

    for bar in bars:
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 1,
                str(int(bar.get_height())), ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'injection_location.pdf', bbox_inches='tight', dpi=300)
    plt.savefig(OUTPUT_DIR / 'injection_location.png', bbox_inches='tight', dpi=300)
    plt.close()
    print("  Generated: injection_location.pdf")


def fig5_injection_technique(cases):
    """Horizontal bar chart of top injection techniques."""
    attack_cases = [c for c in cases if c.get('type') == 'attack']
    techniques = Counter(c.get('injection_technique', 'unknown') for c in attack_cases)

    # Top 15
    top = techniques.most_common(15)
    techs = [t for t, _ in top]
    counts = [c for _, c in top]

    fig, ax = plt.subplots(figsize=(9, 6))
    y_pos = np.arange(len(techs))
    bars = ax.barh(y_pos, counts, color='#9b59b6', alpha=0.85)
    ax.set_yticks(y_pos)
    ax.set_yticklabels([t.replace('_', ' ').title() for t in techs], fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel('Frequency', fontsize=12)
    ax.set_title('Top 15 Injection Techniques', fontsize=14, fontweight='bold')

    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2.,
                str(count), ha='left', va='center', fontsize=9)

    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'injection_techniques.pdf', bbox_inches='tight', dpi=300)
    plt.savefig(OUTPUT_DIR / 'injection_techniques.png', bbox_inches='tight', dpi=300)
    plt.close()
    print("  Generated: injection_techniques.pdf")


def fig6_attack_difficulty_heatmap(cases):
    """Heatmap: attack type × difficulty."""
    attack_cases = [c for c in cases if c.get('type') == 'attack']
    types = sorted(set(c.get('attack_type') for c in attack_cases))
    diffs = ['easy', 'medium', 'hard']

    matrix = np.zeros((len(types), len(diffs)))
    for c in attack_cases:
        at = c.get('attack_type')
        d = c.get('difficulty', 'medium')
        if at in types and d in diffs:
            matrix[types.index(at)][diffs.index(d)] += 1

    fig, ax = plt.subplots(figsize=(7, 5))
    im = ax.imshow(matrix, cmap='YlOrRd', aspect='auto')
    ax.set_xticks(np.arange(len(diffs)))
    ax.set_xticklabels([d.capitalize() for d in diffs])
    ax.set_yticks(np.arange(len(types)))
    ax.set_yticklabels([ATTACK_TYPE_LABELS.get(t, t) for t in types], fontsize=10)

    # Add text annotations
    for i in range(len(types)):
        for j in range(len(diffs)):
            val = int(matrix[i, j])
            color = 'white' if val > matrix.max() * 0.6 else 'black'
            ax.text(j, i, str(val), ha='center', va='center', color=color, fontsize=11)

    ax.set_title('Attack Type × Difficulty Distribution', fontsize=14, fontweight='bold')
    fig.colorbar(im, ax=ax, label='Count')
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'attack_difficulty_heatmap.pdf', bbox_inches='tight', dpi=300)
    plt.savefig(OUTPUT_DIR / 'attack_difficulty_heatmap.png', bbox_inches='tight', dpi=300)
    plt.close()
    print("  Generated: attack_difficulty_heatmap.pdf")


def generate_summary_table(cases):
    """Generate LaTeX summary table for the paper."""
    attack_cases = [c for c in cases if c.get('type') == 'attack']
    benign_cases = [c for c in cases if c.get('type') == 'benign']

    types = Counter(c.get('attack_type') for c in attack_cases)
    all_tools = set()
    for c in cases:
        all_tools.update(c.get('expected_tools', []))
        all_tools.update(fa.get('tool') for fa in c.get('forbidden_actions', []))

    tex = r"""\begin{table}[t]
\centering
\small
\caption{ASB benchmark statistics: 565 cases,
6 attack types, 12 tools, 3 difficulty levels.}
\label{tab:benchmark_stats}
\begin{tabular}{lrrr}
\toprule
\textbf{Attack Type} & \textbf{Easy} & \textbf{Medium} & \textbf{Hard} \\
\midrule
"""
    for at, _ in types.most_common():
        at_cases = [c for c in attack_cases if c.get('attack_type') == at]
        diffs = Counter(c.get('difficulty', 'medium') for c in at_cases)
        label = ATTACK_TYPE_LABELS.get(at, at)
        easy = diffs.get('easy', 0)
        med = diffs.get('medium', 0)
        hard = diffs.get('hard', 0)
        tex += f"{label} & {easy} & {med} & {hard} \\\\\n"

    tex += r"""\midrule
\textbf{Total Attack} & """ + " & ".join(
        str(sum(1 for c in attack_cases if c.get('difficulty') == d))
        for d in ['easy', 'medium', 'hard']
    ) + r""" \\
\midrule
Benign & """ + " & ".join(
        str(sum(1 for c in benign_cases if c.get('difficulty') == d))
        for d in ['easy', 'medium', 'hard']
    ) + r""" \\
\midrule
\textbf{Grand Total} & """ + " & ".join(
        str(sum(1 for c in cases if c.get('difficulty') == d))
        for d in ['easy', 'medium', 'hard']
    ) + r""" \\
\bottomrule
\end{tabular}
\end{table}
"""
    out_path = Path(__file__).parent.parent / "paper" / "tables" / "benchmark_stats.tex"
    with open(out_path, 'w') as f:
        f.write(tex)
    print("  Generated: paper/tables/benchmark_stats.tex")


def print_summary(cases):
    """Print summary statistics."""
    attack_cases = [c for c in cases if c.get('type') == 'attack']
    benign_cases = [c for c in cases if c.get('type') == 'benign']

    print(f"\n{'='*50}")
    print("ASB Benchmark Summary")
    print(f"{'='*50}")
    print(f"Total cases:     {len(cases)}")
    print(f"Attack cases:    {len(attack_cases)} ({len(attack_cases)/len(cases)*100:.1f}%)")
    print(f"Benign cases:    {len(benign_cases)} ({len(benign_cases)/len(cases)*100:.1f}%)")
    print(f"Attack types:    {len(set(c.get('attack_type') for c in attack_cases))}")
    print(f"Injection locs:  {len(set(c.get('injection_location') for c in attack_cases))}")
    print(f"Inject. techs:   {len(set(c.get('injection_technique') for c in attack_cases))}")

    all_tools = set()
    for c in cases:
        all_tools.update(c.get('expected_tools', []))
        all_tools.update(fa.get('tool') for fa in c.get('forbidden_actions', []))
    print(f"Unique tools:    {len(all_tools)}")
    print(f"Difficulty:      easy={sum(1 for c in cases if c.get('difficulty')=='easy')}, "
          f"medium={sum(1 for c in cases if c.get('difficulty')=='medium')}, "
          f"hard={sum(1 for c in cases if c.get('difficulty')=='hard')}")
    print(f"{'='*50}")


def main():
    cases = load_cases()
    print(f"Loaded {len(cases)} cases\n")

    print("Generating figures:")
    fig1_attack_type_distribution(cases)
    fig2_difficulty_distribution(cases)
    fig3_tool_usage(cases)
    fig4_injection_location(cases)
    fig5_injection_technique(cases)
    fig6_attack_difficulty_heatmap(cases)

    print("\nGenerating tables:")
    generate_summary_table(cases)

    print_summary(cases)


if __name__ == "__main__":
    main()
