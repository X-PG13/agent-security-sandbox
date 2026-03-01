"""
Reusable Streamlit UI components for Agent Security Sandbox.

Provides rendering helpers for agent trajectories, defense decisions,
and evaluation metrics.  All functions assume that ``streamlit`` is
already imported and available as ``st`` in the caller's namespace;
this module imports it at the top level and will raise a clear error
if the package is missing.
"""

try:
    import streamlit as st
except ImportError:
    raise ImportError(
        "Streamlit is required for the demo UI but is not installed.\n"
        "Install it with:  pip install streamlit"
    )

from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Trajectory rendering
# ---------------------------------------------------------------------------

def render_trajectory(trajectory) -> None:
    """Render an AgentTrajectory as expandable step sections.

    Each step is displayed inside a Streamlit expander.  Steps where
    the defense blocked the action are highlighted in red; steps that
    were allowed (or had no defense) are shown in green.

    Args:
        trajectory: An ``AgentTrajectory`` instance (from
            ``agent_security_sandbox.core.agent``).
    """
    if trajectory is None:
        st.info("No trajectory to display.  Run the agent first.")
        return

    st.subheader("Agent Trajectory")

    # Summary metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Steps", trajectory.total_steps)
    col2.metric("Total Tokens", trajectory.total_tokens)
    col3.metric(
        "Final Answer",
        "Yes" if trajectory.final_answer else "No",
    )

    # Goal
    st.markdown(f"**Goal:** {trajectory.goal}")

    # Steps
    for step in trajectory.steps:
        # Determine colour based on defense decision
        blocked = False
        if step.defense_decision is not None:
            blocked = not step.defense_decision.get("allowed", True)

        icon = "🔴" if blocked else "🟢"
        label = f"Step {step.step_number}: {step.action} {icon}"

        with st.expander(label, expanded=False):
            st.markdown("**Thought**")
            st.text(step.thought or "(no thought recorded)")

            st.markdown("**Action**")
            st.code(f"{step.action}({step.action_input})", language="python")

            st.markdown("**Observation**")
            st.text(step.observation or "(no observation)")

            if step.defense_decision is not None:
                render_defense_decision(step.defense_decision)

            st.caption(
                f"Timestamp: {step.timestamp}  |  Tokens: {step.tokens_used}"
            )

    # Final answer
    if trajectory.final_answer:
        st.divider()
        st.markdown("### Final Answer")
        st.success(trajectory.final_answer)


# ---------------------------------------------------------------------------
# Defense decision rendering
# ---------------------------------------------------------------------------

def render_defense_decision(decision: Optional[Dict[str, Any]]) -> None:
    """Render a single defense decision with a coloured indicator.

    Args:
        decision: A dict with at least ``"allowed"`` (bool) and
            ``"reason"`` (str) keys.  If *None*, nothing is rendered.
    """
    if decision is None:
        return

    allowed = decision.get("allowed", True)
    reason = decision.get("reason", "No reason provided.")

    if allowed:
        st.markdown(
            f":green[**ALLOWED**] -- {reason}"
        )
    else:
        st.markdown(
            f":red[**BLOCKED**] -- {reason}"
        )


# ---------------------------------------------------------------------------
# Metrics table
# ---------------------------------------------------------------------------

def render_metrics_table(metrics_list: List[Any]) -> None:
    """Render a comparison table of EvaluationMetrics objects.

    Each ``EvaluationMetrics`` object is expected to have at least the
    following attributes: ``defense_id``, ``asr`` (Attack Success Rate),
    ``bsr`` (Benign Success Rate), ``fpr`` (False Positive Rate),
    ``total_cases``, ``attack_cases``, ``benign_cases``.

    Args:
        metrics_list: A list of ``EvaluationMetrics`` instances.
    """
    if not metrics_list:
        st.info("No metrics to display.")
        return

    st.subheader("Metrics Comparison")

    rows = []
    for m in metrics_list:
        row = {
            "Defense": getattr(m, "defense_id", "unknown"),
            "ASR (Attack Success Rate)": f"{getattr(m, 'asr', 0.0):.2%}",
            "BSR (Benign Success Rate)": f"{getattr(m, 'bsr', 0.0):.2%}",
            "FPR (False Positive Rate)": f"{getattr(m, 'fpr', 0.0):.2%}",
            "Total Cases": getattr(m, "total_cases", 0),
            "Attack Cases": getattr(m, "attack_cases", 0),
            "Benign Cases": getattr(m, "benign_cases", 0),
        }
        rows.append(row)

    st.table(rows)


# ---------------------------------------------------------------------------
# Metrics chart
# ---------------------------------------------------------------------------

def render_metrics_chart(metrics_list: List[Any]) -> None:
    """Render a grouped bar chart comparing ASR, BSR, and FPR across defenses.

    Uses ``matplotlib`` to draw the chart, then displays it via
    ``st.pyplot``.

    Args:
        metrics_list: A list of ``EvaluationMetrics`` instances with
            ``defense_id``, ``asr``, ``bsr``, and ``fpr`` attributes.
    """
    if not metrics_list:
        st.info("No metrics to chart.")
        return

    try:
        import matplotlib
        import matplotlib.pyplot as plt
        matplotlib.use("Agg")  # Non-interactive backend
    except ImportError:
        st.warning(
            "matplotlib is required for charts but is not installed.\n"
            "Install it with:  pip install matplotlib"
        )
        return

    import numpy as np

    defense_ids = [getattr(m, "defense_id", "unknown") for m in metrics_list]
    asr_vals = [getattr(m, "asr", 0.0) for m in metrics_list]
    bsr_vals = [getattr(m, "bsr", 0.0) for m in metrics_list]
    fpr_vals = [getattr(m, "fpr", 0.0) for m in metrics_list]

    x = np.arange(len(defense_ids))
    width = 0.25

    fig, ax = plt.subplots(figsize=(max(8, len(defense_ids) * 2), 5))

    bars_asr = ax.bar(x - width, asr_vals, width, label="ASR", color="#e74c3c")
    bars_bsr = ax.bar(x, bsr_vals, width, label="BSR", color="#2ecc71")
    bars_fpr = ax.bar(x + width, fpr_vals, width, label="FPR", color="#f39c12")

    ax.set_xlabel("Defense Strategy")
    ax.set_ylabel("Rate")
    ax.set_title("Defense Strategy Comparison")
    ax.set_xticks(x)
    ax.set_xticklabels(defense_ids, rotation=30, ha="right")
    ax.set_ylim(0, 1.05)
    ax.legend()

    # Value labels on top of bars
    for bars in [bars_asr, bars_bsr, bars_fpr]:
        for bar in bars:
            height = bar.get_height()
            ax.annotate(
                f"{height:.0%}",
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=8,
            )

    fig.tight_layout()
    st.pyplot(fig)
    plt.close(fig)
