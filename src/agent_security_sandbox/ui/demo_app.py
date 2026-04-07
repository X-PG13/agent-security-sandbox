"""
Agent Security Sandbox - Streamlit Demo Application

Launch with: asb serve
Or directly: streamlit run src/agent_security_sandbox/ui/demo_app.py
"""
import sys
from pathlib import Path

try:
    import streamlit as st
except ImportError:
    print("Streamlit is required. Install with: pip install agent-security-sandbox[ui]")
    sys.exit(1)

from agent_security_sandbox.core.agent import ReactAgent
from agent_security_sandbox.core.llm_client import create_llm_client
from agent_security_sandbox.defenses.registry import create_defense
from agent_security_sandbox.tools.registry import ToolRegistry
from agent_security_sandbox.ui.components import (
    render_defense_decision,
    render_metrics_chart,
    render_metrics_table,
    render_trajectory,
)


def _resolve_config_dir() -> Path:
    candidates = [
        Path(__file__).resolve().parents[3] / "config",
        Path.cwd() / "config",
        Path(__file__).resolve().parents[1] / "_bundled" / "config",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


def _default_benchmark_dir() -> str:
    candidates = [
        Path(__file__).resolve().parents[3] / "data" / "mini_benchmark",
        Path.cwd() / "data" / "mini_benchmark",
        Path(__file__).resolve().parents[1] / "_bundled" / "data" / "mini_benchmark",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return str(candidate)
    return "data/mini_benchmark"


def main():
    st.set_page_config(
        page_title="Agent Security Sandbox",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("🛡️ Agent Security Sandbox")
    st.caption("Interactive demo for evaluating AI agent security against prompt injection")

    # ---- Sidebar Configuration ----
    with st.sidebar:
        st.header("Configuration")

        provider = st.selectbox(
            "LLM Provider",
            ["mock", "openai", "openai-compatible", "anthropic"],
            index=0,
        )

        model = st.text_input(
            "Model Name",
            value="" if provider == "mock" else "gpt-4o",
            help="Leave empty for provider default",
        )

        base_url = ""
        if provider == "openai-compatible":
            base_url = st.text_input(
                "API Base URL",
                value="",
                help="e.g. https://your-proxy.com/v1",
            )

        defense_id = st.selectbox(
            "Defense Strategy",
            ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"],
            index=0,
            help="Select any defense from the full D0-D10 benchmark suite.",
        )

        max_steps = st.slider("Max Agent Steps", min_value=1, max_value=20, value=10)

    # ---- Initialize session state ----
    if "trajectory" not in st.session_state:
        st.session_state.trajectory = None
    if "eval_results" not in st.session_state:
        st.session_state.eval_results = []

    # ---- Tabs ----
    tab1, tab2, tab3 = st.tabs(["Run Agent", "Audit Trail", "Benchmark Results"])

    # ---- Tab 1: Run Agent ----
    with tab1:
        st.subheader("Run Agent on a Task")

        goal = st.text_input(
            "Goal",
            value="Read email_001 and summarize it",
            help="Natural language task for the agent",
        )

        untrusted = st.text_area(
            "Untrusted Content (optional)",
            value="",
            help="External content that may contain injection payloads",
            height=100,
        )

        if st.button("Run Agent", type="primary"):
            with st.spinner("Running agent..."):
                try:
                    kwargs = {}
                    if base_url:
                        kwargs["base_url"] = base_url

                    llm = create_llm_client(
                        provider=provider,
                        model=model or None,
                        **kwargs,
                    )

                    config_dir = _resolve_config_dir()
                    tools_cfg = config_dir / "tools.yaml"
                    registry = ToolRegistry(
                        config_path=str(tools_cfg) if tools_cfg.exists() else None
                    )

                    defense = create_defense(defense_id, llm_client=llm)

                    agent = ReactAgent(
                        llm_client=llm,
                        tool_registry=registry,
                        max_steps=max_steps,
                        verbose=False,
                    )

                    trajectory = agent.run(
                        goal=goal,
                        untrusted_content=untrusted if untrusted.strip() else None,
                        defense_strategy=defense,
                    )

                    st.session_state.trajectory = trajectory
                    st.success("Agent run complete!")

                except Exception as e:
                    st.error(f"Error: {e}")

        if st.session_state.trajectory:
            render_trajectory(st.session_state.trajectory)

    # ---- Tab 2: Audit Trail ----
    with tab2:
        st.subheader("Audit Trail")

        trajectory = st.session_state.trajectory
        if trajectory is None:
            st.info("No trajectory available. Run the agent first in the 'Run Agent' tab.")
        else:
            st.markdown(f"**Goal:** {trajectory.goal}")
            st.markdown(f"**Total Steps:** {trajectory.total_steps}")
            st.markdown(f"**Total Tokens:** {trajectory.total_tokens}")
            st.divider()

            for step in trajectory.steps:
                blocked = False
                if step.defense_decision is not None:
                    blocked = not step.defense_decision.get("allowed", True)

                color = "red" if blocked else "green"
                status = "BLOCKED" if blocked else "OK"

                with st.container():
                    st.markdown(
                        f"### Step {step.step_number} — "
                        f"`{step.action}` "
                        f":{color}[{status}]"
                    )

                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.markdown("**Thought:**")
                        st.text(step.thought or "(none)")
                        st.markdown("**Observation:**")
                        st.text(step.observation[:500] if step.observation else "(none)")
                    with col2:
                        st.markdown("**Action Input:**")
                        st.json(step.action_input)
                        if step.defense_decision:
                            render_defense_decision(step.defense_decision)
                        st.caption(f"Tokens: {step.tokens_used}")

                    st.divider()

            if trajectory.final_answer:
                st.markdown("### Final Answer")
                st.success(trajectory.final_answer)

            # Summary
            st.markdown("### Summary Statistics")
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Steps", trajectory.total_steps)
            col2.metric("Tokens", trajectory.total_tokens)
            blocked_count = sum(
                1 for s in trajectory.steps
                if s.defense_decision and not s.defense_decision.get("allowed", True)
            )
            col3.metric("Blocked", blocked_count)
            col4.metric("Has Answer", "Yes" if trajectory.final_answer else "No")

    # ---- Tab 3: Benchmark Results ----
    with tab3:
        st.subheader("Benchmark Evaluation")

        bench_dir = st.text_input(
            "Benchmark Directory",
            value=_default_benchmark_dir(),
        )

        defense_choices = st.multiselect(
            "Defenses to Compare",
            ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"],
            default=["D0", "D5", "D10"],
        )

        if st.button("Run Evaluation", type="primary", key="eval_btn"):
            try:
                from agent_security_sandbox.evaluation.benchmark import BenchmarkSuite
                from agent_security_sandbox.evaluation.runner import ExperimentRunner

                suite = BenchmarkSuite.load_from_directory(bench_dir)
                n_attack = len(suite.attack_cases)
                n_benign = len(suite.benign_cases)
                st.write(
                    f"Loaded {len(suite)} cases"
                    f" ({n_attack} attack, {n_benign} benign)"
                )

                kwargs = {}
                if base_url:
                    kwargs["base_url"] = base_url

                llm = create_llm_client(
                    provider=provider,
                    model=model or None,
                    **kwargs,
                )

                results = []
                progress = st.progress(0)

                for i, did in enumerate(defense_choices):
                    st.write(f"Evaluating {did}...")
                    defense = create_defense(did, llm_client=llm)

                    runner = ExperimentRunner(
                        llm_client=llm,
                        tool_registry_factory=ToolRegistry,
                        defense_strategy=defense,
                        max_steps=max_steps,
                        verbose=False,
                    )

                    result = runner.run_suite(suite)
                    result.metrics.defense_id = did
                    results.append(result)
                    progress.progress((i + 1) / len(defense_choices))

                st.session_state.eval_results = results
                st.success("Evaluation complete!")

            except Exception as e:
                st.error(f"Evaluation error: {e}")

        if st.session_state.eval_results:
            metrics_list = [r.metrics for r in st.session_state.eval_results]

            # Set defense_id if not present
            for i, r in enumerate(st.session_state.eval_results):
                if not hasattr(r.metrics, "defense_id"):
                    r.metrics.defense_id = r.defense_name

            render_metrics_table(metrics_list)
            render_metrics_chart(metrics_list)


if __name__ == "__main__":
    main()
