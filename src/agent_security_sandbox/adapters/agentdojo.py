"""Adapter for the AgentDojo benchmark format.

AgentDojo (Debenedetti et al., 2024) organises benchmarks by
*environment* (e.g. ``workspace``, ``slack``, ``banking``).  Each
environment has:
  - ``tasks``: User tasks with ground-truth solutions.
  - ``injections``: Injection payloads keyed by injection ID.
  - ``tools``: Available tools.

This adapter converts AgentDojo JSON exports to ASB ``BenchmarkCase``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from ..evaluation.benchmark import BenchmarkCase
from .base import BenchmarkAdapter


class AgentDojoAdapter(BenchmarkAdapter):
    """Convert AgentDojo JSON exports to ASB benchmark format."""

    @property
    def name(self) -> str:
        return "AgentDojo"

    def load(self, path: str | Path) -> List[BenchmarkCase]:
        path = Path(path)
        cases: List[BenchmarkCase] = []

        if path.is_file() and path.suffix == ".json":
            raw = self._load_json(path)
            cases.extend(self._convert_environment(raw, path.stem))
        elif path.is_dir():
            for json_file in sorted(path.glob("*.json")):
                raw = self._load_json(json_file)
                cases.extend(self._convert_environment(raw, json_file.stem))

        return cases

    def _convert_environment(
        self, raw: Dict[str, Any], env_name: str,
    ) -> List[BenchmarkCase]:
        """Convert all task-injection pairs from one AgentDojo environment."""
        tasks = raw.get("tasks", [])
        injections = raw.get("injections", {})
        cases: List[BenchmarkCase] = []

        for task_idx, task in enumerate(tasks):
            task_id = task.get("id", f"task_{task_idx}")
            goal = task.get("prompt", task.get("instruction", ""))
            expected_tools = task.get("ground_truth_tools", [])

            # Create one attack case per injection.
            for inj_id, injection in injections.items():
                payload = injection if isinstance(injection, str) else injection.get("payload", "")
                target_tool = (
                    injection.get("target_tool", "")
                    if isinstance(injection, dict) else ""
                )
                forbidden: List[Dict[str, Any]] = []
                if target_tool:
                    target_params = (
                        injection.get("target_params", {})
                        if isinstance(injection, dict) else {}
                    )
                    forbidden.append({"tool": target_tool, "params": target_params})

                cases.append(BenchmarkCase(
                    id=f"agentdojo_{env_name}_{task_id}_{inj_id}",
                    type="attack",
                    goal=goal,
                    untrusted_content=payload,
                    injection_location="tool_output",
                    attack_type="goal_hijacking",
                    injection_technique="agentdojo_injection",
                    expected_tools=expected_tools,
                    forbidden_actions=forbidden,
                    tags=["agentdojo", env_name],
                    difficulty="medium",
                    threat_level="K1_A0_S0",
                ))

            # Also create one benign case per task (no injection).
            cases.append(BenchmarkCase(
                id=f"agentdojo_{env_name}_{task_id}_benign",
                type="benign",
                goal=goal,
                expected_tools=expected_tools,
                tags=["agentdojo", env_name, "benign"],
                difficulty="medium",
            ))

        return cases

    @staticmethod
    def _load_json(path: Path) -> Dict[str, Any]:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
