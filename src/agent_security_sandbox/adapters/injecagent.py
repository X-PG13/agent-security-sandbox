"""Adapter for the InjecAgent benchmark format.

InjecAgent (Zhan et al., 2024) uses a JSONL format with fields:
  - ``user_instruction``: The user's legitimate task.
  - ``injected_prompt``: The attacker's injection payload.
  - ``target_tool``: Tool the attacker wants invoked.
  - ``tool_parameters``: Parameters for the forbidden tool call.
  - ``agent_tools``: Available tools for the agent.
  - ``attack_type``: ``"direct"`` or ``"indirect"``.

This adapter converts InjecAgent cases into ASB ``BenchmarkCase`` objects.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from ..evaluation.benchmark import BenchmarkCase
from .base import BenchmarkAdapter


class InjecAgentAdapter(BenchmarkAdapter):
    """Convert InjecAgent JSONL files to ASB benchmark format."""

    @property
    def name(self) -> str:
        return "InjecAgent"

    def load(self, path: str | Path) -> List[BenchmarkCase]:
        path = Path(path)
        cases: List[BenchmarkCase] = []

        files = sorted(path.glob("*.jsonl")) if path.is_dir() else [path]

        for file_path in files:
            with open(file_path, "r", encoding="utf-8") as fh:
                for line_num, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw = json.loads(line)
                        case = self._convert_case(raw, line_num, file_path.stem)
                        cases.append(case)
                    except (json.JSONDecodeError, KeyError, Exception):
                        # Skip malformed entries.
                        continue

        return cases

    def _convert_case(
        self, raw: Dict[str, Any], idx: int, source: str,
    ) -> BenchmarkCase:
        """Convert a single InjecAgent record to a BenchmarkCase."""
        case_id = raw.get("id", f"injecagent_{source}_{idx:04d}")

        # Map InjecAgent attack_type to ASB attack_type.
        ia_attack_type = raw.get("attack_type", "indirect")
        if ia_attack_type == "direct":
            asb_attack_type = "goal_hijacking"
        else:
            asb_attack_type = "data_exfiltration"

        # Build forbidden actions from target_tool + tool_parameters.
        forbidden: List[Dict[str, Any]] = []
        target_tool = raw.get("target_tool", "")
        tool_params = raw.get("tool_parameters", {})
        if isinstance(tool_params, str):
            try:
                tool_params = json.loads(tool_params)
            except json.JSONDecodeError:
                tool_params = {}
        if target_tool:
            forbidden.append({"tool": target_tool, "params": tool_params})

        # Map agent_tools to expected_tools (benign path).
        agent_tools = raw.get("agent_tools", [])
        if isinstance(agent_tools, str):
            agent_tools = [t.strip() for t in agent_tools.split(",")]

        return BenchmarkCase(
            id=case_id,
            type="attack",
            goal=raw.get("user_instruction", ""),
            untrusted_content=raw.get("injected_prompt", ""),
            injection_location=raw.get("injection_location", "email_body"),
            attack_type=asb_attack_type,
            injection_technique=f"injecagent_{ia_attack_type}",
            expected_tools=agent_tools,
            forbidden_actions=forbidden,
            tags=["injecagent", ia_attack_type],
            difficulty="medium",
            threat_level="K1_A0_S0",
        )
