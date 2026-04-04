"""
D2 -- Policy Gate (Permission Control)

Enforces a configurable access-control policy on tool calls:

* **Critical tools** are blocked entirely (e.g. ``execute_code``).
* **High-risk tools** are only allowed when the tool name appears on
  an explicit whitelist.
* **Parameter whitelists** defined in tool metadata are enforced so
  that, e.g., emails can only be sent to approved recipients.

This defense does *not* modify the prompt -- it operates entirely at
the tool-call gating stage.
"""
from typing import Any, Dict, List, Tuple

from ..tools.base import RiskLevel, Tool
from .base import DefenseStrategy


class PolicyGateDefense(DefenseStrategy):
    """Permission-based tool-call gating.

    Configuration keys (via ``config`` dict):
        enforce_whitelists (bool): If True, enforce parameter-level whitelists
            defined in ``ToolParameter.whitelist``.  Default True.
        block_critical_tools (bool): If True, unconditionally block tools
            whose risk level is CRITICAL.  Default True.
        high_risk_tools (list[str]): Tool names that require explicit
            inclusion in this list to be callable.  Any HIGH-risk tool
            *not* in this list is blocked.
        critical_tools (list[str]): Tool names to be treated as critical
            regardless of their metadata risk level.  These are always
            blocked when *block_critical_tools* is True.
    """

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}
        self.enforce_whitelists: bool = self.config.get("enforce_whitelists", True)
        self.block_critical_tools: bool = self.config.get("block_critical_tools", True)

        # Lists from config -- these override / augment risk-level checks
        self.high_risk_tools: List[str] = self.config.get("high_risk_tools", [])
        self.critical_tools: List[str] = self.config.get("critical_tools", [])

    # ------------------------------------------------------------------
    # DefenseStrategy interface
    # ------------------------------------------------------------------

    def prepare_context(self, goal: str, untrusted_content: str) -> str:
        """Policy Gate does not modify the prompt."""
        return f"{goal}\n\nContext:\n{untrusted_content}"

    def should_allow_tool_call(
        self,
        tool: Tool,
        params: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Evaluate whether a tool call is permitted by the policy."""
        tool_name = tool.metadata.name

        # 1. Block critical tools entirely
        if self._is_critical(tool):
            return (
                False,
                f"Tool '{tool_name}' is classified as critical and is "
                f"blocked by policy.",
            )

        # 2. High-risk tool whitelist check
        if self._is_high_risk(tool):
            if tool_name not in self.high_risk_tools:
                return (
                    False,
                    f"Tool '{tool_name}' is high-risk but not on the "
                    f"allowed high-risk tool list.",
                )

        # 3. Parameter whitelist enforcement
        if self.enforce_whitelists:
            allowed, reason = self._check_param_whitelists(tool, params)
            if not allowed:
                return False, reason

        return True, "Tool call permitted by policy."

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_critical(self, tool: Tool) -> bool:
        """Return True if the tool should be treated as critical."""
        if tool.metadata.name in self.critical_tools:
            return True
        if (
            self.block_critical_tools
            and tool.metadata.risk_level == RiskLevel.CRITICAL
        ):
            return True
        return False

    def _is_high_risk(self, tool: Tool) -> bool:
        """Return True if the tool is high-risk (but not critical)."""
        if tool.metadata.risk_level == RiskLevel.HIGH:
            return True
        return False

    @staticmethod
    def _check_param_whitelists(
        tool: Tool, params: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """Enforce parameter-level whitelists from tool metadata."""
        for param_name, value in params.items():
            param_def = tool.metadata.parameters.get(param_name)
            if param_def and param_def.whitelist is not None:
                if value not in param_def.whitelist:
                    return (
                        False,
                        f"Parameter '{param_name}' value '{value}' is not in "
                        f"the whitelist {param_def.whitelist}.",
                    )
        return True, ""
