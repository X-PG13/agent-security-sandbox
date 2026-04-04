"""
D4 -- Re-execution Detection

Detects prompt injection by re-running the same prompt without untrusted
content and comparing the resulting action.  If the agent's proposed
action changes significantly when the untrusted content is removed, the
original action is likely injection-influenced and should be blocked.

Algorithm:
1. When a high-risk tool call is proposed, record the action + params.
2. Reconstruct the prompt with untrusted content stripped.
3. Ask the LLM what action it would take given the "clean" prompt.
4. Compare the original action with the clean action.
5. If the similarity is below ``similarity_threshold``, block.
"""
import json
import re
from typing import Any, Dict, Optional, Tuple

from ..tools.base import RiskLevel, Tool
from .base import DefenseStrategy


class ReExecutionDefense(DefenseStrategy):
    """Detect injection by comparing actions with and without untrusted content.

    Configuration keys (via ``config`` dict):
        similarity_threshold (float): Minimum similarity (0-1) between
            the original and clean actions for the call to be allowed.
            Default 0.8.
        comparison_method (str): ``"action"`` compares tool name + params;
            ``"output"`` would compare full LLM output (not yet implemented).
            Default ``"action"``.
        re_execute_on_high_risk (bool): Only apply the re-execution check
            for HIGH / CRITICAL risk tools.  Default True.

    Args:
        config: Defence configuration dictionary.
        llm_client: Optional ``LLMClient`` for re-execution.  If not
            provided the defense falls back to heuristic comparison
            (checking whether untrusted-content fragments appear in
            the action parameters).
    """

    def __init__(
        self,
        config: Dict[str, Any] | None = None,
        llm_client: Any = None,
    ):
        self.config = config or {}
        self.llm_client = llm_client

        self.similarity_threshold: float = self.config.get(
            "similarity_threshold", 0.8
        )
        self.comparison_method: str = self.config.get(
            "comparison_method", "action"
        )
        self.re_execute_on_high_risk: bool = self.config.get(
            "re_execute_on_high_risk", True
        )

        # Stored by prepare_context so we can reconstruct a clean prompt.
        self._current_goal: Optional[str] = None
        self._current_untrusted: Optional[str] = None

    # ------------------------------------------------------------------
    # DefenseStrategy interface
    # ------------------------------------------------------------------

    def prepare_context(self, goal: str, untrusted_content: str) -> str:
        """Cache the goal and untrusted content for later re-execution."""
        self._current_goal = goal
        self._current_untrusted = untrusted_content
        return f"{goal}\n\nContext:\n{untrusted_content}"

    def should_allow_tool_call(
        self,
        tool: Tool,
        params: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Compare the proposed action against a clean re-execution."""
        goal: str = context.get("goal", self._current_goal or "")

        # Optionally skip low/medium risk tools
        if self.re_execute_on_high_risk:
            if tool.metadata.risk_level not in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                return True, "Tool is not high-risk; re-execution check skipped."

        # If we have an LLM client, do a proper re-execution
        if self.llm_client is not None:
            return self._llm_reexecution_check(goal, tool, params)

        # Fallback: heuristic comparison -- check whether the action
        # parameters contain fragments of untrusted content that look
        # suspicious.
        return self._heuristic_check(goal, tool, params)

    # ------------------------------------------------------------------
    # LLM-based re-execution
    # ------------------------------------------------------------------

    def _llm_reexecution_check(
        self,
        goal: str,
        tool: Tool,
        params: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Re-run the prompt without untrusted content and compare actions."""
        clean_prompt = self._build_clean_prompt(goal)
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a helpful AI assistant. Given the user's goal, "
                    "decide the single best next action. Respond in exactly "
                    "this format:\n"
                    "Action: <tool_name>\n"
                    "Action Input: {\"param\": \"value\"}"
                ),
            },
            {"role": "user", "content": clean_prompt},
        ]

        try:
            resp = self.llm_client.call(messages, max_tokens=300)
            # If the LLM returned structured tool_calls, extract directly
            if resp.tool_calls:
                tc = resp.tool_calls[0]
                func = tc.get("function", {})
                clean_action = func.get("name")
                raw_args = func.get("arguments", "{}")
                if isinstance(raw_args, str):
                    import json as _json
                    try:
                        clean_params = _json.loads(raw_args)
                    except (ValueError, _json.JSONDecodeError):
                        clean_params = {}
                else:
                    clean_params = raw_args if isinstance(raw_args, dict) else {}
            else:
                clean_action, clean_params = self._parse_action(resp.content)
        except Exception:
            # If re-execution fails, fall back to heuristic
            return self._heuristic_check(goal, tool, params)

        # Compare original vs clean action
        similarity = self._compute_similarity(
            tool.metadata.name, params, clean_action, clean_params
        )

        if similarity >= self.similarity_threshold:
            return (
                True,
                f"Re-execution check passed (similarity={similarity:.2f}). "
                f"Original and clean actions are consistent.",
            )
        else:
            return (
                False,
                f"Re-execution check failed (similarity={similarity:.2f}, "
                f"threshold={self.similarity_threshold:.2f}). "
                f"Original action: {tool.metadata.name}({params}), "
                f"Clean action: {clean_action}({clean_params}). "
                f"The untrusted content may have influenced the action.",
            )

    def _build_clean_prompt(self, goal: str) -> str:
        """Build a prompt that contains only the user's goal."""
        return (
            f"Complete the following task. Only use the tools that are "
            f"necessary.\n\nTask: {goal}"
        )

    # ------------------------------------------------------------------
    # Heuristic fallback
    # ------------------------------------------------------------------

    def _heuristic_check(
        self,
        goal: str,
        tool: Tool,
        params: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Simple heuristic: flag if params contain suspicious content.

        Checks whether parameter values contain fragments from the
        untrusted content that are *not* present in the original goal.
        This catches obvious cases like an injected email address.
        """
        untrusted = self._current_untrusted or ""
        if not untrusted:
            return True, "No untrusted content to compare against."

        goal_lower = goal.lower()
        untrusted_lower = untrusted.lower()

        suspicious_params: list[str] = []
        for param_name, value in params.items():
            if not isinstance(value, str) or len(value) < 4:
                continue
            value_lower = value.lower()
            # Value appears in untrusted content but NOT in the goal
            if value_lower in untrusted_lower and value_lower not in goal_lower:
                suspicious_params.append(param_name)

        if suspicious_params:
            return (
                False,
                f"Heuristic re-execution check failed: parameter(s) "
                f"{suspicious_params} contain values from untrusted content "
                f"that are not present in the original goal.",
            )

        return (
            True,
            "Heuristic re-execution check passed: no suspicious parameter "
            "overlap with untrusted content detected.",
        )

    # ------------------------------------------------------------------
    # Action parsing & comparison
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_action(
        llm_output: str,
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """Extract action name and params from an LLM response."""
        action_match = re.search(r"Action:\s*(\w+)", llm_output, re.IGNORECASE)
        action_name = action_match.group(1).strip() if action_match else None

        action_params: Dict[str, Any] = {}
        input_match = re.search(
            r"Action Input:\s*(\{.*?\})", llm_output, re.DOTALL | re.IGNORECASE
        )
        if input_match:
            try:
                action_params = json.loads(input_match.group(1))
            except json.JSONDecodeError:
                pass

        return action_name, action_params

    @staticmethod
    def _compute_similarity(
        orig_action: str,
        orig_params: Dict[str, Any],
        clean_action: Optional[str],
        clean_params: Dict[str, Any],
    ) -> float:
        """Compute a simple similarity score between two actions.

        Scoring:
        - 0.5 weight for action name match.
        - 0.5 weight for parameter overlap (Jaccard-like).

        Returns a float in [0, 1].
        """
        score = 0.0

        # Action name match
        if clean_action and orig_action.lower() == clean_action.lower():
            score += 0.5
        elif clean_action is None:
            # Could not parse clean action -- penalise slightly
            score += 0.2

        # Parameter similarity
        orig_keys = set(orig_params.keys())
        clean_keys = set(clean_params.keys())

        if not orig_keys and not clean_keys:
            # Both empty -- consider them the same
            score += 0.5
        elif orig_keys or clean_keys:
            # Key overlap
            intersection = orig_keys & clean_keys
            union = orig_keys | clean_keys
            key_sim = len(intersection) / len(union) if union else 0.0

            # Value overlap for shared keys
            value_matches = 0
            for key in intersection:
                if str(orig_params.get(key)) == str(clean_params.get(key)):
                    value_matches += 1
            value_sim = (
                value_matches / len(intersection) if intersection else 0.0
            )

            param_sim = 0.5 * key_sim + 0.5 * value_sim
            score += 0.5 * param_sim

        return score
