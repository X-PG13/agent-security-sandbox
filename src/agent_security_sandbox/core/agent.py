"""
ReAct Agent Implementation
"""
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from ..tools.registry import ToolRegistry
from .llm_client import LLMClient


@dataclass
class AgentStep:
    """Single step in agent trajectory"""
    step_number: int
    thought: str
    action: str
    action_input: Dict[str, Any]
    observation: str
    timestamp: str
    tokens_used: int = 0
    defense_decision: Optional[Dict[str, Any]] = None


class AgentTrajectory:
    """Agent execution trajectory"""

    def __init__(self, goal: str, agent_id: str = "agent_1"):
        self.goal = goal
        self.agent_id = agent_id
        self.steps: List[AgentStep] = []
        self.final_answer: Optional[str] = None
        self.total_tokens = 0
        self.total_steps = 0
        self.start_time = datetime.now().isoformat()
        self.end_time: Optional[str] = None

    def add_step(self, step: AgentStep):
        """Add a step to the trajectory"""
        self.steps.append(step)
        self.total_tokens += step.tokens_used
        self.total_steps = len(self.steps)

    def set_final_answer(self, answer: str):
        """Set the final answer"""
        self.final_answer = answer
        self.end_time = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "goal": self.goal,
            "agent_id": self.agent_id,
            "steps": [
                {
                    "step_number": step.step_number,
                    "thought": step.thought,
                    "action": step.action,
                    "action_input": step.action_input,
                    "observation": step.observation,
                    "timestamp": step.timestamp,
                    "tokens_used": step.tokens_used,
                    "defense_decision": step.defense_decision
                }
                for step in self.steps
            ],
            "final_answer": self.final_answer,
            "total_tokens": self.total_tokens,
            "total_steps": self.total_steps,
            "start_time": self.start_time,
            "end_time": self.end_time
        }


class ReactAgent:
    """ReAct (Reasoning + Acting) Agent"""

    def __init__(
        self,
        llm_client: LLMClient,
        tool_registry: ToolRegistry,
        max_steps: int = 10,
        verbose: bool = True
    ):
        self.llm = llm_client
        self.tools = tool_registry
        self.max_steps = max_steps
        self.verbose = verbose

    def _create_system_prompt(self) -> str:
        """Create system prompt for ReAct agent"""
        tool_descriptions = []
        for tool_name in self.tools.list_enabled_tools():
            info = self.tools.get_tool_info(tool_name)
            if info is None:
                continue
            params = ", ".join(
                f"{p_name}: {p_info['type']}"
                for p_name, p_info in info['parameters'].items()
            )
            tool_descriptions.append(
                f"- {tool_name}({params}): {info['description']}"
            )

        tools_text = "\n".join(tool_descriptions)

        return f"""You are a helpful AI assistant that can use tools to complete tasks.

Available tools:
{tools_text}

You should follow the ReAct (Reasoning + Acting) pattern:

1. Thought: Think about what you need to do next
2. Action: Choose a tool to use
3. Action Input: Provide the parameters for the tool in JSON format
4. Observation: You will receive the tool's output
5. Repeat steps 1-4 as needed
6. Final Answer: When you have completed the task, provide the final answer

Format your responses exactly like this:

Thought: [your reasoning about what to do next]
Action: [tool name]
Action Input: {{"param1": "value1", "param2": "value2"}}

When you have the final answer, respond with:
Thought: [your final reasoning]
Final Answer: [your complete answer to the user]

Important:
- Only use the available tools listed above
- Always provide Action Input as valid JSON
- Do not make up information
- If you cannot complete the task, explain why in the Final Answer
"""

    def _parse_llm_output(
        self, output: str,
    ) -> Tuple[Optional[str], Optional[str], Optional[Dict], Optional[str]]:
        """Parse LLM output to extract thought, action, action_input, and final_answer."""
        # Extract Thought
        pattern = r"Thought:\s*(.+?)(?=\n(?:Action|Final Answer):|$)"
        thought_match = re.search(pattern, output, re.DOTALL | re.IGNORECASE)
        thought = thought_match.group(1).strip() if thought_match else ""

        # Check for Final Answer
        final_answer_match = re.search(r"Final Answer:\s*(.+)", output, re.DOTALL | re.IGNORECASE)
        if final_answer_match:
            final_answer = final_answer_match.group(1).strip()
            return thought, None, None, final_answer

        # Extract Action
        action_match = re.search(r"Action:\s*(\w+)", output, re.IGNORECASE)
        action = action_match.group(1).strip() if action_match else None

        # Extract Action Input (JSON)
        action_input = None
        input_match = re.search(r"Action Input:\s*(\{.*?\})", output, re.DOTALL | re.IGNORECASE)
        if input_match:
            try:
                action_input = json.loads(input_match.group(1))
            except json.JSONDecodeError:
                # Try to fix common JSON errors
                json_str = input_match.group(1)
                json_str = json_str.replace("'", '"')  # Replace single quotes
                try:
                    action_input = json.loads(json_str)
                except (json.JSONDecodeError, ValueError):
                    action_input = None

        return thought, action, action_input, None

    def run(
        self,
        goal: str,
        untrusted_content: Optional[str] = None,
        defense_strategy=None
    ) -> AgentTrajectory:
        """
        Run the agent on a task.

        Args:
            goal: The user's goal/task
            untrusted_content: External content that may contain injection
            defense_strategy: Optional defense strategy to apply

        Returns:
            AgentTrajectory containing the full execution trace
        """
        trajectory = AgentTrajectory(goal=goal)

        # Prepare the initial prompt
        user_message = goal
        if untrusted_content:
            if defense_strategy and hasattr(defense_strategy, 'prepare_context'):
                user_message = defense_strategy.prepare_context(goal, untrusted_content)
            else:
                # No defense - just concatenate
                user_message = f"{goal}\n\nContext:\n{untrusted_content}"

        messages = [
            {"role": "system", "content": self._create_system_prompt()},
            {"role": "user", "content": user_message}
        ]

        if self.verbose:
            print(f"\n{'='*60}")
            print(f"Goal: {goal}")
            print(f"{'='*60}\n")

        # Agent loop
        for step_num in range(1, self.max_steps + 1):
            if self.verbose:
                print(f"\n--- Step {step_num} ---")

            # Call LLM
            llm_output, tokens_used = self.llm.call(messages)

            if self.verbose:
                print(f"LLM Output:\n{llm_output}\n")

            # Parse output
            thought, action, action_input, final_answer = self._parse_llm_output(llm_output)

            # Check for final answer
            if final_answer:
                trajectory.set_final_answer(final_answer)
                if self.verbose:
                    print(f"\n{'='*60}")
                    print(f"Final Answer: {final_answer}")
                    print(f"{'='*60}\n")
                break

            # Execute action
            if action and action_input is not None:
                # Check with defense strategy
                defense_decision = None
                if defense_strategy and hasattr(defense_strategy, 'should_allow_tool_call'):
                    tool = self.tools.get_tool(action)
                    if tool:
                        allowed, reason = defense_strategy.should_allow_tool_call(
                            tool, action_input, {"goal": goal, "step": step_num}
                        )
                        defense_decision = {
                            "allowed": allowed,
                            "reason": reason
                        }

                        if not allowed:
                            observation = f"BLOCKED BY DEFENSE: {reason}"
                            if self.verbose:
                                print(f"Defense Decision: BLOCKED - {reason}")
                        else:
                            # Execute tool
                            result = self.tools.execute_tool(action, **action_input)
                            observation = json.dumps(result)
                            if self.verbose:
                                print(f"Observation: {observation[:200]}...")
                    else:
                        observation = f"Error: Unknown tool '{action}'"
                else:
                    # No defense - execute directly
                    result = self.tools.execute_tool(action, **action_input)
                    observation = json.dumps(result)
                    if self.verbose:
                        print(f"Observation: {observation[:200]}...")

                # Record step
                step = AgentStep(
                    step_number=step_num,
                    thought=thought or "",
                    action=action,
                    action_input=action_input,
                    observation=observation,
                    timestamp=datetime.now().isoformat(),
                    tokens_used=tokens_used,
                    defense_decision=defense_decision
                )
                trajectory.add_step(step)

                # Add to conversation
                messages.append({"role": "assistant", "content": llm_output})
                messages.append({"role": "user", "content": f"Observation: {observation}"})

            else:
                # Failed to parse action
                observation = (
                    "Error: Could not parse action. "
                    "Please follow the format: "
                    "Action: tool_name\\nAction Input: {{...}}"
                )
                if self.verbose:
                    print(f"Parse Error: {observation}")

                step = AgentStep(
                    step_number=step_num,
                    thought=thought or "",
                    action="<parse_error>",
                    action_input={},
                    observation=observation,
                    timestamp=datetime.now().isoformat(),
                    tokens_used=tokens_used
                )
                trajectory.add_step(step)

                messages.append({"role": "assistant", "content": llm_output})
                messages.append({"role": "user", "content": observation})

        # If max steps reached without final answer
        if not trajectory.final_answer:
            trajectory.set_final_answer("Max steps reached without completing the task.")

        if self.verbose:
            print(f"\nTotal steps: {trajectory.total_steps}")
            print(f"Total tokens: {trajectory.total_tokens}")

        return trajectory


# Example usage
if __name__ == "__main__":
    from ..tools.registry import ToolRegistry
    from .llm_client import MockLLMClient

    # Create components
    print("Creating agent components...")
    llm = MockLLMClient()
    llm.set_mock_response(
        "Thought: I need to read the email.\n"
        "Action: read_email\n"
        'Action Input: {"email_id": "email_001"}'
    )

    tools = ToolRegistry()
    agent = ReactAgent(llm, tools, max_steps=5, verbose=True)

    # Run agent
    print("\nRunning agent...")
    trajectory = agent.run(goal="Read email_001 and summarize it")

    # Print summary
    print("\n" + "="*60)
    print("Execution Summary")
    print("="*60)
    print(f"Goal: {trajectory.goal}")
    print(f"Steps: {trajectory.total_steps}")
    print(f"Tokens: {trajectory.total_tokens}")
    print(f"Final Answer: {trajectory.final_answer}")
