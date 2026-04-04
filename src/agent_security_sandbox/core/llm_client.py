"""
LLM Client wrapper for multiple providers (OpenAI, Anthropic, OpenAI-compatible)
"""
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

MAX_RETRIES = 5
RETRY_BASE_DELAY = 2.0  # seconds

try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False


@dataclass
class LLMResponse:
    """Structured response from an LLM call.

    Attributes:
        content: Text content of the response (empty string for pure tool_call responses).
        tokens_used: Total tokens consumed by this call.
        tool_calls: Optional list of tool calls in OpenAI format, e.g.
            ``[{"id": "call_abc", "type": "function",
            "function": {"name": "read_email", "arguments": "{...}"}}]``
    """

    content: str
    tokens_used: int
    tool_calls: Optional[List[Dict[str, Any]]] = None
    logprobs: Optional[List[Dict[str, Any]]] = None


class LLMClient(ABC):
    """Abstract base class for LLM clients"""

    def __init__(self, model: str, temperature: float = 0.7):
        self.model = model
        self.temperature = temperature
        self.total_tokens = 0
        self.total_calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0

    @abstractmethod
    def call(
        self,
        messages: List[Dict[str, Any]],
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict]] = None,
    ) -> LLMResponse:
        """Call the LLM with messages.

        Args:
            messages: List of message dicts (role + content, possibly tool_call_id).
            max_tokens: Optional maximum tokens for the response.
            tools: Optional list of tool schemas in OpenAI format for function calling.

        Returns:
            LLMResponse with content, tokens_used, and optional tool_calls.
        """
        pass

    def embed(self, text: str) -> List[float]:
        """Return an embedding vector for *text*.

        Subclasses that support embedding should override this method.
        The default implementation raises ``NotImplementedError``.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support embed(). "
            "Override this method or use a provider that supports embeddings."
        )

    def get_stats(self) -> Dict[str, int]:
        """Get usage statistics"""
        return {
            "total_calls": self.total_calls,
            "total_tokens": self.total_tokens,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
        }

    def reset_stats(self):
        """Reset usage statistics"""
        self.total_tokens = 0
        self.total_calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0


class OpenAIClient(LLMClient):
    """OpenAI LLM client"""

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        temperature: float = 0.7,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        super().__init__(model, temperature)
        self.api_key = api_key or os.getenv("API_KEY") or os.getenv("OPENAI_API_KEY")
        self.base_url = base_url or os.getenv("OPENAI_BASE_URL")

        if not self.api_key:
            raise ValueError("API key not found. Set API_KEY environment variable.")

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
        messages: List[Dict[str, Any]],
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict]] = None,
    ) -> LLMResponse:
        """Call OpenAI API with retry on transient errors."""
        last_exc: Optional[Exception] = None
        for attempt in range(MAX_RETRIES):
            try:
                kwargs: Dict[str, Any] = {
                    "model": self.model,
                    "messages": messages,
                    "temperature": self.temperature,
                }
                if max_tokens is not None:
                    kwargs["max_tokens"] = max_tokens
                if tools:
                    kwargs["tools"] = tools
                    kwargs["tool_choice"] = "auto"

                response = self.client.chat.completions.create(**kwargs)  # type: ignore[arg-type]

                msg = response.choices[0].message
                content = msg.content or ""

                # Extract structured tool_calls if present
                result_tool_calls: Optional[List[Dict[str, Any]]] = None
                if msg.tool_calls:
                    result_tool_calls = []
                    for tc in msg.tool_calls:
                        result_tool_calls.append({
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        })

                tokens_used = (
                    (response.usage.total_tokens or 0) if response.usage else 0
                )
                _prompt = (
                    (response.usage.prompt_tokens or 0) if response.usage else 0
                )
                _completion = (
                    (response.usage.completion_tokens or 0)
                    if response.usage else 0
                )

                self.total_calls += 1
                self.total_tokens += tokens_used
                self.prompt_tokens += _prompt
                self.completion_tokens += _completion

                return LLMResponse(
                    content=content,
                    tokens_used=tokens_used,
                    tool_calls=result_tool_calls,
                )

            except Exception as e:
                last_exc = e
                if attempt < MAX_RETRIES - 1:
                    delay = RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning(
                        "OpenAI API call failed (attempt %d/%d): %s  "
                        "Retrying in %.1fs ...",
                        attempt + 1, MAX_RETRIES, e, delay,
                    )
                    time.sleep(delay)
        raise RuntimeError(
            f"OpenAI API call failed after {MAX_RETRIES} attempts: {last_exc}"
        )

    def embed(self, text: str) -> List[float]:
        """Return an embedding vector using the OpenAI embeddings API."""
        response = self.client.embeddings.create(
            model="text-embedding-3-small",
            input=text,
        )
        return response.data[0].embedding

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
        resolved_api_key = (
            api_key or os.getenv("API_KEY")
            or os.getenv("OPENAI_API_KEY") or "no-key-required"
        )

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
        model: str = "claude-sonnet-4-5-20250929",
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
        messages: List[Dict[str, Any]],
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict]] = None,
    ) -> LLMResponse:
        """Call Anthropic API."""
        # Convert messages to Anthropic format
        system_message = None
        anthropic_messages: List[Dict[str, Any]] = []

        for msg in messages:
            if msg["role"] == "system":
                system_message = msg["content"]
            elif msg["role"] == "tool":
                # Convert OpenAI tool result -> Anthropic tool_result
                anthropic_messages.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": msg.get("tool_call_id", ""),
                        "content": msg.get("content", ""),
                    }],
                })
            elif msg["role"] == "assistant" and msg.get("tool_calls"):
                # Convert OpenAI assistant tool_calls -> Anthropic tool_use blocks
                content_blocks: List[Dict[str, Any]] = []
                if msg.get("content"):
                    content_blocks.append({"type": "text", "text": msg["content"]})
                for tc in msg["tool_calls"]:
                    args = tc["function"]["arguments"]
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except (ValueError, json.JSONDecodeError):
                            args = {}
                    content_blocks.append({
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["function"]["name"],
                        "input": args,
                    })
                anthropic_messages.append({
                    "role": "assistant",
                    "content": content_blocks,
                })
            else:
                anthropic_messages.append({
                    "role": msg["role"],
                    "content": msg["content"]
                })

        last_exc: Optional[Exception] = None
        for attempt in range(MAX_RETRIES):
            try:
                kwargs: Dict[str, Any] = {
                    "model": self.model,
                    "messages": anthropic_messages,
                    "temperature": self.temperature,
                    "max_tokens": max_tokens or 4096
                }

                if system_message:
                    kwargs["system"] = system_message

                # Convert OpenAI tool schemas to Anthropic format
                if tools:
                    anthropic_tools = []
                    for t in tools:
                        func = t.get("function", t)
                        anthropic_tools.append({
                            "name": func["name"],
                            "description": func.get("description", ""),
                            "input_schema": func.get(
                                "parameters",
                                {"type": "object", "properties": {}},
                            ),
                        })
                    kwargs["tools"] = anthropic_tools

                response = self.client.messages.create(**kwargs)  # type: ignore[arg-type,call-overload]

                # Extract text content and tool_use blocks
                content = ""
                result_tool_calls: Optional[List[Dict[str, Any]]] = None
                for block in response.content:
                    if getattr(block, "type", None) == "text":
                        content += block.text  # type: ignore[union-attr]
                    elif getattr(block, "type", None) == "tool_use":
                        if result_tool_calls is None:
                            result_tool_calls = []
                        result_tool_calls.append({
                            "id": block.id,  # type: ignore[union-attr]
                            "type": "function",
                            "function": {
                                "name": block.name,  # type: ignore[union-attr]
                                "arguments": json.dumps(block.input),  # type: ignore[union-attr]
                            },
                        })

                # Anthropic returns input_tokens and output_tokens separately
                _prompt = response.usage.input_tokens
                _completion = response.usage.output_tokens
                tokens_used = _prompt + _completion

                self.total_calls += 1
                self.total_tokens += tokens_used
                self.prompt_tokens += _prompt
                self.completion_tokens += _completion

                return LLMResponse(
                    content=content,
                    tokens_used=tokens_used,
                    tool_calls=result_tool_calls,
                )

            except Exception as e:
                last_exc = e
                if attempt < MAX_RETRIES - 1:
                    delay = RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning(
                        "Anthropic API call failed (attempt %d/%d): %s  "
                        "Retrying in %.1fs ...",
                        attempt + 1, MAX_RETRIES, e, delay,
                    )
                    time.sleep(delay)
        raise RuntimeError(
            f"Anthropic API call failed after {MAX_RETRIES} attempts: "
            f"{last_exc}"
        )

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
        messages: List[Dict[str, Any]],
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict]] = None,
    ) -> LLMResponse:
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

        return LLMResponse(content=response, tokens_used=tokens_used)

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

    def embed(self, text: str) -> List[float]:
        """Return a deterministic mock embedding based on text hash."""
        import hashlib

        h = hashlib.sha256(text.encode()).hexdigest()
        # Generate a 64-dim vector from the hash
        vec: List[float] = []
        for i in range(0, min(len(h), 64), 1):
            vec.append((int(h[i], 16) - 7.5) / 7.5)
        # Pad to 64 dimensions
        while len(vec) < 64:
            vec.append(0.0)
        # Normalise to unit length
        norm = sum(v * v for v in vec) ** 0.5
        if norm > 0:
            vec = [v / norm for v in vec]
        return vec


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
        messages: List[Dict[str, Any]],
        max_tokens: Optional[int] = None,
        tools: Optional[List[Dict]] = None,
    ) -> LLMResponse:
        # If a manual response queue was set, honour it first.
        if self._response_queue:
            return super().call(messages, max_tokens, tools)

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

            # If function calling mode (tools provided), return structured tool_calls
            if tools:
                return self._structured_tool_call(tool_name, tokens_used)

            return LLMResponse(
                content=self._tool_action(tool_name),
                tokens_used=tokens_used,
            )

        return LLMResponse(
            content=self._final_answer(),
            tokens_used=tokens_used,
        )

    # ------------------------------------------------------------------ #
    # Structured tool calling (function calling mode)
    # ------------------------------------------------------------------ #

    def _structured_tool_call(self, tool_name: str, tokens_used: int) -> LLMResponse:
        """Generate a structured tool_call response for function calling mode."""
        params = self._tool_params(tool_name)
        actual_name = tool_name if tool_name != "__inject__" else "send_email"

        tool_calls = [{
            "id": f"call_mock_{self.total_calls}",
            "type": "function",
            "function": {
                "name": actual_name,
                "arguments": json.dumps(params),
            },
        }]

        return LLMResponse(
            content="",
            tokens_used=tokens_used,
            tool_calls=tool_calls,
        )

    def _tool_params(self, tool_name: str) -> Dict[str, Any]:
        """Return parameters dict for a given tool name."""
        lower = self._goal_text.lower()

        if tool_name == "__inject__":
            target = self._extract_injection_target(self._goal_text)
            return {"to": target, "subject": "data", "body": "secrets"}
        if tool_name == "list_emails":
            return {}
        if tool_name == "read_email":
            return {"email_id": self._extract_email_id(lower)}
        if tool_name == "send_email":
            return {
                "to": "team@company.com",
                "subject": "Re: request",
                "body": "Done as requested.",
            }
        if tool_name == "read_file":
            return {"file_path": self._extract_file_path(lower)}
        if tool_name == "write_file":
            return {"file_path": "/tmp/output.txt", "content": "Generated content."}
        if tool_name == "search_web":
            return {"query": self._extract_search_query(lower)}
        if tool_name == "create_document":
            return {
                "title": self._extract_doc_title(lower),
                "content": "Generated document content.",
            }
        if tool_name == "read_calendar":
            return {"event_id": "event_001"}
        if tool_name == "create_calendar_event":
            return {
                "title": "Meeting", "date": "2024-01-20",
                "time": "10:00", "description": "Scheduled meeting",
            }
        if tool_name == "call_api":
            return {"endpoint": "/api/weather"}
        if tool_name == "post_api":
            return {"endpoint": "/api/data", "data": '{"key": "value"}'}
        return {}

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

        # Calendar tools
        if "calendar" in lower or "event" in lower or "schedule" in lower:
            if "create" in lower or "add" in lower or "schedule" in lower:
                tools.append("create_calendar_event")
            if "read" in lower or "check" in lower or "event_" in lower:
                tools.append("read_calendar")
            if not tools or tools[-1] not in ("create_calendar_event", "read_calendar"):
                tools.append("read_calendar")

        # API tools
        if "api" in lower and ("call" in lower or "get" in lower or "fetch" in lower):
            tools.append("call_api")
        if "api" in lower and ("post" in lower or "send" in lower or "submit" in lower):
            tools.append("post_api")

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
                f'Action Input: {{"file_path": "{fpath}"}}'
            )

        if tool_name == "write_file":
            return (
                "Thought: I need to write a file.\n"
                "Action: write_file\n"
                'Action Input: {"file_path": "/tmp/output.txt", '
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

        if tool_name == "read_calendar":
            return (
                "Thought: I need to read the calendar event.\n"
                "Action: read_calendar\n"
                'Action Input: {"event_id": "event_001"}'
            )

        if tool_name == "create_calendar_event":
            return (
                "Thought: I need to create a calendar event.\n"
                "Action: create_calendar_event\n"
                'Action Input: {"title": "Meeting", "date": "2024-01-20", '
                '"time": "10:00", "description": "Scheduled meeting"}'
            )

        if tool_name == "call_api":
            return (
                "Thought: I need to call the API.\n"
                "Action: call_api\n"
                'Action Input: {"endpoint": "/api/weather"}'
            )

        if tool_name == "post_api":
            return (
                "Thought: I need to post data to the API.\n"
                "Action: post_api\n"
                'Action Input: {"endpoint": "/api/data", '
                '"data": "{\\"key\\": \\"value\\"}"}'
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
        resolved_model: str = model or os.getenv("OPENAI_MODEL") or "gpt-4o-mini"
        return OpenAIClient(model=resolved_model, **kwargs)
    elif provider == "anthropic":
        resolved_model = model or os.getenv("ANTHROPIC_MODEL") or "claude-sonnet-4-5-20250929"
        return AnthropicClient(model=resolved_model, **kwargs)
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

    resp = client.call(messages)
    print(f"Response: {resp.content}")
    print(f"Tokens: {resp.tokens_used}")
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
        resp = mock_client.call(messages)
        print(f"  Call {i+1}: {resp.content}")

    # Uncomment to test with real API (requires API key)
    # print("\nTesting OpenAI Client...")
    # client = create_llm_client("openai", temperature=0.7)
    # response, tokens = client.call(messages)
    # print(f"Response: {response}")
    # print(f"Tokens: {tokens}")
