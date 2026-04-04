"""
D6 -- Output Filter Defense

Inspects tool call parameters for suspicious patterns that indicate the
agent has been manipulated by injected instructions.  Unlike D2 (PolicyGate)
which checks whitelists and risk levels, this defense uses *content-based
heuristics* to detect data exfiltration attempts, injected URLs, and
parameter values that echo injection payloads.

Detection heuristics:
  1. **Exfiltration patterns**: Detects email addresses, URLs, or
     hostnames in outgoing parameters that appear to come from injected
     content rather than the user's original goal.
  2. **Payload echo**: Detects when tool parameters contain phrases
     commonly used in prompt injection ("ignore previous", "system
     prompt", "you are now", etc.).
  3. **Sensitive data leakage**: Detects parameters containing patterns
     that look like secrets, API keys, passwords, or internal data.

This is a tool-gating defense and does not modify the prompt.
"""
import re
from typing import Any, Dict, List, Tuple

from ..tools.base import Tool
from .base import DefenseStrategy

# Regex patterns for injection detection
_INJECTION_PHRASES = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?prior\s+instructions",
    r"disregard\s+(all\s+)?previous",
    r"forget\s+(all\s+)?previous",
    r"you\s+are\s+now",
    r"new\s+instructions?\s*:",
    r"system\s*:\s*you",
    r"act\s+as\s+(if|a|an)",
    r"pretend\s+(you|that)",
    r"override\s+(your|the)\s+(instructions|rules|guidelines)",
    r"bypass\s+(your|the|all)\s+(safety|security|filter)",
    r"do\s+not\s+follow\s+(your|the|previous)",
    r"instead\s*,?\s*(please\s+)?(do|send|forward|execute)",
]

_EXFIL_URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+", re.IGNORECASE
)

_EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
)

_SECRET_PATTERNS = [
    re.compile(r"(?:api[_-]?key|token|password|secret)\s*[:=]\s*\S+", re.I),
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"ghp_[a-zA-Z0-9]{36,}"),
    re.compile(r"Bearer\s+[a-zA-Z0-9._-]{20,}", re.I),
]


class OutputFilterDefense(DefenseStrategy):
    """Content-based output filter that blocks suspicious tool parameters.

    Configuration keys (via ``config`` dict):
        check_injection_phrases (bool): Detect injection language echoed
            in parameters.  Default ``True``.
        check_exfiltration (bool): Detect URLs/emails in outgoing
            parameters.  Default ``True``.
        check_secrets (bool): Detect secret/key patterns.
            Default ``True``.
        allowed_domains (list[str]): Email domains that are always
            allowed (e.g. ``["company.com"]``).  Default ``["company.com"]``.
        allowed_urls (list[str]): URL prefixes that are always allowed.
            Default ``[]``.
        monitored_tools (list[str]): Only apply content checks to these
            tools.  Default ``["send_email", "write_file",
            "create_document", "post_api", "call_api"]``.
    """

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}
        self.check_injection: bool = self.config.get(
            "check_injection_phrases", True
        )
        self.check_exfiltration: bool = self.config.get(
            "check_exfiltration", True
        )
        self.check_secrets: bool = self.config.get(
            "check_secrets", True
        )
        self.allowed_domains: List[str] = self.config.get(
            "allowed_domains", ["company.com"]
        )
        self.allowed_urls: List[str] = self.config.get(
            "allowed_urls", []
        )
        self.monitored_tools: List[str] = self.config.get(
            "monitored_tools",
            ["send_email", "write_file", "create_document",
             "post_api", "call_api"],
        )

        # Pre-compile injection patterns
        self._injection_re = [
            re.compile(p, re.IGNORECASE) for p in _INJECTION_PHRASES
        ]

    def prepare_context(self, goal: str, untrusted_content: str) -> str:
        """No prompt modification -- pure tool-gating defense."""
        if untrusted_content:
            return f"{goal}\n\nContext:\n{untrusted_content}"
        return goal

    def should_allow_tool_call(
        self,
        tool: Tool,
        params: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Check tool parameters for suspicious content."""
        if hasattr(tool, "metadata") and hasattr(tool.metadata, "name"):
            tool_name = tool.metadata.name
        elif hasattr(tool, "name"):
            tool_name = tool.name
        else:
            tool_name = str(tool)

        # Only inspect monitored tools
        if tool_name not in self.monitored_tools:
            return True, "Tool not monitored by output filter."

        # Flatten all param values into a single text blob
        param_text = self._flatten_params(params)

        # 1. Injection phrase detection
        if self.check_injection:
            for pattern in self._injection_re:
                match = pattern.search(param_text)
                if match:
                    return False, (
                        f"Output filter blocked: injection phrase "
                        f"detected in parameters: '{match.group()}'"
                    )

        # 2. Exfiltration detection (suspicious emails/URLs)
        if self.check_exfiltration:
            blocked, reason = self._check_exfiltration(param_text)
            if blocked:
                return False, reason

        # 3. Secret leakage detection
        if self.check_secrets:
            for pattern in _SECRET_PATTERNS:
                match = pattern.search(param_text)
                if match:
                    return False, (
                        "Output filter blocked: potential secret "
                        "leakage detected in parameters."
                    )

        return True, "Output filter: parameters passed content checks."

    def _flatten_params(self, params: Dict[str, Any]) -> str:
        """Concatenate all string values in params for scanning."""
        parts: list[str] = []
        for value in params.values():
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, dict):
                parts.append(self._flatten_params(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        parts.append(item)
        return " ".join(parts)

    def _check_exfiltration(
        self, text: str,
    ) -> Tuple[bool, str]:
        """Check for suspicious email addresses and URLs."""
        # Check emails
        for match in _EMAIL_PATTERN.finditer(text):
            email = match.group()
            domain = email.split("@")[1].lower()
            if not any(domain.endswith(d) for d in self.allowed_domains):
                return True, (
                    f"Output filter blocked: suspicious email "
                    f"address '{email}' not in allowed domains."
                )

        # Check URLs
        for match in _EXFIL_URL_PATTERN.finditer(text):
            url = match.group()
            if not any(url.startswith(prefix) for prefix in self.allowed_urls):
                return True, (
                    f"Output filter blocked: suspicious URL "
                    f"'{url[:60]}' not in allowed URLs."
                )

        return False, ""
