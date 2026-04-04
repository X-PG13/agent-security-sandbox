"""
Base classes for tools with risk metadata
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Tool risk levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolParameter(BaseModel):
    """Tool parameter definition"""
    name: str
    type: str  # "string", "int", "bool", etc.
    required: bool = True
    description: str = ""
    whitelist: Optional[List[str]] = None


class ToolMetadata(BaseModel):
    """Tool metadata for risk assessment and policy enforcement"""
    name: str
    description: str
    risk_level: RiskLevel
    side_effect: bool = Field(
        description="Whether the tool has external side effects"
    )
    data_access: str = Field(
        description="Type of data accessed: public/private/system"
    )
    enabled: bool = True
    parameters: Dict[str, ToolParameter] = Field(default_factory=dict)


class Tool(ABC):
    """Base class for all tools"""

    def __init__(self, metadata: ToolMetadata):
        self.metadata = metadata

    @abstractmethod
    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the tool with given parameters.

        Returns:
            Dict with keys: status, data/message, etc.
        """
        pass

    def validate_params(self, **kwargs) -> tuple[bool, str]:
        """
        Validate parameters against metadata.

        Returns:
            (is_valid, error_message)
        """
        # Check required parameters
        for param_name, param_def in self.metadata.parameters.items():
            if param_def.required and param_name not in kwargs:
                return False, f"Missing required parameter: {param_name}"

        # Check whitelists
        for param_name, value in kwargs.items():
            p_def = self.metadata.parameters.get(param_name)
            if p_def and p_def.whitelist:
                if value not in p_def.whitelist:
                    return (
                        False,
                        f"Parameter {param_name}='{value}' "
                        f"not in whitelist: {p_def.whitelist}",
                    )

        return True, ""

    def to_function_schema(self) -> Dict[str, Any]:
        """
        Convert tool to OpenAI function calling schema.
        """
        properties = {}
        required = []

        for param_name, param_def in self.metadata.parameters.items():
            properties[param_name] = {
                "type": param_def.type,
                "description": param_def.description
            }
            if param_def.required:
                required.append(param_name)

        return {
            "name": self.metadata.name,
            "description": self.metadata.description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        }

    def __str__(self) -> str:
        return f"{self.metadata.name} (risk: {self.metadata.risk_level})"


class ToolResult(BaseModel):
    """Standardized tool execution result"""
    status: str = Field(description="success or error")
    data: Optional[Any] = None
    message: str = ""
    tool_name: str = ""
    params: Dict[str, Any] = Field(default_factory=dict)


# Helper function to create tool metadata from config
def create_tool_metadata(config: Dict[str, Any]) -> ToolMetadata:
    """Create ToolMetadata from YAML config dict"""
    params = {}
    for param_name, param_config in config.get("parameters", {}).items():
        params[param_name] = ToolParameter(
            name=param_name,
            type=param_config.get("type", "string"),
            required=param_config.get("required", True),
            description=param_config.get("description", ""),
            whitelist=param_config.get("whitelist")
        )

    return ToolMetadata(
        name=config["name"],
        description=config["description"],
        risk_level=RiskLevel(config["risk_level"]),
        side_effect=config.get("side_effect", False),
        data_access=config.get("data_access", "public"),
        enabled=config.get("enabled", True),
        parameters=params
    )
