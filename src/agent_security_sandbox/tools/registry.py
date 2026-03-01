"""
Tool Registry - Centralized management of all tools
"""
from pathlib import Path
from typing import Dict, List, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from .base import Tool
from .email import ListEmailsTool, ReadEmailTool, SendEmailTool
from .file import CreateDocumentTool, ReadFileTool, WriteFileTool
from .search import SearchWebTool


class ToolRegistry:
    """Registry for managing all available tools"""

    def __init__(self, config_path: Optional[str] = None):
        self.tools: Dict[str, Tool] = {}
        self.config_path = config_path

        # Register default tools
        self._register_default_tools()

        # Load additional tools from config if provided or default exists
        if not config_path:
            repo_root = Path(__file__).resolve().parents[2]
            default_config = repo_root / "config" / "tools.yaml"
            if default_config.exists():
                self.config_path = str(default_config)

        if self.config_path:
            self._load_from_config(self.config_path)

    def _register_default_tools(self):
        """Register default built-in tools"""
        # Email tools
        self.register(ReadEmailTool())
        self.register(SendEmailTool())
        self.register(ListEmailsTool())

        # Search tools
        self.register(SearchWebTool())

        # File tools
        self.register(ReadFileTool())
        self.register(WriteFileTool())
        self.register(CreateDocumentTool())

    def _load_from_config(self, config_path: str):
        """Load tool configurations from YAML file"""
        if not YAML_AVAILABLE:
            print("Warning: PyYAML not installed. Cannot load config from file.")
            return

        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            # Update tool configurations (e.g., whitelists, enabled status)
            for tool_config in config.get('tools', []):
                tool_name = tool_config['name']
                if tool_name in self.tools:
                    tool = self.tools[tool_name]

                    # Update enabled status
                    tool.metadata.enabled = tool_config.get('enabled', True)

                    # Update whitelists if present
                    if 'parameters' in tool_config:
                        for param_name, param_config in tool_config['parameters'].items():
                            if param_name in tool.metadata.parameters:
                                if 'whitelist' in param_config:
                                    param = tool.metadata.parameters[param_name]
                                    param.whitelist = param_config['whitelist']

        except Exception as e:
            print(f"Warning: Failed to load config from {config_path}: {e}")

    def register(self, tool: Tool):
        """Register a tool"""
        self.tools[tool.metadata.name] = tool

    def get_tool(self, name: str) -> Optional[Tool]:
        """Get a tool by name"""
        return self.tools.get(name)

    def get_enabled_tools(self) -> Dict[str, Tool]:
        """Get all enabled tools"""
        return {
            name: tool
            for name, tool in self.tools.items()
            if tool.metadata.enabled
        }

    def get_tools_by_risk(self, max_risk: str) -> Dict[str, Tool]:
        """
        Get tools up to a certain risk level.

        Args:
            max_risk: "low", "medium", "high", or "critical"
        """
        risk_order = ["low", "medium", "high", "critical"]
        max_risk_index = risk_order.index(max_risk.lower())

        return {
            name: tool
            for name, tool in self.tools.items()
            if tool.metadata.enabled and
            risk_order.index(tool.metadata.risk_level.value) <= max_risk_index
        }

    def list_tools(self) -> List[str]:
        """List all registered tool names"""
        return list(self.tools.keys())

    def list_enabled_tools(self) -> List[str]:
        """List enabled tool names"""
        return [
            name for name, tool in self.tools.items()
            if tool.metadata.enabled
        ]

    def get_function_schemas(self, enabled_only: bool = True) -> List[Dict]:
        """
        Get OpenAI function calling schemas for all tools.

        Args:
            enabled_only: If True, only return schemas for enabled tools
        """
        tools = self.get_enabled_tools() if enabled_only else self.tools

        return [
            tool.to_function_schema()
            for tool in tools.values()
        ]

    def execute_tool(self, tool_name: str, **kwargs) -> Dict:
        """
        Execute a tool by name.

        Args:
            tool_name: Name of the tool to execute
            **kwargs: Tool parameters

        Returns:
            Tool execution result
        """
        tool = self.get_tool(tool_name)

        if not tool:
            return {
                "status": "error",
                "message": f"Tool '{tool_name}' not found"
            }

        if not tool.metadata.enabled:
            return {
                "status": "error",
                "message": f"Tool '{tool_name}' is disabled"
            }

        try:
            result = tool.execute(**kwargs)
            result["tool_name"] = tool_name
            result["params"] = kwargs
            return result
        except Exception as e:
            return {
                "status": "error",
                "message": f"Tool execution failed: {str(e)}",
                "tool_name": tool_name,
                "params": kwargs
            }

    def get_tool_info(self, tool_name: str) -> Optional[Dict]:
        """Get detailed information about a tool"""
        tool = self.get_tool(tool_name)
        if not tool:
            return None

        return {
            "name": tool.metadata.name,
            "description": tool.metadata.description,
            "risk_level": tool.metadata.risk_level.value,
            "side_effect": tool.metadata.side_effect,
            "data_access": tool.metadata.data_access,
            "enabled": tool.metadata.enabled,
            "parameters": {
                param_name: {
                    "type": param.type,
                    "required": param.required,
                    "description": param.description,
                    "whitelist": param.whitelist
                }
                for param_name, param in tool.metadata.parameters.items()
            }
        }


# Example usage
if __name__ == "__main__":
    # Create registry
    print("Creating Tool Registry...")
    registry = ToolRegistry()

    # List all tools
    print(f"\nAll tools: {registry.list_tools()}")
    print(f"Enabled tools: {registry.list_enabled_tools()}")

    # Get low and medium risk tools
    safe_tools = registry.get_tools_by_risk("medium")
    print(f"\nLow-Medium risk tools: {list(safe_tools.keys())}")

    # Execute a tool
    print("\nExecuting read_email tool...")
    result = registry.execute_tool("read_email", email_id="email_001")
    print(f"Result: {result}")

    # Test sending email (should fail whitelist check)
    print("\nExecuting send_email with invalid recipient...")
    result = registry.execute_tool(
        "send_email",
        to="attacker@evil.com",
        subject="Test",
        body="Test body"
    )
    print(f"Result: {result}")

    # Get tool info
    print("\nGetting send_email tool info...")
    info = registry.get_tool_info("send_email")
    print(f"Info: {info}")

    # Get function schemas for OpenAI
    print("\nFunction schemas for OpenAI:")
    schemas = registry.get_function_schemas()
    print(f"Number of schemas: {len(schemas)}")
    print(f"First schema: {schemas[0]}")
