"""
Mock API Client Tools
"""
from typing import Any, Dict, Optional

from .base import RiskLevel, Tool, ToolMetadata, ToolParameter


class MockAPIDatabase:
    """Mock API responses database for testing"""

    def __init__(self):
        self.endpoints: Dict[str, Dict[str, Any]] = {
            "/api/weather": {
                "status_code": 200,
                "data": {"city": "San Francisco", "temperature": "65F", "condition": "sunny"},
            },
            "/api/stocks": {
                "status_code": 200,
                "data": {"ticker": "ACME", "price": 142.50, "change": "+2.3%"},
            },
            "/api/news": {
                "status_code": 200,
                "data": {
                    "headlines": [
                        "Tech stocks rally on AI optimism",
                        "New cybersecurity regulations proposed",
                    ]
                },
            },
        }
        self.posted_data: list = []

    def call_api(self, endpoint: str) -> Dict[str, Any]:
        """Simulate a GET API call"""
        if endpoint in self.endpoints:
            return self.endpoints[endpoint]
        return {"status_code": 404, "data": {"error": f"Endpoint {endpoint} not found"}}

    def post_api(self, endpoint: str, data: str) -> Dict[str, Any]:
        """Simulate a POST API call"""
        self.posted_data.append({"endpoint": endpoint, "data": data})
        return {"status_code": 200, "data": {"message": "Data posted successfully"}}


class CallAPITool(Tool):
    """Tool to call (GET) an API endpoint"""

    def __init__(self, db: Optional[MockAPIDatabase] = None):
        self._db = db or MockAPIDatabase()
        metadata = ToolMetadata(
            name="call_api",
            description="Call a GET API endpoint and return the response",
            risk_level=RiskLevel.LOW,
            side_effect=False,
            data_access="public",
            enabled=True,
            parameters={
                "endpoint": ToolParameter(
                    name="endpoint",
                    type="string",
                    required=True,
                    description="The API endpoint path (e.g., /api/weather)",
                )
            },
        )
        super().__init__(metadata)

    def execute(self, endpoint: str) -> Dict[str, Any]:
        is_valid, error_msg = self.validate_params(endpoint=endpoint)
        if not is_valid:
            return {"status": "error", "message": error_msg}

        result = self._db.call_api(endpoint)
        return {
            "status": "success",
            "data": result,
            "message": f"API call to {endpoint} completed",
        }


class PostAPITool(Tool):
    """Tool to POST data to an API endpoint"""

    def __init__(self, db: Optional[MockAPIDatabase] = None):
        self._db = db or MockAPIDatabase()
        metadata = ToolMetadata(
            name="post_api",
            description="Post data to an API endpoint",
            risk_level=RiskLevel.HIGH,
            side_effect=True,
            data_access="public",
            enabled=True,
            parameters={
                "endpoint": ToolParameter(
                    name="endpoint",
                    type="string",
                    required=True,
                    description="The API endpoint path",
                ),
                "data": ToolParameter(
                    name="data",
                    type="string",
                    required=True,
                    description="Data to post (JSON string)",
                ),
            },
        )
        super().__init__(metadata)

    def execute(self, endpoint: str, data: str) -> Dict[str, Any]:
        is_valid, error_msg = self.validate_params(endpoint=endpoint, data=data)
        if not is_valid:
            return {"status": "error", "message": error_msg}

        result = self._db.post_api(endpoint, data)
        return {
            "status": "success",
            "data": result,
            "message": f"Data posted to {endpoint} successfully",
        }
