"""
Mock Web Search Tool
"""
from typing import Any, Dict, Optional

from .base import RiskLevel, Tool, ToolMetadata, ToolParameter


class MockSearchDatabase:
    """Mock search results database"""

    def __init__(self):
        self.search_results = {
            "python": [
                {
                    "title": "Python.org",
                    "url": "https://python.org",
                    "snippet": "Official Python website",
                },
                {
                    "title": "Python Tutorial",
                    "url": "https://docs.python.org/tutorial",
                    "snippet": "Learn Python programming",
                },
            ],
            "security": [
                {
                    "title": "OWASP Top 10",
                    "url": "https://owasp.org",
                    "snippet": "Top security risks",
                },
                {
                    "title": "Security Best Practices",
                    "url": "https://security.com",
                    "snippet": "How to secure your applications",
                },
            ],
            "llm agent": [
                {
                    "title": "LangChain Documentation",
                    "url": "https://langchain.com",
                    "snippet": "Build LLM agents",
                },
                {
                    "title": "Agent Architecture",
                    "url": "https://agents.com",
                    "snippet": "Designing intelligent agents",
                },
            ],
            "default": [
                {
                    "title": "Generic Result",
                    "url": "https://example.com",
                    "snippet": "No specific results found",
                },
            ],
        }

    def search(self, query: str) -> list:
        """Search for query"""
        query_lower = query.lower()

        # Find matching results
        for key in self.search_results:
            if key in query_lower:
                return self.search_results[key]

        # Default results
        return self.search_results["default"]


class SearchWebTool(Tool):
    """Tool to search the web"""

    def __init__(self, db: Optional[MockSearchDatabase] = None):
        self._db = db or MockSearchDatabase()
        metadata = ToolMetadata(
            name="search_web",
            description="Search the web for information on a given query",
            risk_level=RiskLevel.LOW,
            side_effect=False,
            data_access="public",
            enabled=True,
            parameters={
                "query": ToolParameter(
                    name="query",
                    type="string",
                    required=True,
                    description="The search query"
                )
            }
        )
        super().__init__(metadata)

    def execute(self, query: str) -> Dict[str, Any]:
        """Execute web search"""
        # Validate parameters
        is_valid, error_msg = self.validate_params(query=query)
        if not is_valid:
            return {
                "status": "error",
                "message": error_msg
            }

        # Perform search
        results = self._db.search(query)

        return {
            "status": "success",
            "data": {
                "query": query,
                "results": results,
                "count": len(results)
            },
            "message": f"Found {len(results)} results for '{query}'"
        }


# Example usage
if __name__ == "__main__":
    search_tool = SearchWebTool()

    # Test search
    print("Searching for 'python'...")
    result = search_tool.execute(query="python")
    print(f"Result: {result}\n")

    print("Searching for 'LLM agent'...")
    result = search_tool.execute(query="LLM agent")
    print(f"Result: {result}\n")
