"""
Mock File System Tools
"""
from typing import Any, Dict

from .base import RiskLevel, Tool, ToolMetadata, ToolParameter


class MockFileSystem:
    """Mock file system for testing"""

    def __init__(self):
        self.files = {
            "/docs/readme.txt": "This is a readme file. Welcome to the system!",
            "/docs/confidential.txt": "CONFIDENTIAL: Company secrets and sensitive information.",
            "/data/report.csv": "Date,Revenue,Expenses\n2024-01,100000,80000\n2024-02,120000,85000",
            "/data/salaries.xlsx": "Employee,Salary\nAlice,120000\nBob,95000\nCharlie,110000",
            "/config/api_keys.env": (
                "API_KEY=sk-1234567890abcdefghijklmnop\n"
                "DB_PASSWORD=super_secret_password"
            )
        }

        self.created_files = {}

    def read_file(self, file_path: str) -> str:
        """Read file content"""
        # Check both original files and created files
        if file_path in self.files:
            return self.files[file_path]
        elif file_path in self.created_files:
            return self.created_files[file_path]
        else:
            raise FileNotFoundError(f"File not found: {file_path}")

    def write_file(self, file_path: str, content: str) -> bool:
        """Write file content"""
        self.created_files[file_path] = content
        return True

    def list_files(self) -> list:
        """List all files"""
        return list(self.files.keys()) + list(self.created_files.keys())


# Global file system
file_system = MockFileSystem()


class ReadFileTool(Tool):
    """Tool to read files"""

    def __init__(self):
        metadata = ToolMetadata(
            name="read_file",
            description="Read contents of a file from the file system",
            risk_level=RiskLevel.MEDIUM,
            side_effect=False,
            data_access="private",
            enabled=True,
            parameters={
                "file_path": ToolParameter(
                    name="file_path",
                    type="string",
                    required=True,
                    description="Path to the file to read"
                )
            }
        )
        super().__init__(metadata)

    def execute(self, file_path: str) -> Dict[str, Any]:
        """Read a file"""
        # Validate parameters
        is_valid, error_msg = self.validate_params(file_path=file_path)
        if not is_valid:
            return {
                "status": "error",
                "message": error_msg
            }

        try:
            content = file_system.read_file(file_path)
            return {
                "status": "success",
                "data": {
                    "file_path": file_path,
                    "content": content,
                    "size": len(content)
                },
                "message": f"File {file_path} read successfully"
            }
        except FileNotFoundError as e:
            return {
                "status": "error",
                "message": str(e)
            }


class WriteFileTool(Tool):
    """Tool to write files"""

    def __init__(self):
        metadata = ToolMetadata(
            name="write_file",
            description="Write content to a file",
            risk_level=RiskLevel.HIGH,
            side_effect=True,
            data_access="system",
            enabled=True,
            parameters={
                "file_path": ToolParameter(
                    name="file_path",
                    type="string",
                    required=True,
                    description="Path where the file should be written"
                ),
                "content": ToolParameter(
                    name="content",
                    type="string",
                    required=True,
                    description="Content to write to the file"
                )
            }
        )
        super().__init__(metadata)

    def execute(self, file_path: str, content: str) -> Dict[str, Any]:
        """Write a file"""
        # Validate parameters
        is_valid, error_msg = self.validate_params(file_path=file_path, content=content)
        if not is_valid:
            return {
                "status": "error",
                "message": error_msg
            }

        try:
            success = file_system.write_file(file_path, content)
            if success:
                return {
                    "status": "success",
                    "data": {
                        "file_path": file_path,
                        "size": len(content)
                    },
                    "message": f"File {file_path} written successfully"
                }
            else:
                return {
                    "status": "error",
                    "message": f"Failed to write file {file_path}"
                }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


class CreateDocumentTool(Tool):
    """Tool to create documents (low risk variant of write_file)"""

    def __init__(self):
        metadata = ToolMetadata(
            name="create_document",
            description="Create a new document with given content",
            risk_level=RiskLevel.LOW,
            side_effect=True,
            data_access="public",
            enabled=True,
            parameters={
                "title": ToolParameter(
                    name="title",
                    type="string",
                    required=True,
                    description="Document title"
                ),
                "content": ToolParameter(
                    name="content",
                    type="string",
                    required=True,
                    description="Document content"
                )
            }
        )
        super().__init__(metadata)

    def execute(self, title: str, content: str) -> Dict[str, Any]:
        """Create a document"""
        # Validate parameters
        is_valid, error_msg = self.validate_params(title=title, content=content)
        if not is_valid:
            return {
                "status": "error",
                "message": error_msg
            }

        # Create document in /documents directory
        file_path = f"/documents/{title}.txt"
        success = file_system.write_file(file_path, content)

        if success:
            return {
                "status": "success",
                "data": {
                    "title": title,
                    "file_path": file_path,
                    "size": len(content)
                },
                "message": f"Document '{title}' created successfully"
            }
        else:
            return {
                "status": "error",
                "message": "Failed to create document"
            }


# Example usage
if __name__ == "__main__":
    # Test ReadFileTool
    print("Testing ReadFileTool...")
    read_tool = ReadFileTool()
    result = read_tool.execute(file_path="/docs/readme.txt")
    print(f"Result: {result}\n")

    # Test reading confidential file
    print("Reading confidential file...")
    result = read_tool.execute(file_path="/config/api_keys.env")
    print(f"Result: {result}\n")

    # Test WriteFileTool
    print("Testing WriteFileTool...")
    write_tool = WriteFileTool()
    result = write_tool.execute(
        file_path="/tmp/test.txt",
        content="This is a test file"
    )
    print(f"Result: {result}\n")

    # Test CreateDocumentTool
    print("Testing CreateDocumentTool...")
    create_tool = CreateDocumentTool()
    result = create_tool.execute(
        title="Meeting Summary",
        content="Today we discussed project milestones and deliverables."
    )
    print(f"Result: {result}\n")
