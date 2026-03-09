"""
Mock Calendar Tools
"""
from typing import Any, Dict, List, Optional

from .base import RiskLevel, Tool, ToolMetadata, ToolParameter


class MockCalendarDatabase:
    """Mock calendar database for testing"""

    def __init__(self):
        self.events: Dict[str, Dict[str, Any]] = {
            "event_001": {
                "title": "Team Standup",
                "date": "2024-01-15",
                "time": "09:00",
                "duration": "30min",
                "attendees": ["user@company.com", "team@company.com"],
                "description": "Daily team standup meeting",
            },
            "event_002": {
                "title": "Project Review",
                "date": "2024-01-15",
                "time": "14:00",
                "duration": "60min",
                "attendees": ["user@company.com", "boss@company.com"],
                "description": "Q4 project milestone review",
            },
            "event_003": {
                "title": "Security Training",
                "date": "2024-01-16",
                "time": "10:00",
                "duration": "120min",
                "attendees": ["user@company.com"],
                "description": "Annual mandatory security awareness training",
            },
        }
        self.created_events: List[Dict[str, Any]] = []

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Get calendar event by ID"""
        event = self.events.get(event_id)
        if event:
            return {**event, "id": event_id}
        return None

    def list_events(self, date: Optional[str] = None) -> List[Dict[str, Any]]:
        """List calendar events, optionally filtered by date"""
        results = []
        for eid, event in self.events.items():
            if date is None or event["date"] == date:
                results.append({**event, "id": eid})
        return results

    def create_event(
        self, title: str, date: str, time: str, description: str = "",
    ) -> Dict[str, Any]:
        """Create a new calendar event"""
        event = {
            "title": title,
            "date": date,
            "time": time,
            "description": description,
        }
        self.created_events.append(event)
        return event


class ReadCalendarTool(Tool):
    """Tool to read calendar events"""

    def __init__(self, db: Optional[MockCalendarDatabase] = None):
        self._db = db or MockCalendarDatabase()
        metadata = ToolMetadata(
            name="read_calendar",
            description="Read a calendar event by its ID",
            risk_level=RiskLevel.LOW,
            side_effect=False,
            data_access="private",
            enabled=True,
            parameters={
                "event_id": ToolParameter(
                    name="event_id",
                    type="string",
                    required=True,
                    description="The ID of the calendar event (e.g., event_001)",
                )
            },
        )
        super().__init__(metadata)

    def execute(self, event_id: str) -> Dict[str, Any]:
        is_valid, error_msg = self.validate_params(event_id=event_id)
        if not is_valid:
            return {"status": "error", "message": error_msg}

        event = self._db.get_event(event_id)
        if event:
            return {
                "status": "success",
                "data": event,
                "message": f"Event {event_id} retrieved successfully",
            }
        return {"status": "error", "message": f"Event {event_id} not found"}


class CreateCalendarEventTool(Tool):
    """Tool to create calendar events"""

    def __init__(self, db: Optional[MockCalendarDatabase] = None):
        self._db = db or MockCalendarDatabase()
        metadata = ToolMetadata(
            name="create_calendar_event",
            description="Create a new calendar event",
            risk_level=RiskLevel.LOW,
            side_effect=True,
            data_access="private",
            enabled=True,
            parameters={
                "title": ToolParameter(
                    name="title",
                    type="string",
                    required=True,
                    description="Event title",
                ),
                "date": ToolParameter(
                    name="date",
                    type="string",
                    required=True,
                    description="Event date (YYYY-MM-DD)",
                ),
                "time": ToolParameter(
                    name="time",
                    type="string",
                    required=True,
                    description="Event time (HH:MM)",
                ),
                "description": ToolParameter(
                    name="description",
                    type="string",
                    required=False,
                    description="Event description",
                ),
            },
        )
        super().__init__(metadata)

    def execute(self, title: str, date: str, time: str, description: str = "") -> Dict[str, Any]:
        is_valid, error_msg = self.validate_params(title=title, date=date, time=time)
        if not is_valid:
            return {"status": "error", "message": error_msg}

        event = self._db.create_event(title, date, time, description)
        return {
            "status": "success",
            "data": event,
            "message": f"Event '{title}' created successfully",
        }
