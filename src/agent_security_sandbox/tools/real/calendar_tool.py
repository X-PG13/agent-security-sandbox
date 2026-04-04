"""Google Calendar API integration for real-environment testing.

Requires Google API credentials and the ``google-api-python-client``
package (included in the ``real`` optional dependency group).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from ..base import RiskLevel, ToolMetadata, ToolParameter
from .base import RealTool

logger = logging.getLogger(__name__)


class GoogleCalendarTool(RealTool):
    """Create and read calendar events via the Google Calendar API.

    In dry-run mode (default), all operations are logged but no actual
    API calls are made.

    Args:
        credentials_path: Path to Google OAuth2 credentials JSON.
        dry_run: If ``True``, do not make real API calls.
        sandbox_account: Google account email for the test calendar.
        calendar_id: Calendar ID to operate on (default ``"primary"``).
    """

    def __init__(
        self,
        credentials_path: Optional[str] = None,
        dry_run: bool = True,
        sandbox_account: Optional[str] = None,
        calendar_id: str = "primary",
        rate_limit_seconds: float = 1.0,
    ) -> None:
        metadata = ToolMetadata(
            name="google_calendar",
            description="Create or read Google Calendar events",
            risk_level=RiskLevel.MEDIUM,
            side_effect=True,
            data_access="private",
            parameters={
                "action": ToolParameter(
                    name="action", type="string",
                    description="'create' or 'read'", required=True,
                ),
                "title": ToolParameter(
                    name="title", type="string",
                    description="Event title", required=False,
                ),
                "date": ToolParameter(
                    name="date", type="string",
                    description="Event date (YYYY-MM-DD)", required=False,
                ),
                "time": ToolParameter(
                    name="time", type="string",
                    description="Event time (HH:MM)", required=False,
                ),
                "description": ToolParameter(
                    name="description", type="string",
                    description="Event description", required=False,
                ),
                "event_id": ToolParameter(
                    name="event_id", type="string",
                    description="Event ID for reading", required=False,
                ),
            },
        )
        super().__init__(
            metadata=metadata,
            dry_run=dry_run,
            rate_limit_seconds=rate_limit_seconds,
            sandbox_account=sandbox_account,
        )
        self._credentials_path = credentials_path
        self._calendar_id = calendar_id
        self._service = None

    def _get_service(self) -> Any:
        """Lazy-initialise the Calendar API service."""
        if self._service is not None:
            return self._service

        try:
            from google.oauth2.credentials import Credentials
            from googleapiclient.discovery import build

            creds = Credentials.from_authorized_user_file(
                self._credentials_path,
                scopes=["https://www.googleapis.com/auth/calendar"],
            )
            self._service = build("calendar", "v3", credentials=creds)
            return self._service
        except ImportError:
            raise ImportError(
                "google-api-python-client and google-auth are required. "
                "Install with: pip install agent-security-sandbox[real]"
            )

    def _real_execute(self, **kwargs: Any) -> Dict[str, Any]:
        action = kwargs.get("action", "read")

        if action == "create":
            return self._create_event(**kwargs)
        elif action == "read":
            return self._read_event(**kwargs)
        else:
            return {"status": "error", "message": f"Unknown action: {action}"}

    def _create_event(self, **kwargs: Any) -> Dict[str, Any]:
        title = kwargs.get("title", "Untitled Event")
        date = kwargs.get("date", "2024-01-01")
        time_str = kwargs.get("time", "09:00")
        description = kwargs.get("description", "")

        event = {
            "summary": title,
            "description": description,
            "start": {
                "dateTime": f"{date}T{time_str}:00",
                "timeZone": "UTC",
            },
            "end": {
                "dateTime": f"{date}T{time_str}:00",
                "timeZone": "UTC",
            },
        }

        service = self._get_service()
        result = (
            service.events()
            .insert(calendarId=self._calendar_id, body=event)
            .execute()
        )

        logger.info("Calendar event created: %s", result.get("id"))
        return {
            "status": "created",
            "event_id": result.get("id", ""),
            "title": title,
            "date": date,
        }

    def _read_event(self, **kwargs: Any) -> Dict[str, Any]:
        event_id = kwargs.get("event_id")
        if not event_id:
            # List upcoming events.
            service = self._get_service()
            result = (
                service.events()
                .list(calendarId=self._calendar_id, maxResults=10)
                .execute()
            )
            events = result.get("items", [])
            return {
                "status": "ok",
                "events": [
                    {
                        "id": e.get("id"),
                        "title": e.get("summary", ""),
                        "start": e.get("start", {}).get("dateTime", ""),
                    }
                    for e in events
                ],
            }

        service = self._get_service()
        event = (
            service.events()
            .get(calendarId=self._calendar_id, eventId=event_id)
            .execute()
        )
        return {
            "status": "ok",
            "event_id": event.get("id"),
            "title": event.get("summary", ""),
            "description": event.get("description", ""),
            "start": event.get("start", {}).get("dateTime", ""),
        }
