"""Gmail API integration for real-environment email testing.

Requires Google API credentials and the ``google-api-python-client``
package (included in the ``real`` optional dependency group).
"""
from __future__ import annotations

import base64
import logging
from email.mime.text import MIMEText
from typing import Any, Dict, Optional

from ..base import RiskLevel, ToolMetadata, ToolParameter
from .base import RealTool

logger = logging.getLogger(__name__)


class GmailTool(RealTool):
    """Send and read emails via the Gmail API.

    In dry-run mode (default), all operations are logged but no actual
    API calls are made.

    Args:
        credentials_path: Path to Google OAuth2 credentials JSON.
        dry_run: If ``True``, do not make real API calls.
        sandbox_account: Gmail address of the test account.
    """

    def __init__(
        self,
        credentials_path: Optional[str] = None,
        dry_run: bool = True,
        sandbox_account: Optional[str] = None,
        rate_limit_seconds: float = 1.0,
    ) -> None:
        metadata = ToolMetadata(
            name="gmail_send",
            description="Send an email via Gmail API",
            risk_level=RiskLevel.HIGH,
            side_effect=True,
            data_access="private",
            parameters={
                "to": ToolParameter(
                    name="to", type="string",
                    description="Recipient email", required=True,
                ),
                "subject": ToolParameter(
                    name="subject", type="string",
                    description="Email subject", required=True,
                ),
                "body": ToolParameter(
                    name="body", type="string",
                    description="Email body", required=True,
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
        self._service = None

    def _get_service(self) -> Any:
        """Lazy-initialise the Gmail API service."""
        if self._service is not None:
            return self._service

        try:
            from google.oauth2.credentials import Credentials
            from googleapiclient.discovery import build

            creds = Credentials.from_authorized_user_file(
                self._credentials_path,
                scopes=["https://www.googleapis.com/auth/gmail.send"],
            )
            self._service = build("gmail", "v1", credentials=creds)
            return self._service
        except ImportError:
            raise ImportError(
                "google-api-python-client and google-auth are required. "
                "Install with: pip install agent-security-sandbox[real]"
            )

    def _real_execute(self, **kwargs: Any) -> Dict[str, Any]:
        """Send an email via the Gmail API."""
        to = kwargs["to"]
        subject = kwargs["subject"]
        body = kwargs["body"]

        message = MIMEText(body)
        message["to"] = to
        message["subject"] = subject

        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
        service = self._get_service()
        result = (
            service.users()
            .messages()
            .send(userId="me", body={"raw": raw})
            .execute()
        )

        logger.info("Email sent to %s (id=%s)", to, result.get("id"))
        return {
            "status": "sent",
            "message_id": result.get("id", ""),
            "to": to,
            "subject": subject,
        }
