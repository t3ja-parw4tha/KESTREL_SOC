"""Google Workspace pull connector — Admin SDK Reports API (login + admin activity)."""

import asyncio
import json
import logging
from typing import Any

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)

_SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
]


def _pull_sync(sa_key_json: str, admin_email: str) -> list[dict[str, Any]]:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    credentials = service_account.Credentials.from_service_account_info(
        json.loads(sa_key_json),
        scopes=_SCOPES,
    ).with_subject(admin_email)

    service = build("admin", "reports_v1", credentials=credentials)
    events: list[dict[str, Any]] = []
    for application in ("login", "admin"):
        try:
            resp = (
                service.activities()
                .list(
                    userKey="all",
                    applicationName=application,
                    maxResults=200,
                )
                .execute()
            )
            for item in resp.get("items", []):
                item["_gworkspace_application"] = application
                events.append(item)
        except Exception as e:
            logger.warning("google_workspace.pull app=%s error: %s", application, e)
    return events


def _test_sync(sa_key_json: str, admin_email: str) -> tuple[bool, str]:
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        credentials = service_account.Credentials.from_service_account_info(
            json.loads(sa_key_json),
            scopes=_SCOPES,
        ).with_subject(admin_email)
        service = build("admin", "reports_v1", credentials=credentials)
        service.activities().list(
            userKey="all", applicationName="login", maxResults=1
        ).execute()
        return True, "OK"
    except Exception as e:
        return False, str(e)


class GoogleWorkspaceConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "google-workspace"

    @property
    def source_name(self) -> str:
        return "GoogleWorkspace"

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        sa_key = (s.gworkspace_service_account_key.get_secret_value() or "").strip()
        admin_email = (s.gworkspace_admin_email or "").strip()
        if not sa_key or not admin_email:
            return False, "GWORKSPACE_SERVICE_ACCOUNT_KEY or GWORKSPACE_ADMIN_EMAIL not configured"
        try:
            return await asyncio.to_thread(_test_sync, sa_key, admin_email)
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        sa_key = (s.gworkspace_service_account_key.get_secret_value() or "").strip()
        admin_email = (s.gworkspace_admin_email or "").strip()
        if not sa_key or not admin_email:
            return []
        try:
            events = await asyncio.to_thread(_pull_sync, sa_key, admin_email)
            logger.info("google_workspace.pull fetched %d events", len(events))
            return events
        except Exception as e:
            logger.warning("google_workspace.pull failed: %s", e)
            return []
