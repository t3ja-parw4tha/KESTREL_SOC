"""Okta System Log pull connector."""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class OktaConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "okta"

    @property
    def source_name(self) -> str:
        return "Okta"

    def _base(self) -> str:
        s = get_settings()
        domain = (s.okta_domain or "").lstrip("https://").rstrip("/")
        return f"https://{domain}"

    def _headers(self) -> dict[str, str]:
        s = get_settings()
        return {"Authorization": f"SSWS {(s.okta_api_token.get_secret_value() or '').strip()}"}

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.okta_domain or not s.okta_api_token.get_secret_value():
            return False, "OKTA_DOMAIN or OKTA_API_TOKEN not configured"
        try:
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(f"{self._base()}/api/v1/users?limit=1", headers=self._headers())
            return r.status_code == 200, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.okta_domain or not s.okta_api_token.get_secret_value():
            return []
        since = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        # Pull security-relevant event types
        event_filters = [
            "user.authentication.auth_via_mfa",
            "user.session.start",
            "user.account.lock",
            "policy.evaluate_sign_on",
            "security.threat.detected",
            "user.authentication.sso",
        ]
        try:
            all_events: list[dict[str, Any]] = []
            async with httpx.AsyncClient(timeout=30) as client:
                for event_type in event_filters:
                    r = await client.get(
                        f"{self._base()}/api/v1/logs",
                        headers=self._headers(),
                        params={"since": since, "filter": f'eventType eq "{event_type}"', "limit": 100},
                    )
                    if r.status_code == 200:
                        all_events.extend(r.json())
            logger.info("okta.pull fetched %d events", len(all_events))
            return all_events
        except Exception as e:
            logger.warning("okta.pull failed: %s", e)
            return []
