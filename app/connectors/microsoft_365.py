"""Microsoft 365 Defender pull connector via Microsoft Graph Security API."""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class Microsoft365Connector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "microsoft-365"

    @property
    def source_name(self) -> str:
        return "Microsoft365"

    async def _get_token(self) -> str:
        s = get_settings()
        tenant = (s.m365_tenant_id or s.azure_tenant_id or "").strip()
        client_id = (s.m365_client_id or s.azure_client_id or "").strip()
        client_secret = (s.m365_client_secret.get_secret_value()
                         or s.azure_client_secret.get_secret_value() or "").strip()
        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.post(
                f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
            r.raise_for_status()
            return r.json()["access_token"]

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        tenant = s.m365_tenant_id or s.azure_tenant_id
        client_id = s.m365_client_id or s.azure_client_id
        if not tenant or not client_id:
            return False, "M365_TENANT_ID and M365_CLIENT_ID (or Azure equivalents) not configured"
        try:
            await self._get_token()
            return True, "OK"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        tenant = s.m365_tenant_id or s.azure_tenant_id
        client_id = s.m365_client_id or s.azure_client_id
        if not tenant or not client_id:
            return []
        since = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            token = await self._get_token()
            headers = {"Authorization": f"Bearer {token}"}
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(
                    "https://graph.microsoft.com/v1.0/security/incidents"
                    f"?$filter=lastUpdateDateTime ge {since}&$top=100&$orderby=lastUpdateDateTime desc",
                    headers=headers,
                )
                r.raise_for_status()
                incidents = r.json().get("value", [])
            logger.info("m365.pull fetched %d incidents", len(incidents))
            return incidents
        except Exception as e:
            logger.warning("m365.pull failed: %s", e)
            return []
