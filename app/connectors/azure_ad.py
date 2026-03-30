"""Azure Active Directory (Entra ID) pull connector via Microsoft Graph API."""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class AzureADConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "azure-ad"

    @property
    def source_name(self) -> str:
        return "AzureAD"

    async def _get_token(self) -> str:
        s = get_settings()
        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.post(
                f"https://login.microsoftonline.com/{s.azure_tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": s.azure_client_id,
                    "client_secret": s.azure_client_secret.get_secret_value(),
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
            r.raise_for_status()
            return r.json()["access_token"]

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.azure_tenant_id or not s.azure_client_id or not s.azure_client_secret.get_secret_value():
            return False, "Azure credentials not configured"
        try:
            await self._get_token()
            return True, "OK"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.azure_tenant_id or not s.azure_client_id or not s.azure_client_secret.get_secret_value():
            return []
        since = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            token = await self._get_token()
            headers = {"Authorization": f"Bearer {token}"}
            events: list[dict[str, Any]] = []
            async with httpx.AsyncClient(timeout=30) as client:
                # Risky sign-ins
                r_risk = await client.get(
                    "https://graph.microsoft.com/v1.0/identityProtection/riskDetections"
                    f"?$filter=detectedDateTime ge {since}&$top=200&$orderby=detectedDateTime desc",
                    headers=headers,
                )
                if r_risk.status_code == 200:
                    for item in r_risk.json().get("value", []):
                        item["_kestrel_event_type"] = "riskDetection"
                        events.append(item)
                # Sign-in audit log
                r_signin = await client.get(
                    "https://graph.microsoft.com/v1.0/auditLogs/signIns"
                    f"?$filter=createdDateTime ge {since} and riskLevelDuringSignIn ne 'none'&$top=100",
                    headers=headers,
                )
                if r_signin.status_code == 200:
                    for item in r_signin.json().get("value", []):
                        item["_kestrel_event_type"] = "riskySignIn"
                        events.append(item)
            logger.info("azure_ad.pull fetched %d events", len(events))
            return events
        except Exception as e:
            logger.warning("azure_ad.pull failed: %s", e)
            return []
