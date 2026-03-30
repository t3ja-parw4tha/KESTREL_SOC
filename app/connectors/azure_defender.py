"""Microsoft Defender for Cloud pull connector via Azure Security Management REST API."""

import logging
from typing import Any

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class AzureDefenderConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "azure-defender"

    @property
    def source_name(self) -> str:
        return "AzureDefender"

    async def _get_token(self) -> str:
        s = get_settings()
        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.post(
                f"https://login.microsoftonline.com/{s.azure_tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": s.azure_client_id,
                    "client_secret": s.azure_client_secret.get_secret_value(),
                    "scope": "https://management.azure.com/.default",
                    "grant_type": "client_credentials",
                },
            )
            r.raise_for_status()
            return r.json()["access_token"]

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.azure_tenant_id or not s.azure_client_id or not s.azure_subscription_id:
            return False, "Azure credentials or AZURE_SUBSCRIPTION_ID not configured"
        try:
            await self._get_token()
            return True, "OK"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.azure_tenant_id or not s.azure_client_id or not s.azure_subscription_id:
            return []
        try:
            token = await self._get_token()
            sub = s.azure_subscription_id
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(
                    f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Security/alerts"
                    "?api-version=2022-01-01",
                    headers={"Authorization": f"Bearer {token}"},
                )
                r.raise_for_status()
                alerts = r.json().get("value", [])
            logger.info("azure_defender.pull fetched %d alerts", len(alerts))
            return alerts
        except Exception as e:
            logger.warning("azure_defender.pull failed: %s", e)
            return []
