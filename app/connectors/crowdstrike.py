"""CrowdStrike Falcon pull connector via Alerts API v2."""

import logging
from typing import Any

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class CrowdStrikeConnector(BaseConnector):
    _access_token: str = ""
    _token_expires: float = 0.0

    @property
    def source_id(self) -> str:
        return "crowdstrike"

    @property
    def source_name(self) -> str:
        return "CrowdStrike"

    def _base(self) -> str:
        s = get_settings()
        return (s.crowdstrike_base_url or "https://api.crowdstrike.com").rstrip("/")

    async def _get_token(self) -> str:
        import time
        if self._access_token and time.time() < self._token_expires - 30:
            return self._access_token
        s = get_settings()
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                f"{self._base()}/oauth2/token",
                data={
                    "client_id": (s.crowdstrike_client_id or "").strip(),
                    "client_secret": (s.crowdstrike_client_secret.get_secret_value() or "").strip(),
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            r.raise_for_status()
            data = r.json()
            self._access_token = data["access_token"]
            self._token_expires = time.time() + data.get("expires_in", 1800)
        return self._access_token

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.crowdstrike_client_id or not s.crowdstrike_client_secret.get_secret_value():
            return False, "CROWDSTRIKE_CLIENT_ID or CROWDSTRIKE_CLIENT_SECRET not configured"
        try:
            await self._get_token()
            return True, "OK"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.crowdstrike_client_id or not s.crowdstrike_client_secret.get_secret_value():
            return []
        try:
            token = await self._get_token()
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            base = self._base()
            async with httpx.AsyncClient(timeout=30) as client:
                # Query alert IDs
                r_ids = await client.post(
                    f"{base}/alerts/queries/alerts/v2",
                    headers=headers,
                    json={"filter": "status:'new'+status:'in_progress'", "limit": 200, "sort": "created_timestamp|desc"},
                )
                r_ids.raise_for_status()
                ids = r_ids.json().get("resources", [])
                if not ids:
                    return []
                # Fetch alert details
                r_detail = await client.post(
                    f"{base}/alerts/entities/alerts/v2",
                    headers=headers,
                    json={"ids": ids},
                )
                r_detail.raise_for_status()
                alerts = r_detail.json().get("resources", [])
            logger.info("crowdstrike.pull fetched %d alerts", len(alerts))
            return alerts
        except Exception as e:
            logger.warning("crowdstrike.pull failed: %s", e)
            return []
