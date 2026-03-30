"""SentinelOne Singularity pull connector via Management API v2.1."""

import logging
from typing import Any

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class SentinelOneConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "sentinelone"

    @property
    def source_name(self) -> str:
        return "SentinelOne"

    def _base(self) -> str:
        s = get_settings()
        return (s.s1_console_url or "").rstrip("/")

    def _headers(self) -> dict[str, str]:
        s = get_settings()
        return {"Authorization": f"ApiToken {(s.s1_api_token.get_secret_value() or '').strip()}"}

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.s1_console_url or not s.s1_api_token.get_secret_value():
            return False, "S1_CONSOLE_URL or S1_API_TOKEN not configured"
        try:
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(f"{self._base()}/web/api/v2.1/system/status",
                                     headers=self._headers())
            return r.status_code == 200, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.s1_console_url or not s.s1_api_token.get_secret_value():
            return []
        params: dict[str, Any] = {"resolved": "false", "limit": 200, "sortBy": "createdAt", "sortOrder": "desc"}
        if s.s1_site_id:
            params["siteIds"] = s.s1_site_id
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(
                    f"{self._base()}/web/api/v2.1/threats",
                    headers=self._headers(),
                    params=params,
                )
                r.raise_for_status()
                threats = r.json().get("data", [])
            logger.info("sentinelone.pull fetched %d threats", len(threats))
            return threats
        except Exception as e:
            logger.warning("sentinelone.pull failed: %s", e)
            return []
