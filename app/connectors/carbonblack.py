"""VMware Carbon Black Cloud pull connector via Alerts API v7."""

import logging
from typing import Any

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class CarbonBlackConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "carbonblack"

    @property
    def source_name(self) -> str:
        return "CarbonBlack"

    def _auth_header(self) -> str:
        s = get_settings()
        api_key = (s.cbc_api_key.get_secret_value() or "").strip()
        api_id = (s.cbc_api_id or "").strip()
        return f"{api_key}/{api_id}"

    def _base(self) -> str:
        s = get_settings()
        return (s.cbc_base_url or "").rstrip("/")

    def _org(self) -> str:
        return (get_settings().cbc_org_key or "").strip()

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.cbc_org_key or not s.cbc_api_key.get_secret_value() or not s.cbc_api_id or not s.cbc_base_url:
            return False, "CBC_ORG_KEY, CBC_API_KEY, CBC_API_ID, or CBC_BASE_URL not configured"
        try:
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    f"{self._base()}/appservices/v6/orgs/{self._org()}/alerts/workflow_states",
                    headers={"X-Auth-Token": self._auth_header()},
                )
            return r.status_code == 200, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.cbc_org_key or not s.cbc_api_key.get_secret_value() or not s.cbc_api_id or not s.cbc_base_url:
            return []
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    f"{self._base()}/api/alerts/v7/orgs/{self._org()}/alerts/_search",
                    headers={"X-Auth-Token": self._auth_header(), "Content-Type": "application/json"},
                    json={"rows": 200, "criteria": {"minimum_severity": 3}, "sort": [{"field": "backend_update_timestamp", "order": "DESC"}]},
                )
                r.raise_for_status()
                alerts = r.json().get("results", [])
            logger.info("carbonblack.pull fetched %d alerts", len(alerts))
            return alerts
        except Exception as e:
            logger.warning("carbonblack.pull failed: %s", e)
            return []
