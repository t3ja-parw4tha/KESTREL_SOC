"""Fortinet FortiGate pull connector via REST API v2."""

import logging
from typing import Any

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class FortinetConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "fortinet"

    @property
    def source_name(self) -> str:
        return "Fortinet"

    def _headers(self) -> dict[str, str]:
        s = get_settings()
        return {"Authorization": f"Bearer {(s.fortigate_api_key.get_secret_value() or '').strip()}"}

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.fortigate_host or not s.fortigate_api_key.get_secret_value():
            return False, "FORTIGATE_HOST or FORTIGATE_API_KEY not configured"
        vdom = s.fortigate_vdom or "root"
        try:
            async with httpx.AsyncClient(timeout=12, verify=False) as client:  # noqa: S501
                r = await client.get(
                    f"https://{s.fortigate_host}/api/v2/monitor/system/status?vdom={vdom}",
                    headers=self._headers(),
                )
            return r.status_code == 200, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.fortigate_host or not s.fortigate_api_key.get_secret_value():
            return []
        vdom = s.fortigate_vdom or "root"
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:  # noqa: S501
                r = await client.get(
                    f"https://{s.fortigate_host}/api/v2/log/forticloud/threat/select",
                    headers=self._headers(),
                    params={"vdom": vdom, "rows": 500, "start": 1},
                )
                r.raise_for_status()
                results = r.json().get("results", [])
            logger.info("fortinet.pull fetched %d threat log entries", len(results))
            return results
        except Exception as e:
            logger.warning("fortinet.pull failed: %s", e)
            return []
