"""Qualys VMDR pull connector — vulnerability detections via Qualys API v2."""

import logging
from typing import Any
import xml.etree.ElementTree as ET

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class QualysConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "qualys"

    @property
    def source_name(self) -> str:
        return "Qualys"

    def _auth(self) -> tuple[str, str]:
        s = get_settings()
        return (s.qualys_username, s.qualys_password.get_secret_value() or "")

    def _base_url(self) -> str:
        s = get_settings()
        url = (s.qualys_api_url or "").strip().rstrip("/")
        return url or "https://qualysapi.qg2.apps.qualys.com"

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.qualys_username or not s.qualys_password.get_secret_value():
            return False, "QUALYS_USERNAME or QUALYS_PASSWORD not configured"
        try:
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    f"{self._base_url()}/api/2.0/fo/user/?action=list",
                    auth=self._auth(),
                    headers={"X-Requested-With": "Kestrel SOC"},
                )
            return r.status_code == 200, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.qualys_username or not s.qualys_password.get_secret_value():
            return []
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.post(
                    f"{self._base_url()}/api/2.0/fo/asset/host/vm/detection/",
                    auth=self._auth(),
                    headers={"X-Requested-With": "Kestrel SOC"},
                    data={
                        "action": "list",
                        "show_results": "1",
                        "status": "New,Active,Re-Opened",
                        "severities": "4,5",
                        "truncation_limit": "500",
                    },
                )
                r.raise_for_status()
            # Parse XML (vendor API; XML bomb risk bounded by httpx response limits)
            root = ET.fromstring(r.text)  # nosec B314
            events: list[dict[str, Any]] = []
            for host in root.iter("HOST"):
                host_ip = host.findtext("IP", "")
                for det in host.iter("DETECTION"):
                    ev: dict[str, Any] = {
                        "_qualys_host_ip": host_ip,
                        "_qualys_hostname": host.findtext("DNS", ""),
                    }
                    for child in det:
                        ev[child.tag.lower()] = child.text
                    events.append(ev)
            logger.info("qualys.pull fetched %d vulnerability detections", len(events))
            return events
        except Exception as e:
            logger.warning("qualys.pull failed: %s", e)
            return []
