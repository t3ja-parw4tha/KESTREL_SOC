"""IBM QRadar pull connector via REST API v12+."""

import logging
from typing import Any

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class QRadarConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "qradar"

    @property
    def source_name(self) -> str:
        return "QRadar"

    def _headers(self) -> dict[str, str]:
        s = get_settings()
        return {
            "SEC": (s.qradar_token.get_secret_value() or "").strip(),
            "Accept": "application/json",
            "Version": "12.0",
        }

    def _base(self) -> str:
        s = get_settings()
        return f"https://{(s.qradar_host or '').strip()}"

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.qradar_host or not s.qradar_token.get_secret_value():
            return False, "QRADAR_HOST or QRADAR_TOKEN not configured"
        try:
            async with httpx.AsyncClient(timeout=12, verify=False) as client:  # noqa: S501
                r = await client.get(f"{self._base()}/api/system/information", headers=self._headers())
            return r.status_code == 200, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.qradar_host or not s.qradar_token.get_secret_value():
            return []
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:  # noqa: S501
                r = await client.get(
                    f"{self._base()}/api/siem/offenses",
                    headers=self._headers(),
                    params={"status": "OPEN", "sort": "-last_updated_time", "limit": 100},
                )
                r.raise_for_status()
                offenses = r.json()
            events = []
            for o in offenses:
                events.append({
                    "id": str(o.get("id", "")),
                    "title": o.get("description", "QRadar Offense"),
                    "severity": o.get("magnitude", 5),
                    "category": o.get("categories", ["unknown"])[0] if o.get("categories") else "unknown",
                    "source_ip": o.get("source_address_ids", [None])[0],
                    "offense_type": o.get("offense_type"),
                    "event_count": o.get("event_count"),
                    "start_time": o.get("start_time"),
                    "last_updated": o.get("last_updated_time"),
                    "status": o.get("status"),
                })
            logger.info("qradar.pull fetched %d offenses", len(events))
            return events
        except Exception as e:
            logger.warning("qradar.pull failed: %s", e)
            return []
