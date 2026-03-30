"""Tenable.io pull connector — vulnerability findings via Vulnerabilities API."""

import logging
from typing import Any

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class TenableConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "tenable"

    @property
    def source_name(self) -> str:
        return "Tenable"

    def _headers(self) -> dict[str, str]:
        s = get_settings()
        ak = (s.tenable_access_key.get_secret_value() or "").strip()
        sk = (s.tenable_secret_key.get_secret_value() or "").strip()
        return {"X-ApiKeys": f"accessKey={ak}; secretKey={sk}"}

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.tenable_access_key.get_secret_value() or not s.tenable_secret_key.get_secret_value():
            return False, "TENABLE_ACCESS_KEY or TENABLE_SECRET_KEY not configured"
        try:
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get("https://cloud.tenable.com/session", headers=self._headers())
            return r.status_code == 200, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.tenable_access_key.get_secret_value() or not s.tenable_secret_key.get_secret_value():
            return []
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                # Get recent scans
                r_scans = await client.get("https://cloud.tenable.com/scans?limit=5", headers=self._headers())
                r_scans.raise_for_status()
                scans = r_scans.json().get("scans") or []
                events: list[dict[str, Any]] = []
                for scan in scans[:3]:  # Limit to 3 most recent scans
                    scan_id = scan.get("id")
                    if not scan_id or scan.get("status") != "completed":
                        continue
                    r_vulns = await client.get(
                        f"https://cloud.tenable.com/scans/{scan_id}",
                        headers=self._headers(),
                    )
                    if r_vulns.status_code != 200:
                        continue
                    for vuln in r_vulns.json().get("vulnerabilities", [])[:100]:
                        vuln["_kestrel_scan_id"] = scan_id
                        vuln["_kestrel_scan_name"] = scan.get("name")
                        events.append(vuln)
            logger.info("tenable.pull fetched %d vulnerability findings", len(events))
            return events
        except Exception as e:
            logger.warning("tenable.pull failed: %s", e)
            return []
