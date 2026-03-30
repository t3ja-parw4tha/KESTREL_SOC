"""Palo Alto NGFW (PAN-OS) pull connector via XML API."""

import logging
from typing import Any

import defusedxml.ElementTree as ET

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class PanosConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "palo-alto"

    @property
    def source_name(self) -> str:
        return "PaloAlto"

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.panos_host or not s.panos_api_key.get_secret_value():
            return False, "PANOS_HOST or PANOS_API_KEY not configured"
        try:
            key = s.panos_api_key.get_secret_value().strip()
            async with httpx.AsyncClient(timeout=12, verify=False) as client:  # noqa: S501
                r = await client.get(f"https://{s.panos_host}/api/?type=version&key={key}")
            return r.status_code == 200 and "<status>success</status>" in r.text, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.panos_host or not s.panos_api_key.get_secret_value():
            return []
        key = s.panos_api_key.get_secret_value().strip()
        vsys = s.panos_vsys or "vsys1"
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:  # noqa: S501
                r = await client.get(
                    f"https://{s.panos_host}/api/",
                    params={
                        "type": "log",
                        "log-type": "threat",
                        "nlogs": "200",
                        "vsys": vsys,
                        "key": key,
                    },
                )
                r.raise_for_status()
            # Parse XML response (vendor API; XML bomb risk bounded by httpx response limits)
            root = ET.fromstring(r.text)  # nosec B314
            events: list[dict[str, Any]] = []
            for entry in root.iter("entry"):
                ev: dict[str, Any] = {}
                for child in entry:
                    ev[child.tag] = child.text
                events.append(ev)
            logger.info("panos.pull fetched %d threat log entries", len(events))
            return events
        except Exception as e:
            logger.warning("panos.pull failed: %s", e)
            return []
