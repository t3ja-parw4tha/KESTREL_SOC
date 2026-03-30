"""Splunk Enterprise / Splunk Cloud pull connector via REST API."""

import logging
from typing import Any

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class SplunkConnector(BaseConnector):
    """Pull notable events from Splunk via the REST search API."""

    @property
    def source_id(self) -> str:
        return "splunk"

    @property
    def source_name(self) -> str:
        return "Splunk"

    def _base_url(self) -> str:
        s = get_settings()
        host = (s.splunk_host or "").strip()
        port = s.splunk_port or 8089
        return f"https://{host}:{port}"

    def _headers(self) -> dict[str, str]:
        s = get_settings()
        token = (s.splunk_token.get_secret_value() or "").strip()
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/x-www-form-urlencoded"}

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.splunk_host or not s.splunk_token.get_secret_value():
            return False, "SPLUNK_HOST or SPLUNK_TOKEN not configured"
        try:
            async with httpx.AsyncClient(timeout=12, verify=False) as client:  # noqa: S501
                r = await client.get(f"{self._base_url()}/services/server/info?output_mode=json",
                                     headers=self._headers())
            return r.status_code == 200, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.splunk_host or not s.splunk_token.get_secret_value():
            logger.debug("splunk.pull skipped: not configured")
            return []
        query = s.splunk_query or "search index=notable earliest=-5m | head 1000"
        base = self._base_url()
        headers = self._headers()
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:  # noqa: S501
                # Create a oneshot search job
                r = await client.post(
                    f"{base}/services/search/jobs/export",
                    headers=headers,
                    data={"search": query, "output_mode": "json", "earliest_time": "-5m", "latest_time": "now"},
                )
                r.raise_for_status()
            events = []
            for line in r.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                import json
                try:
                    obj = json.loads(line)
                    if obj.get("result"):
                        events.append(obj["result"])
                except json.JSONDecodeError:
                    pass
            logger.info("splunk.pull fetched %d events", len(events))
            return events
        except Exception as e:
            logger.warning("splunk.pull failed: %s", e)
            return []
