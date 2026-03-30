"""Elastic Security pull connector via Elasticsearch API."""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class ElasticConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "elastic-siem"

    @property
    def source_name(self) -> str:
        return "ElasticSIEM"

    def _headers(self) -> dict[str, str]:
        s = get_settings()
        return {
            "Authorization": f"ApiKey {(s.elastic_api_key.get_secret_value() or '').strip()}",
            "Content-Type": "application/json",
        }

    def _base(self) -> str:
        s = get_settings()
        return (s.elastic_host or "").strip().rstrip("/")

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.elastic_host or not s.elastic_api_key.get_secret_value():
            return False, "ELASTIC_HOST or ELASTIC_API_KEY not configured"
        try:
            async with httpx.AsyncClient(timeout=12, verify=False) as client:  # noqa: S501
                r = await client.get(f"{self._base()}/_cluster/health", headers=self._headers())
            return r.status_code == 200, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.elastic_host or not s.elastic_api_key.get_secret_value():
            return []
        since = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        query = {
            "size": 500,
            "sort": [{"@timestamp": "desc"}],
            "query": {
                "bool": {
                    "filter": [{"range": {"@timestamp": {"gte": since}}}]
                }
            },
        }
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:  # noqa: S501
                r = await client.post(
                    f"{self._base()}/.alerts-security.alerts-default/_search",
                    headers=self._headers(),
                    json=query,
                )
                r.raise_for_status()
                hits = r.json().get("hits", {}).get("hits", [])
            events = [h.get("_source", {}) for h in hits]
            logger.info("elastic.pull fetched %d alerts", len(events))
            return events
        except Exception as e:
            logger.warning("elastic.pull failed: %s", e)
            return []
