"""Palo Alto Cortex XDR pull connector via Public API v1."""

import hashlib
import logging
import secrets
import string
import time
from typing import Any

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


def _make_auth_headers(api_key: str, api_key_id: str) -> dict[str, str]:
    """Generate Cortex XDR HMAC auth headers (nonce + timestamp + SHA256 digest)."""
    nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
    ts = str(int(time.time() * 1000))
    auth_hash = hashlib.sha256((api_key + nonce + ts).encode()).hexdigest()
    return {
        "x-xdr-auth-id": str(api_key_id),
        "x-xdr-nonce": nonce,
        "x-xdr-timestamp": ts,
        "x-xdr-auth-hash": auth_hash,
        "Content-Type": "application/json",
    }


class CortexXDRConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "cortex-xdr"

    @property
    def source_name(self) -> str:
        return "CortexXDR"

    def _base(self) -> str:
        s = get_settings()
        return (s.cortex_base_url or "").rstrip("/")

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        if not s.cortex_api_key.get_secret_value() or not s.cortex_api_key_id or not s.cortex_base_url:
            return False, "CORTEX_API_KEY, CORTEX_API_KEY_ID, or CORTEX_BASE_URL not configured"
        try:
            headers = _make_auth_headers(
                s.cortex_api_key.get_secret_value().strip(),
                s.cortex_api_key_id.strip(),
            )
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.post(
                    f"{self._base()}/public_api/v1/alerts/get_alerts_multi_events",
                    headers=headers,
                    json={"request_data": {"filters": [], "paging": {"from": 0, "to": 1}}},
                )
            return r.status_code == 200, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        if not s.cortex_api_key.get_secret_value() or not s.cortex_api_key_id or not s.cortex_base_url:
            return []
        try:
            headers = _make_auth_headers(
                s.cortex_api_key.get_secret_value().strip(),
                s.cortex_api_key_id.strip(),
            )
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    f"{self._base()}/public_api/v1/alerts/get_alerts_multi_events",
                    headers=headers,
                    json={"request_data": {
                        "filters": [{"field": "severity", "value": ["high", "critical"], "operator": "in"}],
                        "paging": {"from": 0, "to": 200},
                        "sort": {"field": "creation_time", "keyword": "desc"},
                    }},
                )
                r.raise_for_status()
                alerts = r.json().get("reply", {}).get("alerts", [])
            logger.info("cortex_xdr.pull fetched %d alerts", len(alerts))
            return alerts
        except Exception as e:
            logger.warning("cortex_xdr.pull failed: %s", e)
            return []
