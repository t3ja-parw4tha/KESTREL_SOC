"""Microsoft Sentinel (Azure Log Analytics) pull connector."""

import logging
from typing import Any

import httpx

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)

# KQL: SecurityAlert from last 24h (connector typically runs every 5–15 min)
DEFAULT_QUERY = """
SecurityAlert
| where TimeGenerated > ago(24h)
| order by TimeGenerated desc
| take 500
"""


class SentinelConnector(BaseConnector):
    """Pull SecurityAlert from Azure Log Analytics workspace."""

    @property
    def source_id(self) -> str:
        return "sentinel"

    @property
    def source_name(self) -> str:
        return "Sentinel"

    def _get_token(self) -> str:
        """Obtain OAuth2 token for Azure Resource Manager / Log Analytics."""
        settings = get_settings()
        tenant = (settings.azure_tenant_id or "").strip()
        client_id = (settings.azure_client_id or "").strip()
        client_secret = (settings.azure_client_secret.get_secret_value() or "").strip()
        if not tenant or not client_id or not client_secret:
            raise ValueError("Azure credentials not configured")

        url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://api.loganalytics.io/.default",
            "grant_type": "client_credentials",
        }
        with httpx.Client(timeout=15) as client:
            resp = client.post(url, data=data)
            resp.raise_for_status()
            return resp.json()["access_token"]

    async def test_connection(self) -> tuple[bool, str]:
        """Verify Azure credentials and workspace access."""
        try:
            settings = get_settings()
            workspace_id = (settings.loganalytics_workspace_id or "").strip()
            if not workspace_id:
                return False, "LOGANALYTICS_WORKSPACE_ID not set"
            self._get_token()
            return True, "OK"
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        """Query Log Analytics and return SecurityAlert rows as event dicts."""
        settings = get_settings()
        workspace_id = (settings.loganalytics_workspace_id or "").strip()
        if not workspace_id:
            logger.warning("sentinel.pull skipped: workspace not configured")
            return []

        try:
            token = self._get_token()
        except Exception as e:
            logger.warning("sentinel.pull auth failed: %s", e)
            return []

        url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        body = {"query": DEFAULT_QUERY}

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(url, headers=headers, json=body)
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            logger.warning("sentinel.pull query failed: %s", e)
            return []

        # Response: { "tables": [ { "columns": [...], "name": "PrimaryResult", "rows": [ [...] ] } ] }
        tables = data.get("tables") or []
        if not tables:
            return []
        cols = [c.get("name") for c in tables[0].get("columns") or []]
        rows = tables[0].get("rows") or []
        events = []
        for row in rows:
            ev = dict(zip(cols, row))
            # Ensure id for dedup
            if "Id" not in ev and "SystemAlertId" in ev:
                ev["id"] = ev["SystemAlertId"]
            elif "Id" not in ev:
                ev["id"] = ev.get("TimeGenerated") or ""
            events.append(ev)
        logger.info("sentinel.pull fetched %d alerts", len(events))
        return events
