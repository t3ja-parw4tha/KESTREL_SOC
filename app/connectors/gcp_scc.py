"""GCP Security Command Center pull connector via google-cloud-securitycenter."""

import asyncio
import json
import logging
from typing import Any

from app.config import get_settings
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


def _pull_sync(org_id: str, sa_key_json: str) -> list[dict[str, Any]]:
    """Synchronous GCP SCC pull — run in executor thread."""
    from google.oauth2 import service_account
    from google.cloud import securitycenter

    credentials = service_account.Credentials.from_service_account_info(
        json.loads(sa_key_json),
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )
    client = securitycenter.SecurityCenterClient(credentials=credentials)
    parent = f"organizations/{org_id}"
    findings: list[dict[str, Any]] = []
    for finding in client.list_findings(
        request={
            "parent": f"{parent}/sources/-",
            "filter": 'state="ACTIVE" AND severity!="LOW"',
            "page_size": 500,
        }
    ):
        f = finding.finding
        findings.append({
            "name": f.name,
            "category": f.category,
            "severity": securitycenter.Finding.Severity(f.severity).name,
            "state": securitycenter.Finding.State(f.state).name,
            "resource_name": f.resource_name,
            "event_time": f.event_time.isoformat() if f.event_time else None,
            "description": f.description,
            "source_properties": dict(f.source_properties),
        })
    return findings


def _test_sync(org_id: str, sa_key_json: str) -> tuple[bool, str]:
    try:
        from google.oauth2 import service_account
        from google.cloud import securitycenter

        credentials = service_account.Credentials.from_service_account_info(
            json.loads(sa_key_json),
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        client = securitycenter.SecurityCenterClient(credentials=credentials)
        parent = f"organizations/{org_id}"
        # Just list sources to confirm connectivity
        next(iter(client.list_sources(request={"parent": parent, "page_size": 1})), None)
        return True, "OK"
    except Exception as e:
        return False, str(e)


class GcpSccConnector(BaseConnector):
    @property
    def source_id(self) -> str:
        return "gcp-scc"

    @property
    def source_name(self) -> str:
        return "GCP-SCC"

    async def test_connection(self) -> tuple[bool, str]:
        s = get_settings()
        org_id = s.gcp_org_id.strip() if s.gcp_org_id else ""
        sa_key = (s.gcp_service_account_key.get_secret_value() or "").strip()
        if not org_id or not sa_key:
            return False, "GCP_ORG_ID or GCP_SERVICE_ACCOUNT_KEY not configured"
        try:
            return await asyncio.to_thread(_test_sync, org_id, sa_key)
        except Exception as e:
            return False, str(e)

    async def pull(self) -> list[dict[str, Any]]:
        s = get_settings()
        org_id = s.gcp_org_id.strip() if s.gcp_org_id else ""
        sa_key = (s.gcp_service_account_key.get_secret_value() or "").strip()
        if not org_id or not sa_key:
            return []
        try:
            events = await asyncio.to_thread(_pull_sync, org_id, sa_key)
            logger.info("gcp_scc.pull fetched %d findings", len(events))
            return events
        except Exception as e:
            logger.warning("gcp_scc.pull failed: %s", e)
            return []
