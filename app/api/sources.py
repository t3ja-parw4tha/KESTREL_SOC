"""Sources API router."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.config import get_settings
from app.security.rbac import require_permission

router = APIRouter(prefix="/sources", tags=["sources"])


@router.get("")
async def list_sources(
    _user: Annotated[dict, Depends(require_permission("sources:read"))],
):
    settings = get_settings()

    def configured(keys: list[str]) -> bool:
        for k in keys:
            val = getattr(settings, k.lower(), "")
            if hasattr(val, "get_secret_value"):
                val = val.get_secret_value()
            if not val:
                return False
        return True

    sources: list[dict[str, object]] = [
        {
            "id": "sentinel",
            "name": "Microsoft Sentinel",
            "type": "SIEM",
            "status": "connected"
            if configured(
                [
                    "azure_tenant_id",
                    "azure_client_id",
                    "azure_client_secret",
                    "loganalytics_workspace_id",
                ]
            )
            else "not_configured",
            "description": "Azure Log Analytics — pulls SecurityAlert via KQL",
            "push": False,
        },
        {
            "id": "guardduty",
            "name": "AWS GuardDuty",
            "type": "Cloud",
            "status": "connected"
            if configured(["aws_access_key_id", "aws_secret_access_key"])
            else "not_configured",
            "description": "AWS threat detection findings",
            "push": False,
        },
        {
            "id": "virustotal",
            "name": "VirusTotal",
            "type": "Enrichment",
            "status": "connected"
            if configured(["virustotal_api_key"])
            else "not_configured",
            "description": "IP and hash reputation enrichment",
            "push": False,
        },
        {
            "id": "abuseipdb",
            "name": "AbuseIPDB",
            "type": "Enrichment",
            "status": "connected"
            if configured(["abuseipdb_api_key"])
            else "not_configured",
            "description": "IP abuse confidence scoring",
            "push": False,
        },
        {
            "id": "suricata",
            "name": "Suricata IDS",
            "type": "IDS/IPS",
            "status": "push_ready",
            "description": "Network IDS — send events to POST /api/v1/ingest",
            "push": True,
        },
        {
            "id": "windows",
            "name": "Windows Event Log",
            "type": "OS",
            "status": "push_ready",
            "description": "Windows security events — send to POST /api/v1/ingest",
            "push": True,
        },
        {
            "id": "defender",
            "name": "Microsoft Defender",
            "type": "EDR",
            "status": "push_ready",
            "description": "Defender alerts — send to POST /api/v1/ingest",
            "push": True,
        },
        {
            "id": "snort",
            "name": "Snort",
            "type": "IDS/IPS",
            "status": "push_ready",
            "description": "Network IDS — send to POST /api/v1/ingest",
            "push": True,
        },
    ]

    configured_count = sum(1 for s in sources if s.get("status") == "connected")

    return {
        "items": sources,
        "configured_count": configured_count,
        "total_pull_sources": 4,
    }
