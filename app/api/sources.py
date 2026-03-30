"""Sources API router."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models.alert import Alert
from app.security.rbac import require_permission
from app.services.source_health import build_health_snapshots

router = APIRouter(prefix="/sources", tags=["sources"])


SOURCE_CATALOG: list[dict[str, Any]] = [
    {
        "id": "sentinel",
        "name": "Microsoft Sentinel",
        "type": "SIEM",
        "required": ["azure_tenant_id", "azure_client_id", "azure_client_secret", "loganalytics_workspace_id"],
        "description": "Azure Log Analytics - pulls SecurityAlert & incidents via KQL",
        "push": False,
    },
    {
        "id": "splunk",
        "name": "Splunk Enterprise",
        "type": "SIEM",
        "required": ["splunk_host", "splunk_token"],
        "description": "Splunk SIEM - pull alerts and notable events via REST API",
        "push": False,
    },
    {
        "id": "qradar",
        "name": "IBM QRadar",
        "type": "SIEM",
        "required": ["qradar_host", "qradar_token"],
        "description": "QRadar offenses and events via REST API",
        "push": False,
    },
    {
        "id": "elastic-siem",
        "name": "Elastic SIEM",
        "type": "SIEM",
        "required": ["elastic_host", "elastic_api_key"],
        "description": "Elasticsearch alerts and detection rule findings",
        "push": False,
    },
    {
        "id": "guardduty",
        "name": "AWS GuardDuty",
        "type": "Cloud",
        "required": ["aws_access_key_id", "aws_secret_access_key"],
        "description": "AWS threat detection findings - requires IAM credentials",
        "push": False,
    },
    {
        "id": "azure-defender",
        "name": "Microsoft Defender",
        "type": "Cloud",
        "required": ["azure_tenant_id", "azure_client_id", "azure_client_secret"],
        "description": "Azure Defender for Cloud and Microsoft 365 Defender alerts",
        "push": False,
    },
    {
        "id": "gcp-scc",
        "name": "GCP Security Command Center",
        "type": "Cloud",
        "required": ["gcp_org_id", "gcp_service_account_key"],
        "description": "Google Cloud Security Command Center findings",
        "push": False,
    },
    {
        "id": "aws-cloudtrail",
        "name": "AWS CloudTrail",
        "type": "Cloud",
        "required": ["aws_access_key_id", "aws_secret_access_key"],
        "description": "AWS API activity, IAM changes, and account events",
        "push": False,
    },
    {
        "id": "crowdstrike",
        "name": "CrowdStrike Falcon",
        "type": "EDR",
        "required": ["crowdstrike_client_id", "crowdstrike_client_secret"],
        "description": "CrowdStrike detections and incidents via OAuth2 API",
        "push": False,
    },
    {
        "id": "sentinelone",
        "name": "SentinelOne",
        "type": "EDR",
        "required": ["s1_console_url", "s1_api_token"],
        "description": "Endpoint threat detections via SentinelOne API",
        "push": False,
    },
    {
        "id": "carbonblack",
        "name": "VMware Carbon Black",
        "type": "EDR",
        "required": ["cbc_org_key", "cbc_api_key"],
        "description": "Carbon Black EDR alerts and endpoint activity",
        "push": False,
    },
    {
        "id": "cortex-xdr",
        "name": "Palo Alto Cortex XDR",
        "type": "EDR",
        "required": ["cortex_api_key", "cortex_api_key_id"],
        "description": "Cortex XDR incidents and analytics alerts",
        "push": False,
    },
    {
        "id": "azure-ad",
        "name": "Azure Active Directory",
        "type": "Identity",
        "required": ["azure_tenant_id", "azure_client_id", "azure_client_secret"],
        "description": "Azure AD sign-in events, risky users, and identity protection",
        "push": False,
    },
    {
        "id": "okta",
        "name": "Okta",
        "type": "Identity",
        "required": ["okta_domain", "okta_api_token"],
        "description": "Okta system log - authentication events and policy violations",
        "push": False,
    },
    {
        "id": "palo-alto",
        "name": "Palo Alto Firewall",
        "type": "Network",
        "required": ["panos_host", "panos_api_key"],
        "description": "Palo Alto Networks threat and traffic logs via Panorama API",
        "push": False,
    },
    {
        "id": "fortinet",
        "name": "Fortinet FortiGate",
        "type": "Network",
        "required": ["fortigate_host", "fortigate_api_key"],
        "description": "FortiGate firewall events and IPS alerts",
        "push": False,
    },
    {
        "id": "microsoft-365",
        "name": "Microsoft 365 Defender",
        "type": "Email",
        "required": ["m365_tenant_id", "m365_client_id", "m365_client_secret"],
        "description": "Microsoft 365 email threats, phishing, and collaboration alerts",
        "push": False,
    },
    {
        "id": "google-workspace",
        "name": "Google Workspace",
        "type": "Email",
        "required": ["gworkspace_service_account_key"],
        "description": "Google Workspace audit events and Gmail threat detections",
        "push": False,
    },
    {
        "id": "virustotal",
        "name": "VirusTotal",
        "type": "Enrichment",
        "required": ["virustotal_api_key"],
        "description": "IP, hash, and domain reputation enrichment",
        "push": False,
    },
    {
        "id": "abuseipdb",
        "name": "AbuseIPDB",
        "type": "Enrichment",
        "required": ["abuseipdb_api_key"],
        "description": "IP abuse confidence scoring and reporting",
        "push": False,
    },
    {
        "id": "shodan",
        "name": "Shodan",
        "type": "Enrichment",
        "required": ["shodan_api_key"],
        "description": "Internet exposure data - open ports, banners, and CVEs",
        "push": False,
    },
    {
        "id": "tenable",
        "name": "Tenable.io",
        "type": "Vulnerability",
        "required": ["tenable_access_key", "tenable_secret_key"],
        "description": "Vulnerability scan findings and asset risk scores",
        "push": False,
    },
    {
        "id": "qualys",
        "name": "Qualys VMDR",
        "type": "Vulnerability",
        "required": ["qualys_api_url", "qualys_username", "qualys_password"],
        "description": "Qualys vulnerability management detections",
        "push": False,
    },
    {
        "id": "windows",
        "name": "Windows Event Log",
        "type": "OS",
        "required": [],
        "description": "Windows security events via Winlogbeat or NXLog agent",
        "push": True,
        "status": "push_ready",
    },
    {
        "id": "syslog",
        "name": "Syslog Push",
        "type": "OS",
        "required": [],
        "description": "Generic syslog ingestion - any device that speaks RFC 5424",
        "push": True,
        "status": "push_ready",
    },
    {
        "id": "linux-auditd",
        "name": "Linux Auditd",
        "type": "OS",
        "required": [],
        "description": "Linux audit daemon events via Filebeat or Auditbeat",
        "push": True,
        "status": "push_ready",
    },
    {
        "id": "suricata",
        "name": "Suricata IDS",
        "type": "IDS/IPS",
        "required": [],
        "description": "Suricata network IDS alerts via EVE JSON + Filebeat",
        "push": True,
        "status": "push_ready",
    },
    {
        "id": "snort",
        "name": "Snort",
        "type": "IDS/IPS",
        "required": [],
        "description": "Snort NIDS unified2 output to POST /api/v1/ingest",
        "push": True,
        "status": "push_ready",
    },
    {
        "id": "zeek",
        "name": "Zeek (Bro)",
        "type": "IDS/IPS",
        "required": [],
        "description": "Zeek network visibility logs forwarded via JSON over HTTP",
        "push": True,
        "status": "push_ready",
    },
]


def _is_configured(settings: Any, keys: list[str]) -> bool:
    for key in keys:
        val = getattr(settings, key, "")
        if hasattr(val, "get_secret_value"):
            val = val.get_secret_value()
        if not val:
            return False
    return True


def _build_source_items() -> list[dict[str, Any]]:
    settings = get_settings()
    items = deepcopy(SOURCE_CATALOG)

    for item in items:
        if item.get("push"):
            item["status"] = item.get("status", "push_ready")
        else:
            required = list(item.get("required") or [])
            item["status"] = "connected" if _is_configured(settings, required) else "not_configured"
        item.pop("required", None)

    return items


def _normalize_source_key(source: str) -> str:
    return source.lower().replace("-", "_").replace(" ", "_")


def _match_alert_source(source_id: str, alert_sources: set[str]) -> str | None:
    sid = _normalize_source_key(source_id)
    for db_src in alert_sources:
        norm = _normalize_source_key(db_src)
        if sid in norm or norm in sid:
            return db_src
    return None


@router.get("")
async def list_sources(
    _user: Annotated[dict, Depends(require_permission("sources:read"))],
    db: AsyncSession = Depends(get_db),
):
    sources = _build_source_items()
    configured_count = sum(1 for s in sources if s.get("status") == "connected")

    now = datetime.now(timezone.utc)
    since_24h = now - timedelta(hours=24)

    total_r = await db.execute(
        select(Alert.source, func.count(Alert.id).label("total")).group_by(Alert.source)
    )
    total_by_source: dict[str, int] = {row.source: row.total for row in total_r}

    today_r = await db.execute(
        select(Alert.source, func.count(Alert.id).label("cnt"))
        .where(Alert.created_at >= since_24h)
        .group_by(Alert.source)
    )
    today_by_source: dict[str, int] = {row.source: row.cnt for row in today_r}

    last_r = await db.execute(
        select(Alert.source, func.max(Alert.created_at).label("last_seen")).group_by(Alert.source)
    )
    last_by_source: dict[str, datetime] = {row.source: row.last_seen for row in last_r}

    source_ids = {str(s["id"]) for s in sources}
    snapshots = await build_health_snapshots(db, only_source_ids=source_ids)
    health_by_id = {s.source_id: s for s in snapshots}

    for src in sources:
        source_id = str(src["id"])
        db_key = _match_alert_source(source_id, set(total_by_source.keys()))
        src["events_today"] = today_by_source.get(db_key, 0) if db_key else 0
        src["total_alerts"] = total_by_source.get(db_key, 0) if db_key else 0

        last_dt = last_by_source.get(db_key) if db_key else None
        src["last_seen"] = last_dt.isoformat() if last_dt else None

        health = health_by_id.get(source_id)
        if health is not None:
            src["health"] = {
                "freshness_seconds": health.freshness_seconds,
                "ingest_lag_seconds": health.ingest_lag_seconds,
                "error_budget_remaining_pct": health.error_budget_remaining_pct,
                "error_rate_pct": health.error_rate_pct,
                "window_successes": health.window_successes,
                "window_failures": health.window_failures,
                "consecutive_failures": health.consecutive_failures,
                "is_stale": health.is_stale,
                "last_success_at": health.last_success_at.isoformat() if health.last_success_at else None,
                "last_error_at": health.last_error_at.isoformat() if health.last_error_at else None,
                "last_error_message": health.last_error_message,
            }
            if health.last_success_at is not None:
                src["last_seen"] = health.last_success_at.isoformat()

    stale_count = sum(1 for s in snapshots if s.is_stale)

    return {
        "items": sources,
        "configured_count": configured_count,
        "health_summary": {
            "tracked_sources": len(snapshots),
            "stale_sources": stale_count,
            "healthy_sources": max(0, len(snapshots) - stale_count),
        },
    }


@router.get("/health")
async def source_health_dashboard(
    _user: Annotated[dict, Depends(require_permission("sources:read"))],
    db: AsyncSession = Depends(get_db),
):
    sources = _build_source_items()
    source_ids = {str(s["id"]) for s in sources}
    snapshots = await build_health_snapshots(db, only_source_ids=source_ids)

    stale = [s for s in snapshots if s.is_stale]
    min_error_budget = min((s.error_budget_remaining_pct for s in snapshots), default=100.0)

    return {
        "summary": {
            "tracked_sources": len(snapshots),
            "stale_sources": len(stale),
            "min_error_budget_remaining_pct": round(min_error_budget, 2),
        },
        "items": [
            {
                "source_id": s.source_id,
                "source_name": s.source_name,
                "source_type": s.source_type,
                "is_stale": s.is_stale,
                "freshness_seconds": s.freshness_seconds,
                "ingest_lag_seconds": s.ingest_lag_seconds,
                "error_budget_remaining_pct": s.error_budget_remaining_pct,
                "error_rate_pct": s.error_rate_pct,
                "window_successes": s.window_successes,
                "window_failures": s.window_failures,
                "consecutive_failures": s.consecutive_failures,
                "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
                "last_success_at": s.last_success_at.isoformat() if s.last_success_at else None,
                "last_error_at": s.last_error_at.isoformat() if s.last_error_at else None,
                "last_error_message": s.last_error_message,
            }
            for s in snapshots
        ],
    }
