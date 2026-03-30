import logging
import os
import re
import stat
import uuid
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models import AuditLog
from app.security.rbac import require_permission
from app.security.csrf import verify_csrf

router = APIRouter(prefix="/settings", tags=["settings"])

ENV_PATH = Path(".env")

# ── All env keys accepted by the API ──────────────────────────────────────────
ALLOWED_KEYS = {
    # AI
    "AI_PROVIDER",
    "OPENAI_API_KEY", "OPENAI_MODEL",
    "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL",
    "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_DEPLOYMENT",
    "GEMINI_API_KEY", "GEMINI_MODEL",
    "BEDROCK_MODEL_ID",
    "GROQ_API_KEY", "GROQ_MODEL",
    "MISTRAL_API_KEY", "MISTRAL_MODEL",
    "OLLAMA_BASE_URL", "OLLAMA_MODEL",
    # Microsoft Azure shared (Sentinel / Defender for Cloud / Azure AD / M365)
    "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
    "LOGANALYTICS_WORKSPACE_ID", "AZURE_SUBSCRIPTION_ID",
    # AWS (GuardDuty + CloudTrail)
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION",
    "CLOUDTRAIL_TRAIL_NAME",
    # CrowdStrike Falcon
    "CROWDSTRIKE_CLIENT_ID", "CROWDSTRIKE_CLIENT_SECRET", "CROWDSTRIKE_BASE_URL",
    # SentinelOne
    "S1_CONSOLE_URL", "S1_API_TOKEN", "S1_SITE_ID",
    # Carbon Black Cloud
    "CBC_ORG_KEY", "CBC_API_KEY", "CBC_API_ID", "CBC_BASE_URL",
    # Cortex XDR
    "CORTEX_API_KEY", "CORTEX_API_KEY_ID", "CORTEX_BASE_URL",
    # Splunk
    "SPLUNK_HOST", "SPLUNK_PORT", "SPLUNK_TOKEN", "SPLUNK_QUERY",
    # IBM QRadar
    "QRADAR_HOST", "QRADAR_TOKEN",
    # Elastic Security
    "ELASTIC_HOST", "ELASTIC_API_KEY",
    # Okta
    "OKTA_DOMAIN", "OKTA_API_TOKEN",
    # Palo Alto NGFW
    "PANOS_HOST", "PANOS_API_KEY", "PANOS_VSYS",
    # Fortinet FortiGate
    "FORTIGATE_HOST", "FORTIGATE_API_KEY", "FORTIGATE_VDOM",
    # Microsoft 365 Defender
    "M365_TENANT_ID", "M365_CLIENT_ID", "M365_CLIENT_SECRET",
    # Google Workspace
    "GWORKSPACE_SERVICE_ACCOUNT_KEY", "GWORKSPACE_ADMIN_EMAIL",
    # GCP Security Command Center
    "GCP_ORG_ID", "GCP_SERVICE_ACCOUNT_KEY",
    # Tenable.io
    "TENABLE_ACCESS_KEY", "TENABLE_SECRET_KEY",
    # Qualys VMDR
    "QUALYS_API_URL", "QUALYS_USERNAME", "QUALYS_PASSWORD",
    # Threat Intel / Enrichment
    "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "SHODAN_API_KEY",
    # Suricata (file path)
    "SURICATA_EVE_PATH",
    # Notifications
    "SLACK_WEBHOOK_URL", "ALERT_EMAIL",
}

# Values that are redacted in API responses
SENSITIVE = {
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AZURE_OPENAI_API_KEY",
    "GEMINI_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY",
    "AZURE_CLIENT_SECRET",
    "AWS_SECRET_ACCESS_KEY",
    "CROWDSTRIKE_CLIENT_SECRET",
    "S1_API_TOKEN",
    "CBC_API_KEY",
    "CORTEX_API_KEY",
    "SPLUNK_TOKEN",
    "QRADAR_TOKEN",
    "ELASTIC_API_KEY",
    "OKTA_API_TOKEN",
    "PANOS_API_KEY",
    "FORTIGATE_API_KEY",
    "M365_CLIENT_SECRET",
    "GWORKSPACE_SERVICE_ACCOUNT_KEY",
    "GCP_SERVICE_ACCOUNT_KEY",
    "TENABLE_ACCESS_KEY", "TENABLE_SECRET_KEY",
    "QUALYS_PASSWORD",
    "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "SHODAN_API_KEY",
    "AZURE_CLIENT_ID",  # treat as sensitive
}

REDACTED = "[REDACTED]"


def read_env() -> dict[str, str]:
    """Read current .env file into a dict."""
    if not ENV_PATH.exists():
        return {}
    result: dict[str, str] = {}
    for line in ENV_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        result[key.strip()] = value.strip().strip('"').strip("'")
    return result


_settings_logger = logging.getLogger("app.security.settings_audit")
_UNSAFE_VALUE_PATTERN = re.compile(r"[\n\r\x00`$;|&]")


def _sanitize_setting_value(value: str) -> str:
    if _UNSAFE_VALUE_PATTERN.search(value):
        raise HTTPException(status_code=400, detail="Setting value contains unsafe characters")
    return value.strip()


def write_env(data: dict[str, str]) -> None:
    lines: list[str] = []
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                lines.append(line)
                continue
            key = stripped.partition("=")[0].strip()
            if key not in data:
                lines.append(line)
    for key, value in data.items():
        lines.append(f'{key}="{value}"')
    ENV_PATH.write_text("\n".join(lines) + "\n")
    try:
        os.chmod(ENV_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def redact(data: dict[str, str]) -> dict[str, str]:
    return {k: (REDACTED if k in SENSITIVE and v else v) for k, v in data.items()}


class SettingsUpdate(BaseModel):
    key: str
    value: str


class SettingsBulkUpdate(BaseModel):
    settings: dict[str, str]


@router.get("")
async def get_settings_view(
    _admin: Annotated[dict, Depends(require_permission("admin:write"))],
):
    current = read_env()
    filtered = {k: v for k, v in current.items() if k in ALLOWED_KEYS}
    return {
        "settings": redact(filtered),
        "configured": {
            "ai": bool(current.get("OPENAI_API_KEY") or current.get("ANTHROPIC_API_KEY")
                       or current.get("GEMINI_API_KEY") or current.get("GROQ_API_KEY")
                       or current.get("MISTRAL_API_KEY") or current.get("OLLAMA_BASE_URL")),
            "openai": bool(current.get("OPENAI_API_KEY")),
            "anthropic": bool(current.get("ANTHROPIC_API_KEY")),
            "azure_openai": bool(current.get("AZURE_OPENAI_API_KEY") and current.get("AZURE_OPENAI_ENDPOINT")),
            "gemini": bool(current.get("GEMINI_API_KEY")),
            "bedrock": bool(current.get("AWS_ACCESS_KEY_ID") and current.get("AWS_SECRET_ACCESS_KEY")),
            "groq": bool(current.get("GROQ_API_KEY")),
            "mistral": bool(current.get("MISTRAL_API_KEY")),
            "ollama": bool(current.get("OLLAMA_BASE_URL")),
            "sentinel": bool(current.get("AZURE_TENANT_ID") and current.get("AZURE_CLIENT_ID")),
            "splunk": bool(current.get("SPLUNK_HOST") and current.get("SPLUNK_TOKEN")),
            "qradar": bool(current.get("QRADAR_HOST") and current.get("QRADAR_TOKEN")),
            "elastic-siem": bool(current.get("ELASTIC_HOST") and current.get("ELASTIC_API_KEY")),
            "guardduty": bool(current.get("AWS_ACCESS_KEY_ID")),
            "azure-defender": bool(current.get("AZURE_TENANT_ID") and current.get("AZURE_SUBSCRIPTION_ID")),
            "gcp-scc": bool(current.get("GCP_ORG_ID") and current.get("GCP_SERVICE_ACCOUNT_KEY")),
            "aws-cloudtrail": bool(current.get("AWS_ACCESS_KEY_ID")),
            "crowdstrike": bool(current.get("CROWDSTRIKE_CLIENT_ID") and current.get("CROWDSTRIKE_CLIENT_SECRET")),
            "sentinelone": bool(current.get("S1_CONSOLE_URL") and current.get("S1_API_TOKEN")),
            "carbonblack": bool(current.get("CBC_ORG_KEY") and current.get("CBC_API_KEY")),
            "cortex-xdr": bool(current.get("CORTEX_API_KEY") and current.get("CORTEX_BASE_URL")),
            "azure-ad": bool(current.get("AZURE_TENANT_ID") and current.get("AZURE_CLIENT_ID")),
            "okta": bool(current.get("OKTA_DOMAIN") and current.get("OKTA_API_TOKEN")),
            "palo-alto": bool(current.get("PANOS_HOST") and current.get("PANOS_API_KEY")),
            "fortinet": bool(current.get("FORTIGATE_HOST") and current.get("FORTIGATE_API_KEY")),
            "microsoft-365": bool(current.get("M365_TENANT_ID") and current.get("M365_CLIENT_ID")),
            "google-workspace": bool(current.get("GWORKSPACE_SERVICE_ACCOUNT_KEY")),
            "virustotal": bool(current.get("VIRUSTOTAL_API_KEY")),
            "abuseipdb": bool(current.get("ABUSEIPDB_API_KEY")),
            "shodan": bool(current.get("SHODAN_API_KEY")),
            "tenable": bool(current.get("TENABLE_ACCESS_KEY") and current.get("TENABLE_SECRET_KEY")),
            "qualys": bool(current.get("QUALYS_API_URL") and current.get("QUALYS_USERNAME")),
            "slack": bool(current.get("SLACK_WEBHOOK_URL")),
        },
    }


@router.post("")
async def update_settings(
    body: SettingsBulkUpdate,
    _admin: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: None = Depends(verify_csrf),
    db: AsyncSession = Depends(get_db),
):
    bad_keys = set(body.settings.keys()) - ALLOWED_KEYS
    if bad_keys:
        raise HTTPException(status_code=400, detail=f"Unknown settings keys: {bad_keys}")
    skip = {k for k, v in body.settings.items() if v == REDACTED}
    to_write = {}
    for k, v in body.settings.items():
        if k in skip or not v.strip():
            continue
        to_write[k] = _sanitize_setting_value(v)
    current = read_env()
    old_values = {k: current.get(k) for k in to_write}
    current.update(to_write)
    write_env(current)
    get_settings.cache_clear()
    admin_id = str(_admin.get("sub", "unknown"))
    admin_name = _admin.get("username") or admin_id
    changed_keys = list(to_write.keys())
    safe_keys = [k for k in changed_keys if k not in SENSITIVE]
    redacted_count = len([k for k in changed_keys if k in SENSITIVE])
    _settings_logger.warning(
        "Settings updated by user=%s safe_keys=%s sensitive_changed=%d",
        admin_id, safe_keys, redacted_count,
    )
    # Audit log each changed setting
    try:
        for setting_key, new_value in to_write.items():
            old_value = old_values.get(setting_key)
            audit = AuditLog(
                id=str(uuid.uuid4()),
                action="settings.update",
                alert_id=None,
                analyst=admin_name,
                details={
                    "setting_key": setting_key,
                    "old": REDACTED if setting_key in SENSITIVE else old_value,
                    "new": REDACTED if setting_key in SENSITIVE else new_value,
                },
            )
            db.add(audit)
        await db.commit()
    except Exception:
        _settings_logger.warning("Audit log write failed for settings update by user=%s", admin_id)
    return {"updated": changed_keys, "skipped": list(skip)}


@router.delete("/{key}")
async def delete_setting(
    key: str,
    _admin: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: None = Depends(verify_csrf),
    db: AsyncSession = Depends(get_db),
):
    if key not in ALLOWED_KEYS:
        raise HTTPException(status_code=400, detail="Unknown key")
    current = read_env()
    old_value = current.get(key)
    current.pop(key, None)
    write_env(current)
    get_settings.cache_clear()
    admin_id = str(_admin.get("sub", "unknown"))
    admin_name = _admin.get("username") or admin_id
    logged_key = "[REDACTED_SENSITIVE_KEY]" if key in SENSITIVE else key
    _settings_logger.warning("Setting deleted by user=%s key=%s", admin_id, logged_key)
    # Audit log the deletion
    try:
        audit = AuditLog(
            id=str(uuid.uuid4()),
            action="settings.delete",
            alert_id=None,
            analyst=admin_name,
            details={
                "setting_key": logged_key,
                "old": REDACTED if key in SENSITIVE else old_value,
                "new": None,
            },
        )
        db.add(audit)
        await db.commit()
    except Exception:
        _settings_logger.warning("Audit log write failed for settings delete by user=%s key=%s", admin_id, logged_key)
    return {"deleted": key}


# ── Connection test helpers ────────────────────────────────────────────────────

async def _azure_oauth_token(tenant: str, client_id: str, client_secret: str, scope: str) -> str:
    """Obtain an Azure OAuth2 token. Raises on failure."""
    import httpx
    async with httpx.AsyncClient(timeout=12) as client:
        r = await client.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data={"client_id": client_id, "client_secret": client_secret,
                  "scope": scope, "grant_type": "client_credentials"},
        )
        if r.status_code != 200:
            raise ValueError(f"Azure auth failed: HTTP {r.status_code}")
        return r.json()["access_token"]


@router.post("/test/{source}")
async def test_connection(
    source: str,
    _admin: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: None = Depends(verify_csrf),
):
    """Test connectivity for a configured source. Returns {status, message}."""
    import httpx
    env = read_env()

    def ok(msg: str) -> dict:
        return {"status": "ok", "message": msg}

    def err(msg: str) -> dict:
        return {"status": "error", "message": msg}

    def missing(*keys: str) -> str | None:
        """Return first missing required key, or None if all present."""
        for k in keys:
            if not env.get(k, "").strip():
                return k
        return None

    try:
        # ── Microsoft Sentinel ───────────────────────────────────────────────
        if source == "sentinel":
            m = missing("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "LOGANALYTICS_WORKSPACE_ID")
            if m:
                return err(f"Missing required field: {m}")
            await _azure_oauth_token(env["AZURE_TENANT_ID"], env["AZURE_CLIENT_ID"],
                                     env["AZURE_CLIENT_SECRET"], "https://api.loganalytics.io/.default")
            return ok("Sentinel connection successful — Azure credentials valid")

        # ── Splunk ───────────────────────────────────────────────────────────
        if source == "splunk":
            m = missing("SPLUNK_HOST", "SPLUNK_TOKEN")
            if m:
                return err(f"Missing required field: {m}")
            port = env.get("SPLUNK_PORT", "8089")
            async with httpx.AsyncClient(timeout=12, verify=False) as client:  # noqa: S501
                r = await client.get(
                    f"https://{env['SPLUNK_HOST']}:{port}/services/server/info?output_mode=json",
                    headers={"Authorization": f"Bearer {env['SPLUNK_TOKEN']}"},
                )
            if r.status_code == 200:
                return ok("Splunk connection successful — REST API reachable")
            return err(f"Splunk API returned HTTP {r.status_code}")

        # ── IBM QRadar ───────────────────────────────────────────────────────
        if source == "qradar":
            m = missing("QRADAR_HOST", "QRADAR_TOKEN")
            if m:
                return err(f"Missing required field: {m}")
            async with httpx.AsyncClient(timeout=12, verify=False) as client:  # noqa: S501
                r = await client.get(
                    f"https://{env['QRADAR_HOST']}/api/system/information",
                    headers={"SEC": env["QRADAR_TOKEN"], "Accept": "application/json"},
                )
            if r.status_code == 200:
                return ok("QRadar connection successful")
            return err(f"QRadar API returned HTTP {r.status_code}")

        # ── Elastic Security ─────────────────────────────────────────────────
        if source == "elastic-siem":
            m = missing("ELASTIC_HOST", "ELASTIC_API_KEY")
            if m:
                return err(f"Missing required field: {m}")
            async with httpx.AsyncClient(timeout=12, verify=False) as client:  # noqa: S501
                r = await client.get(
                    f"{env['ELASTIC_HOST'].rstrip('/')}/_cluster/health",
                    headers={"Authorization": f"ApiKey {env['ELASTIC_API_KEY']}"},
                )
            if r.status_code == 200:
                return ok("Elastic Security connection successful")
            return err(f"Elastic API returned HTTP {r.status_code}")

        # ── AWS GuardDuty ────────────────────────────────────────────────────
        if source == "guardduty":
            m = missing("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
            if m:
                return err(f"Missing required field: {m}")
            import boto3
            region = env.get("AWS_REGION", "us-east-1")
            gd = boto3.client(
                "guardduty",
                aws_access_key_id=env["AWS_ACCESS_KEY_ID"],
                aws_secret_access_key=env["AWS_SECRET_ACCESS_KEY"],
                region_name=region,
            )
            import asyncio
            await asyncio.to_thread(gd.list_detectors)
            return ok(f"GuardDuty connection successful — region {region}")

        # ── Microsoft Defender for Cloud ─────────────────────────────────────
        if source == "azure-defender":
            m = missing("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID")
            if m:
                return err(f"Missing required field: {m}")
            token = await _azure_oauth_token(
                env["AZURE_TENANT_ID"], env["AZURE_CLIENT_ID"],
                env["AZURE_CLIENT_SECRET"], "https://management.azure.com/.default")
            sub = env["AZURE_SUBSCRIPTION_ID"]
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Security/alerts"
                    "?api-version=2022-01-01&$top=1",
                    headers={"Authorization": f"Bearer {token}"},
                )
            if r.status_code in (200, 204):
                return ok("Defender for Cloud connection successful")
            return err(f"Defender for Cloud API returned HTTP {r.status_code}")

        # ── GCP Security Command Center ───────────────────────────────────────
        if source == "gcp-scc":
            m = missing("GCP_ORG_ID", "GCP_SERVICE_ACCOUNT_KEY")
            if m:
                return err(f"Missing required field: {m}")
            try:
                import json
                import google.auth
                from google.oauth2 import service_account
                import google.auth.transport.requests
                key_data = env["GCP_SERVICE_ACCOUNT_KEY"]
                creds_dict = json.loads(key_data) if key_data.strip().startswith("{") else json.loads(Path(key_data).read_text())
                creds = service_account.Credentials.from_service_account_info(
                    creds_dict,
                    scopes=["https://www.googleapis.com/auth/cloud-platform"],
                )
                req = google.auth.transport.requests.Request()
                import asyncio
                await asyncio.to_thread(creds.refresh, req)
                return ok("GCP SCC credentials valid — token obtained")
            except Exception as e:
                _settings_logger.warning("GCP SCC credential test failed: %s", e)
                return err("GCP SCC credential validation failed — check service account key")

        # ── AWS CloudTrail ───────────────────────────────────────────────────
        if source == "aws-cloudtrail":
            m = missing("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
            if m:
                return err(f"Missing required field: {m}")
            import boto3
            import asyncio
            region = env.get("AWS_REGION", "us-east-1")
            ct = boto3.client(
                "cloudtrail",
                aws_access_key_id=env["AWS_ACCESS_KEY_ID"],
                aws_secret_access_key=env["AWS_SECRET_ACCESS_KEY"],
                region_name=region,
            )
            await asyncio.to_thread(ct.describe_trails, includeShadowTrails=False)
            return ok(f"CloudTrail connection successful — region {region}")

        # ── CrowdStrike Falcon ───────────────────────────────────────────────
        if source == "crowdstrike":
            m = missing("CROWDSTRIKE_CLIENT_ID", "CROWDSTRIKE_CLIENT_SECRET")
            if m:
                return err(f"Missing required field: {m}")
            base = env.get("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com").rstrip("/")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.post(
                    f"{base}/oauth2/token",
                    data={
                        "client_id": env["CROWDSTRIKE_CLIENT_ID"],
                        "client_secret": env["CROWDSTRIKE_CLIENT_SECRET"],
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            if r.status_code == 201:
                return ok("CrowdStrike Falcon connection successful — OAuth2 token obtained")
            return err(f"CrowdStrike auth failed: HTTP {r.status_code}")

        # ── SentinelOne ──────────────────────────────────────────────────────
        if source == "sentinelone":
            m = missing("S1_CONSOLE_URL", "S1_API_TOKEN")
            if m:
                return err(f"Missing required field: {m}")
            base = env["S1_CONSOLE_URL"].rstrip("/")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    f"{base}/web/api/v2.1/system/status",
                    headers={"Authorization": f"ApiToken {env['S1_API_TOKEN']}"},
                )
            if r.status_code == 200:
                return ok("SentinelOne connection successful")
            return err(f"SentinelOne API returned HTTP {r.status_code}")

        # ── Carbon Black Cloud ───────────────────────────────────────────────
        if source == "carbonblack":
            m = missing("CBC_ORG_KEY", "CBC_API_KEY", "CBC_API_ID", "CBC_BASE_URL")
            if m:
                return err(f"Missing required field: {m}")
            org = env["CBC_ORG_KEY"]
            token = f"{env['CBC_API_KEY']}/{env['CBC_API_ID']}"
            base = env["CBC_BASE_URL"].rstrip("/")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    f"{base}/appservices/v6/orgs/{org}/alerts/workflow_states",
                    headers={"X-Auth-Token": token},
                )
            if r.status_code == 200:
                return ok("Carbon Black Cloud connection successful")
            return err(f"Carbon Black API returned HTTP {r.status_code}")

        # ── Palo Alto Cortex XDR ─────────────────────────────────────────────
        if source == "cortex-xdr":
            m = missing("CORTEX_API_KEY", "CORTEX_API_KEY_ID", "CORTEX_BASE_URL")
            if m:
                return err(f"Missing required field: {m}")
            import hashlib
            import string
            import secrets
            import time
            nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
            ts = str(int(time.time() * 1000))
            api_key = env["CORTEX_API_KEY"]
            auth_string = api_key + nonce + ts
            auth_hash = hashlib.sha256(auth_string.encode()).hexdigest()
            headers = {
                "x-xdr-auth-id": str(env["CORTEX_API_KEY_ID"]),
                "x-xdr-nonce": nonce,
                "x-xdr-timestamp": ts,
                "x-xdr-auth-hash": auth_hash,
                "Content-Type": "application/json",
            }
            base = env["CORTEX_BASE_URL"].rstrip("/")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.post(
                    f"{base}/public_api/v1/alerts/get_alerts_multi_events",
                    headers=headers,
                    json={"request_data": {"filters": [], "paging": {"from": 0, "to": 1}}},
                )
            if r.status_code == 200:
                return ok("Cortex XDR connection successful")
            return err(f"Cortex XDR API returned HTTP {r.status_code}")

        # ── Azure Active Directory (Graph API) ───────────────────────────────
        if source == "azure-ad":
            m = missing("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")
            if m:
                return err(f"Missing required field: {m}")
            token = await _azure_oauth_token(
                env["AZURE_TENANT_ID"], env["AZURE_CLIENT_ID"],
                env["AZURE_CLIENT_SECRET"], "https://graph.microsoft.com/.default")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$top=1",
                    headers={"Authorization": f"Bearer {token}"},
                )
            if r.status_code in (200, 403):
                # 403 = authenticated but licence missing — credentials still valid
                return ok("Azure AD connection successful — Graph API reachable")
            return err(f"Azure AD Graph API returned HTTP {r.status_code}")

        # ── Okta ─────────────────────────────────────────────────────────────
        if source == "okta":
            m = missing("OKTA_DOMAIN", "OKTA_API_TOKEN")
            if m:
                return err(f"Missing required field: {m}")
            domain = env["OKTA_DOMAIN"].lstrip("https://").rstrip("/")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    f"https://{domain}/api/v1/users?limit=1",
                    headers={"Authorization": f"SSWS {env['OKTA_API_TOKEN']}"},
                )
            if r.status_code == 200:
                return ok("Okta connection successful")
            return err(f"Okta API returned HTTP {r.status_code}")

        # ── Palo Alto NGFW (PAN-OS XML API) ──────────────────────────────────
        if source == "palo-alto":
            m = missing("PANOS_HOST", "PANOS_API_KEY")
            if m:
                return err(f"Missing required field: {m}")
            async with httpx.AsyncClient(timeout=12, verify=False) as client:  # noqa: S501
                r = await client.get(
                    f"https://{env['PANOS_HOST']}/api/?type=version&key={env['PANOS_API_KEY']}",
                )
            if r.status_code == 200 and "<status>success</status>" in r.text:
                return ok("Palo Alto NGFW connection successful — API key valid")
            return err(f"PAN-OS API returned HTTP {r.status_code}")

        # ── Fortinet FortiGate ────────────────────────────────────────────────
        if source == "fortinet":
            m = missing("FORTIGATE_HOST", "FORTIGATE_API_KEY")
            if m:
                return err(f"Missing required field: {m}")
            vdom = env.get("FORTIGATE_VDOM", "root")
            async with httpx.AsyncClient(timeout=12, verify=False) as client:  # noqa: S501
                r = await client.get(
                    f"https://{env['FORTIGATE_HOST']}/api/v2/monitor/system/status?vdom={vdom}",
                    headers={"Authorization": f"Bearer {env['FORTIGATE_API_KEY']}"},
                )
            if r.status_code == 200:
                return ok("FortiGate connection successful")
            return err(f"FortiGate API returned HTTP {r.status_code}")

        # ── Microsoft 365 Defender ────────────────────────────────────────────
        if source == "microsoft-365":
            m = missing("M365_TENANT_ID", "M365_CLIENT_ID", "M365_CLIENT_SECRET")
            if m:
                return err(f"Missing required field: {m}")
            token = await _azure_oauth_token(
                env["M365_TENANT_ID"], env["M365_CLIENT_ID"],
                env["M365_CLIENT_SECRET"], "https://graph.microsoft.com/.default")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    "https://graph.microsoft.com/v1.0/security/incidents?$top=1",
                    headers={"Authorization": f"Bearer {token}"},
                )
            if r.status_code in (200, 403):
                return ok("Microsoft 365 Defender connection successful")
            return err(f"M365 Defender API returned HTTP {r.status_code}")

        # ── Google Workspace ──────────────────────────────────────────────────
        if source == "google-workspace":
            m = missing("GWORKSPACE_SERVICE_ACCOUNT_KEY", "GWORKSPACE_ADMIN_EMAIL")
            if m:
                return err(f"Missing required field: {m}")
            try:
                import json
                import asyncio
                from google.oauth2 import service_account
                import google.auth.transport.requests
                key_raw = env["GWORKSPACE_SERVICE_ACCOUNT_KEY"]
                creds_dict = json.loads(key_raw) if key_raw.strip().startswith("{") else json.loads(Path(key_raw).read_text())
                creds = service_account.Credentials.from_service_account_info(
                    creds_dict,
                    scopes=["https://www.googleapis.com/auth/admin.reports.audit.readonly"],
                    subject=env["GWORKSPACE_ADMIN_EMAIL"],
                )
                req = google.auth.transport.requests.Request()
                await asyncio.to_thread(creds.refresh, req)
                return ok("Google Workspace credentials valid — token obtained")
            except Exception as e:
                _settings_logger.warning("Google Workspace credential test failed: %s", e)
                return err("Google Workspace credential validation failed — check service account key")

        # ── VirusTotal ────────────────────────────────────────────────────────
        if source == "virustotal":
            if not env.get("VIRUSTOTAL_API_KEY"):
                return err("VIRUSTOTAL_API_KEY not configured")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                    headers={"x-apikey": env["VIRUSTOTAL_API_KEY"]},
                )
            if r.status_code == 200:
                return ok("VirusTotal connection successful")
            return err(f"VirusTotal API returned HTTP {r.status_code}")

        # ── AbuseIPDB ─────────────────────────────────────────────────────────
        if source == "abuseipdb":
            if not env.get("ABUSEIPDB_API_KEY"):
                return err("ABUSEIPDB_API_KEY not configured")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": env["ABUSEIPDB_API_KEY"]},
                    params={"ipAddress": "8.8.8.8"},
                )
            if r.status_code == 200:
                return ok("AbuseIPDB connection successful")
            return err(f"AbuseIPDB API returned HTTP {r.status_code}")

        # ── Shodan ────────────────────────────────────────────────────────────
        if source == "shodan":
            if not env.get("SHODAN_API_KEY"):
                return err("SHODAN_API_KEY not configured")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    f"https://api.shodan.io/api-info?key={env['SHODAN_API_KEY']}",
                )
            if r.status_code == 200:
                return ok("Shodan connection successful")
            return err(f"Shodan API returned HTTP {r.status_code}")

        # ── Tenable.io ────────────────────────────────────────────────────────
        if source == "tenable":
            m = missing("TENABLE_ACCESS_KEY", "TENABLE_SECRET_KEY")
            if m:
                return err(f"Missing required field: {m}")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    "https://cloud.tenable.com/session",
                    headers={
                        "X-ApiKeys": f"accessKey={env['TENABLE_ACCESS_KEY']}; secretKey={env['TENABLE_SECRET_KEY']}",
                    },
                )
            if r.status_code == 200:
                return ok("Tenable.io connection successful")
            return err(f"Tenable API returned HTTP {r.status_code}")

        # ── Qualys VMDR ───────────────────────────────────────────────────────
        if source == "qualys":
            m = missing("QUALYS_API_URL", "QUALYS_USERNAME", "QUALYS_PASSWORD")
            if m:
                return err(f"Missing required field: {m}")
            api_url = env["QUALYS_API_URL"].strip().rstrip("/")
            if not api_url.startswith("http"):
                api_url = f"https://{api_url}"
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.post(
                    f"{api_url}/api/2.0/fo/session/",
                    data={"action": "login", "username": env["QUALYS_USERNAME"], "password": env["QUALYS_PASSWORD"]},
                    headers={"X-Requested-With": "KestrelSOC"},
                )
            if r.status_code == 200 and "Logged in" in r.text:
                return ok("Qualys connection successful")
            if r.status_code == 200:
                return ok("Qualys API reachable")
            return err(f"Qualys API returned HTTP {r.status_code}")

        # ── AI Provider Tests ─────────────────────────────────────────────────

        if source == "openai":
            if not env.get("OPENAI_API_KEY"):
                return err("OPENAI_API_KEY not configured")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {env['OPENAI_API_KEY']}"},
                )
            if r.status_code == 200:
                return ok("OpenAI connection successful — API key valid")
            return err(f"OpenAI API returned HTTP {r.status_code}")

        if source == "anthropic":
            if not env.get("ANTHROPIC_API_KEY"):
                return err("ANTHROPIC_API_KEY not configured")
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": env["ANTHROPIC_API_KEY"],
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={"model": "claude-haiku-4-5-20251001", "max_tokens": 1,
                          "messages": [{"role": "user", "content": "hi"}]},
                )
            if r.status_code == 200:
                return ok("Anthropic connection successful — API key valid")
            return err(f"Anthropic API returned HTTP {r.status_code}")

        if source == "azure-openai":
            m = missing("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT")
            if m:
                return err(f"Missing required field: {m}")
            endpoint = env["AZURE_OPENAI_ENDPOINT"].rstrip("/")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    f"{endpoint}/openai/models?api-version=2024-02-01",
                    headers={"api-key": env["AZURE_OPENAI_API_KEY"]},
                )
            if r.status_code == 200:
                return ok("Azure OpenAI connection successful")
            return err(f"Azure OpenAI API returned HTTP {r.status_code}")

        if source == "gemini":
            if not env.get("GEMINI_API_KEY"):
                return err("GEMINI_API_KEY not configured")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    f"https://generativelanguage.googleapis.com/v1beta/models?key={env['GEMINI_API_KEY']}",
                )
            if r.status_code == 200:
                return ok("Google Gemini connection successful — API key valid")
            return err(f"Gemini API returned HTTP {r.status_code}")

        if source == "bedrock":
            m = missing("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
            if m:
                return err(f"Missing required field: {m}")
            import boto3
            import asyncio
            region = env.get("AWS_REGION", "us-east-1")
            br = boto3.client(
                "bedrock",
                aws_access_key_id=env["AWS_ACCESS_KEY_ID"],
                aws_secret_access_key=env["AWS_SECRET_ACCESS_KEY"],
                region_name=region,
            )
            await asyncio.to_thread(br.list_foundation_models)
            return ok(f"AWS Bedrock connection successful — region {region}")

        if source == "groq":
            if not env.get("GROQ_API_KEY"):
                return err("GROQ_API_KEY not configured")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    "https://api.groq.com/openai/v1/models",
                    headers={"Authorization": f"Bearer {env['GROQ_API_KEY']}"},
                )
            if r.status_code == 200:
                return ok("Groq connection successful — API key valid")
            return err(f"Groq API returned HTTP {r.status_code}")

        if source == "mistral":
            if not env.get("MISTRAL_API_KEY"):
                return err("MISTRAL_API_KEY not configured")
            async with httpx.AsyncClient(timeout=12) as client:
                r = await client.get(
                    "https://api.mistral.ai/v1/models",
                    headers={"Authorization": f"Bearer {env['MISTRAL_API_KEY']}"},
                )
            if r.status_code == 200:
                return ok("Mistral AI connection successful — API key valid")
            return err(f"Mistral API returned HTTP {r.status_code}")

        if source == "ollama":
            base = env.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(f"{base}/api/tags")
            if r.status_code == 200:
                models = [m.get("name") for m in r.json().get("models", [])]
                return ok(f"Ollama connection successful — {len(models)} models available")
            return err(f"Ollama API returned HTTP {r.status_code}")

        # ── Push-based sources (no API to test) ───────────────────────────────
        if source in {"windows", "syslog", "linux-auditd", "suricata", "snort", "zeek"}:
            return {"status": "push", "message": f"{source} is a push-based source — no API to test. Send events to POST /api/v1/ingest to activate."}

        return err(f"No test handler for source: {source}")

    except Exception as e:
        _settings_logger.warning("Connection test failed for source=%s: %s", source, e)
        return err("Connection test failed — check configuration and network reachability")
