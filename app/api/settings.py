from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.config import get_settings
from app.security.rbac import require_permission
from app.security.csrf import verify_csrf

router = APIRouter(prefix="/settings", tags=["settings"])

ENV_PATH = Path(".env")

ALLOWED_KEYS = {
    # AI
    "OPENAI_API_KEY",
    "AI_PROVIDER",
    "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_DEPLOYMENT",
    # Sentinel
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "LOGANALYTICS_WORKSPACE_ID",
    # AWS
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_REGION",
    # Enrichment
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    # Notifications
    "SLACK_WEBHOOK_URL",
    "ALERT_EMAIL",
    # Suricata
    "SURICATA_EVE_PATH",
}

REDACTED = "[REDACTED]"
SENSITIVE = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AZURE_CLIENT_SECRET",
    "AWS_SECRET_ACCESS_KEY",
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    "AZURE_CLIENT_ID",
}


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


import logging
import os
import re
import stat

_settings_logger = logging.getLogger("app.security.settings_audit")

# Shell metacharacters and newlines that must not appear in setting values
_UNSAFE_VALUE_PATTERN = re.compile(r"[\n\r\x00`$;|&]")


def _sanitize_setting_value(value: str) -> str:
    """Reject setting values containing shell metacharacters or newlines."""
    if _UNSAFE_VALUE_PATTERN.search(value):
        raise HTTPException(
            status_code=400,
            detail="Setting value contains unsafe characters",
        )
    return value.strip()


def write_env(data: dict[str, str]) -> None:
    """Write dict back to .env file safely."""
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
    # Restrict .env file permissions (owner read/write only on POSIX)
    try:
        os.chmod(ENV_PATH, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except OSError:
        pass  # Non-POSIX OS (Windows)


def redact(data: dict[str, str]) -> dict[str, str]:
    """Redact sensitive values before sending to frontend."""
    return {
        k: (REDACTED if k in SENSITIVE and v else v)
        for k, v in data.items()
    }


class SettingsUpdate(BaseModel):
    key: str
    value: str


class SettingsBulkUpdate(BaseModel):
    settings: dict[str, str]


@router.get("")
async def get_settings_view(
    _admin: Annotated[dict, Depends(require_permission("admin:write"))],
):
    """Return current settings with sensitive values redacted."""
    current = read_env()
    filtered = {k: v for k, v in current.items() if k in ALLOWED_KEYS}
    return {
        "settings": redact(filtered),
        "configured": {
            "ai": bool(current.get("OPENAI_API_KEY") or current.get("ANTHROPIC_API_KEY")),
            "sentinel": bool(current.get("AZURE_TENANT_ID") and current.get("AZURE_CLIENT_ID")),
            "guardduty": bool(current.get("AWS_ACCESS_KEY_ID")),
            "virustotal": bool(current.get("VIRUSTOTAL_API_KEY")),
            "abuseipdb": bool(current.get("ABUSEIPDB_API_KEY")),
            "slack": bool(current.get("SLACK_WEBHOOK_URL")),
        },
    }


@router.post("")
async def update_settings(
    body: SettingsBulkUpdate,
    _admin: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: None = Depends(verify_csrf),
):
    """Update multiple settings. Writes to local .env file."""
    bad_keys = set(body.settings.keys()) - ALLOWED_KEYS
    if bad_keys:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown settings keys: {bad_keys}",
        )
    skip = {k for k, v in body.settings.items() if v == REDACTED}
    to_write = {}
    for k, v in body.settings.items():
        if k in skip or not v.strip():
            continue
        to_write[k] = _sanitize_setting_value(v)
    current = read_env()
    current.update(to_write)
    write_env(current)
    get_settings.cache_clear()
    # Audit: log which keys were changed and by whom.
    # Sensitive key names are not logged — only the count of sensitive changes.
    admin_id = _admin.get("sub", "unknown")
    changed_keys = list(to_write.keys())
    safe_keys = [k for k in changed_keys if k not in SENSITIVE]
    redacted_count = len([k for k in changed_keys if k in SENSITIVE])
    _settings_logger.warning(
        "Settings updated by user=%s safe_keys=%s sensitive_changed=%d",
        admin_id,
        safe_keys,
        redacted_count,
    )
    return {"updated": changed_keys, "skipped": list(skip)}


@router.delete("/{key}")
async def delete_setting(
    key: str,
    _admin: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: None = Depends(verify_csrf),
):
    """Remove a setting from .env."""
    if key not in ALLOWED_KEYS:
        raise HTTPException(status_code=400, detail="Unknown key")
    current = read_env()
    current.pop(key, None)
    write_env(current)
    get_settings.cache_clear()
    admin_id = _admin.get("sub", "unknown")
    logged_key = "[REDACTED_SENSITIVE_KEY]" if key in SENSITIVE else key
    _settings_logger.warning("Setting deleted by user=%s key=%s", admin_id, logged_key)
    return {"deleted": key}


@router.post("/test/{source}")
async def test_connection(
    source: str,
    _admin: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: None = Depends(verify_csrf),
):
    """Test a specific source connection."""
    current = read_env()

    if source == "sentinel":
        if not current.get("AZURE_TENANT_ID"):
            return {"status": "error", "message": "Sentinel not configured"}
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    f"https://login.microsoftonline.com/{current['AZURE_TENANT_ID']}/oauth2/v2.0/token",
                    data={
                        "client_id": current.get("AZURE_CLIENT_ID", ""),
                        "client_secret": current.get("AZURE_CLIENT_SECRET", ""),
                        "scope": "https://api.loganalytics.io/.default",
                        "grant_type": "client_credentials",
                    },
                )
            if r.status_code == 200:
                return {"status": "ok", "message": "Sentinel connection successful"}
            return {"status": "error", "message": f"Auth failed: {r.status_code}"}
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e)}

    if source == "virustotal":
        if not current.get("VIRUSTOTAL_API_KEY"):
            return {"status": "error", "message": "VirusTotal not configured"}
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                    headers={"x-apikey": current["VIRUSTOTAL_API_KEY"]},
                )
            if r.status_code == 200:
                return {"status": "ok", "message": "VirusTotal connection successful"}
            return {"status": "error", "message": f"API error: {r.status_code}"}
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e)}

    if source == "abuseipdb":
        if not current.get("ABUSEIPDB_API_KEY"):
            return {"status": "error", "message": "AbuseIPDB not configured"}
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": current["ABUSEIPDB_API_KEY"]},
                    params={"ipAddress": "8.8.8.8"},
                )
            if r.status_code == 200:
                return {"status": "ok", "message": "AbuseIPDB connection successful"}
            return {"status": "error", "message": f"API error: {r.status_code}"}
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e)}

    return {"status": "error", "message": f"Unknown source: {source}"}

