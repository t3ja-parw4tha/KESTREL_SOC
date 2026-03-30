"""Slack notifications via webhook. Validates URL (HTTPS only), sanitizes content."""

import logging
import re
from typing import Any

import httpx

from app.security.sanitization import sanitize_text

logger = logging.getLogger(__name__)

# Only allow HTTPS webhooks; reject localhost/private IPs in production
SLACK_WEBHOOK_PATTERN = re.compile(
    r"^https://hooks\.slack\.com/services/[A-Za-z0-9\-_/]+$"
)
MAX_MESSAGE_LENGTH = 3000
MAX_BLOCKS = 50


def _validate_webhook_url(url: str) -> bool:
    """Return True if URL is a valid Slack webhook (HTTPS, hooks.slack.com)."""
    if not url or not isinstance(url, str):
        return False
    u = url.strip()
    if len(u) > 2048:
        return False
    return bool(SLACK_WEBHOOK_PATTERN.match(u))


def _truncate(s: str, max_len: int) -> str:
    if not s or len(s) <= max_len:
        return s or ""
    return s[: max_len - 3] + "..."


def _safe_str(val: Any) -> str:
    """Coerce to string and sanitize for Slack (no HTML, bounded length)."""
    if val is None:
        return ""
    s = str(val).strip()
    s = sanitize_text(s)[:MAX_MESSAGE_LENGTH]
    return s


async def send_slack_alert(webhook_url: str, alert_payload: dict[str, Any]) -> bool:
    """
    Send a single alert summary to Slack. Returns True if sent successfully.
    webhook_url must match Slack webhook format (HTTPS). Alert content is sanitized.
    """
    if not _validate_webhook_url(webhook_url):
        logger.warning("slack.invalid_webhook_url_format")
        return False

    title = _safe_str(alert_payload.get("title") or "Security Alert")
    severity = _safe_str(alert_payload.get("severity") or "Unknown")
    source = _safe_str(alert_payload.get("source") or "")
    alert_id = _safe_str(alert_payload.get("id") or "")
    summary = _safe_str(alert_payload.get("ai_summary") or alert_payload.get("title") or "")

    text = f"*{_truncate(title, 200)}*\nSeverity: {severity} | Source: {source}\n{_truncate(summary, 1000)}"
    blocks: list[dict[str, Any]] = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": text},
        },
    ]
    if alert_id:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"Alert ID: `{alert_id}`"}],
        })

    payload: dict[str, Any] = {
        "text": _truncate(text, 4000),
        "blocks": blocks[:MAX_BLOCKS],
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code != 200:
                logger.warning(
                    "slack.delivery_failed status=%s body_len=%s",
                    resp.status_code,
                    len(resp.text),
                )
                return False
            return True
    except Exception as e:
        logger.warning("slack.delivery_error: %s", e)
        return False
