"""
Rule-based notification dispatcher. Triggers Slack/email for new critical/high alerts.
No secrets in logs; content sanitized by slack/email modules.
"""

import logging
from typing import Any

from app.config import get_settings
from app.notifications.slack import send_slack_alert
from app.notifications.email import send_alert_email

logger = logging.getLogger(__name__)

# Severities that trigger notifications (configurable via env in future)
NOTIFY_SEVERITIES = frozenset({"Critical", "High", "critical", "high"})


def _alert_payload_from_dict(alert_dict: dict[str, Any]) -> dict[str, Any]:
    """Build a safe payload for notification (sanitized fields only)."""
    return {
        "id": str(alert_dict.get("id", ""))[:36],
        "title": str(alert_dict.get("title", "Alert"))[:512],
        "severity": str(alert_dict.get("severity", ""))[:32],
        "source": str(alert_dict.get("source", ""))[:100],
        "ai_summary": str(alert_dict.get("ai_summary") or "")[:2000],
    }


async def notify_new_alert(alert_dict: dict[str, Any]) -> None:
    """
    If alert severity is Critical or High, send Slack and/or email per config.
    Call from ingest (background task). Never raises; logs only.
    """
    severity = (alert_dict.get("severity") or "").strip()
    if severity not in NOTIFY_SEVERITIES:
        return

    settings = get_settings()
    payload = _alert_payload_from_dict(alert_dict)

    # Slack
    webhook = (settings.slack_webhook_url.get_secret_value() or "").strip()
    if webhook:
        try:
            ok = await send_slack_alert(webhook, payload)
            if ok:
                logger.info("notification.slack.sent alert_id=%s", payload.get("id"))
        except Exception as e:
            logger.warning("notification.slack.error: %s", e)

    # Email
    to_addr = (settings.alert_email_to or "").strip()
    if to_addr and settings.smtp_host:
        try:
            subject = f"[KESTREL] {severity}: {payload.get('title', 'Alert')}"[:200]
            body = (
                f"Severity: {severity}\n"
                f"Source: {payload.get('source', '')}\n"
                f"Alert ID: {payload.get('id', '')}\n\n"
                f"{payload.get('ai_summary', '')}"
            )
            ok = await send_alert_email(to_addr, subject, body)
            if ok:
                logger.info("notification.email.sent alert_id=%s", payload.get("id"))
        except Exception as e:
            logger.warning("notification.email.error: %s", e)
