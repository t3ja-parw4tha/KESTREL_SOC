"""Notifications: Slack, email, and rule-based dispatcher. No secrets in logs."""

from app.notifications.dispatcher import notify_new_alert
from app.notifications.slack import send_slack_alert
from app.notifications.email import send_alert_email

__all__ = ["notify_new_alert", "send_slack_alert", "send_alert_email"]
