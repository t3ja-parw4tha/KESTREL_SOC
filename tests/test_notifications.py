"""Tests for notification modules: Slack URL validation, sanitization."""

import pytest
from unittest.mock import AsyncMock, patch

from app.notifications.slack import _validate_webhook_url, send_slack_alert
from app.notifications.dispatcher import NOTIFY_SEVERITIES


def test_slack_webhook_valid():
    assert _validate_webhook_url("https://hooks.slack.com/services/T00/B00/xxx") is True
    assert _validate_webhook_url("https://hooks.slack.com/services/ABC/def/ghi123") is True


def test_slack_webhook_invalid():
    assert _validate_webhook_url("") is False
    assert _validate_webhook_url("http://hooks.slack.com/services/x") is False
    assert _validate_webhook_url("https://evil.com/hook") is False
    assert _validate_webhook_url("https://hooks.slack.com/") is False


@pytest.mark.asyncio
async def test_send_slack_alert_no_webhook():
    ok = await send_slack_alert("", {"title": "Test", "severity": "High"})
    assert ok is False


@pytest.mark.asyncio
async def test_send_slack_alert_invalid_url():
    ok = await send_slack_alert("https://evil.com", {"title": "Test"})
    assert ok is False


@pytest.mark.asyncio
async def test_send_slack_alert_success_mocked():
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_post = AsyncMock(return_value=mock_resp)
    mock_context = AsyncMock()
    mock_context.post = mock_post
    mock_context.__aenter__.return_value = mock_context
    mock_context.__aexit__.return_value = None
    with patch("app.notifications.slack.httpx.AsyncClient", return_value=mock_context):
        ok = await send_slack_alert(
            "https://hooks.slack.com/services/T/B/X",
            {"id": "1", "title": "Test", "severity": "High", "source": "Test"},
        )
    assert ok is True


def test_notify_severities():
    assert "Critical" in NOTIFY_SEVERITIES
    assert "High" in NOTIFY_SEVERITIES
    assert "Low" not in NOTIFY_SEVERITIES
