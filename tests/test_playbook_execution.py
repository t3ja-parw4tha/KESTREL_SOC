"""Tests for SOAR playbook evaluation engine (app/services/soar.py)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.playbook import Playbook
from app.services.soar import _evaluate_condition, execute_playbook_actions, run_playbooks_for_alert
from app.schemas.playbook import PlaybookCondition, PlaybookAction


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_alert(**kwargs) -> Alert:
    a = Alert()
    a.id = "test-alert-1"
    a.title = kwargs.get("title", "Test Alert")
    a.source = kwargs.get("source", "suricata")
    a.category = kwargs.get("category", "network")
    a.severity = kwargs.get("severity", AlertSeverity.HIGH)
    a.status = kwargs.get("status", AlertStatus.OPEN)
    a.source_ip = kwargs.get("source_ip", None)
    a.dest_ip = kwargs.get("dest_ip", None)
    a.risk_level = kwargs.get("risk_level", "high")
    a.assigned_to = kwargs.get("assigned_to", None)
    a.ai_summary = kwargs.get("ai_summary", None)
    return a


def make_condition(field: str, operator: str, value: str) -> PlaybookCondition:
    return PlaybookCondition(field=field, operator=operator, value=value)


def make_action(action_type: str, value: str) -> PlaybookAction:
    return PlaybookAction(type=action_type, value=value)


# ── _evaluate_condition ────────────────────────────────────────────────────────

def test_condition_equals_match():
    alert = make_alert(severity=AlertSeverity.CRITICAL)
    cond = make_condition("severity", "equals", "Critical")
    assert _evaluate_condition(alert, cond) is True


def test_condition_equals_no_match():
    alert = make_alert(severity=AlertSeverity.LOW)
    cond = make_condition("severity", "equals", "Critical")
    assert _evaluate_condition(alert, cond) is False


def test_condition_not_equals():
    alert = make_alert(source="guardduty")
    cond = make_condition("source", "not_equals", "suricata")
    assert _evaluate_condition(alert, cond) is True


def test_condition_contains():
    alert = make_alert(title="Suspicious PowerShell Execution Detected")
    cond = make_condition("title", "contains", "powershell")
    assert _evaluate_condition(alert, cond) is True


def test_condition_not_contains():
    alert = make_alert(title="Normal DNS Query")
    cond = make_condition("title", "not_contains", "powershell")
    assert _evaluate_condition(alert, cond) is True


def test_condition_unsupported_field_returns_false():
    alert = make_alert()
    cond = make_condition("nonexistent_field", "equals", "value")
    assert _evaluate_condition(alert, cond) is False


def test_condition_null_field_returns_false():
    alert = make_alert(source_ip=None)
    cond = make_condition("source_ip", "equals", "1.2.3.4")
    assert _evaluate_condition(alert, cond) is False


def test_condition_case_insensitive():
    alert = make_alert(severity=AlertSeverity.HIGH)
    cond = make_condition("severity", "equals", "high")
    assert _evaluate_condition(alert, cond) is True


# ── execute_playbook_actions ───────────────────────────────────────────────────

def test_action_set_status_resolved():
    alert = make_alert()
    execute_playbook_actions(alert, [make_action("set_status", "resolved").model_dump()], "Test Playbook")
    assert alert.status == AlertStatus.RESOLVED


def test_action_set_status_resolved_updates_summary():
    alert = make_alert(ai_summary=None)
    execute_playbook_actions(alert, [make_action("set_status", "resolved").model_dump()], "Auto Closer")
    assert "Auto Closer" in (alert.ai_summary or "")


def test_action_set_severity():
    alert = make_alert(severity=AlertSeverity.LOW)
    execute_playbook_actions(alert, [make_action("set_severity", "Critical").model_dump()], "Escalator")
    assert alert.severity == AlertSeverity.CRITICAL


def test_action_assign_to():
    alert = make_alert()
    execute_playbook_actions(alert, [make_action("assign_to", "alice").model_dump()], "Assigner")
    assert alert.assigned_to == "alice"


def test_action_add_tag_prefixes_title():
    alert = make_alert(title="Original Title")
    execute_playbook_actions(alert, [make_action("add_tag", "AUTO").model_dump()], "Tagger")
    assert "[AUTO]" in alert.title


def test_action_add_tag_not_duplicated():
    alert = make_alert(title="[AUTO] Original Title")
    execute_playbook_actions(alert, [make_action("add_tag", "AUTO").model_dump()], "Tagger")
    assert alert.title.count("[AUTO]") == 1


def test_action_invalid_severity_skipped():
    alert = make_alert(severity=AlertSeverity.HIGH)
    execute_playbook_actions(alert, [make_action("set_severity", "INVALID_LEVEL").model_dump()], "Bad Playbook")
    # Original severity unchanged
    assert alert.severity == AlertSeverity.HIGH


# ── run_playbooks_for_alert ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_playbooks_matching_condition_executes_action():
    alert = make_alert(severity=AlertSeverity.CRITICAL)

    playbook = Playbook()
    playbook.id = 1
    playbook.name = "Critical Auto-Resolve"
    playbook.is_active = True
    playbook.trigger_type = "alert_created"
    playbook.conditions = [{"field": "severity", "operator": "equals", "value": "Critical"}]
    playbook.actions = [{"type": "set_status", "value": "resolved"}]

    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [playbook]
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)

    await run_playbooks_for_alert(db, alert)

    assert alert.status == AlertStatus.RESOLVED


@pytest.mark.asyncio
async def test_run_playbooks_no_match_skips_action():
    alert = make_alert(severity=AlertSeverity.LOW)

    playbook = Playbook()
    playbook.id = 2
    playbook.name = "Critical Only"
    playbook.is_active = True
    playbook.trigger_type = "alert_created"
    playbook.conditions = [{"field": "severity", "operator": "equals", "value": "Critical"}]
    playbook.actions = [{"type": "set_status", "value": "resolved"}]

    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [playbook]
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)

    await run_playbooks_for_alert(db, alert)

    assert alert.status == AlertStatus.OPEN


@pytest.mark.asyncio
async def test_run_playbooks_inactive_playbook_skipped():
    alert = make_alert(severity=AlertSeverity.CRITICAL)

    playbook = Playbook()
    playbook.id = 3
    playbook.name = "Inactive Playbook"
    playbook.is_active = False  # Won't appear in query — simulated by empty result
    playbook.trigger_type = "alert_created"
    playbook.conditions = [{"field": "severity", "operator": "equals", "value": "Critical"}]
    playbook.actions = [{"type": "set_status", "value": "resolved"}]

    mock_scalars = MagicMock()
    mock_scalars.all.return_value = []  # query filters inactive
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)

    await run_playbooks_for_alert(db, alert)

    assert alert.status == AlertStatus.OPEN


@pytest.mark.asyncio
async def test_run_playbooks_multiple_conditions_all_must_match():
    """Two conditions: severity=Critical AND source=guardduty. Alert is Critical but source=suricata → no match."""
    alert = make_alert(severity=AlertSeverity.CRITICAL, source="suricata")

    playbook = Playbook()
    playbook.id = 4
    playbook.name = "Multi-condition"
    playbook.is_active = True
    playbook.trigger_type = "alert_created"
    playbook.conditions = [
        {"field": "severity", "operator": "equals", "value": "Critical"},
        {"field": "source", "operator": "equals", "value": "guardduty"},
    ]
    playbook.actions = [{"type": "set_status", "value": "resolved"}]

    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [playbook]
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)

    await run_playbooks_for_alert(db, alert)

    assert alert.status == AlertStatus.OPEN


@pytest.mark.asyncio
async def test_run_playbooks_empty_conditions_skipped():
    """Playbook with no conditions is skipped (safety guard)."""
    alert = make_alert()

    playbook = Playbook()
    playbook.id = 5
    playbook.name = "Empty Conditions"
    playbook.is_active = True
    playbook.trigger_type = "alert_created"
    playbook.conditions = []  # Empty — should be skipped
    playbook.actions = [{"type": "set_status", "value": "resolved"}]

    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [playbook]
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)

    await run_playbooks_for_alert(db, alert)

    assert alert.status == AlertStatus.OPEN


@pytest.mark.asyncio
async def test_run_playbooks_malformed_conditions_skipped():
    """Playbook with invalid condition schema is skipped without raising."""
    alert = make_alert()

    playbook = Playbook()
    playbook.id = 6
    playbook.name = "Malformed"
    playbook.is_active = True
    playbook.trigger_type = "alert_created"
    playbook.conditions = [{"bad_field": "no_operator"}]  # Invalid schema
    playbook.actions = [{"type": "set_status", "value": "resolved"}]

    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [playbook]
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)

    # Should not raise
    await run_playbooks_for_alert(db, alert)
    assert alert.status == AlertStatus.OPEN
