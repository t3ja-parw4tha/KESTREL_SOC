"""SOAR Playbook Evaluation Engine."""

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.playbook import Playbook
from app.schemas.playbook import PlaybookAction, PlaybookCondition

log = structlog.get_logger(__name__)


async def run_playbooks_for_alert(db: AsyncSession, alert: Alert) -> None:
    """
    Evaluate an alert against all active playbooks for 'alert_created'.
    Modifies the alert in-place based on matched actions.
    """
    stmt = select(Playbook).where(
        Playbook.is_active.is_(True),
        Playbook.trigger_type == "alert_created"
    ).order_by(Playbook.id.asc())
    
    r = await db.execute(stmt)
    playbooks = r.scalars().all()

    for playbook in playbooks:
        try:
            # Parse JSON to schema models for strict validation
            conditions = [PlaybookCondition(**c) for c in playbook.conditions]
            actions = [PlaybookAction(**a) for a in playbook.actions]
        except Exception as e:
            log.error("playbook.parse_error", playbook_id=playbook.id, error=str(e))
            continue

        if not conditions:
            continue

        match = True
        for cond in conditions:
            if not _evaluate_condition(alert, cond):
                match = False
                break
        
        if match:
            log.info("playbook.matched", playbook_id=playbook.id, playbook_name=playbook.name, alert_id=alert.id)
            _execute_actions(alert, actions, playbook.name)


def _evaluate_condition(alert: Alert, cond: PlaybookCondition) -> bool:
    """Safely evaluate a single condition against alert fields."""
    # Only allow evaluating specific safe fields
    allowed_fields = {
        "severity": getattr(alert.severity, "value", str(alert.severity)) if alert.severity else None,
        "source": alert.source,
        "category": alert.category,
        "status": getattr(alert.status, "value", str(alert.status)) if alert.status else None,
        "title": alert.title,
        "source_ip": alert.source_ip,
        "dest_ip": alert.dest_ip,
        "risk_level": alert.risk_level,
    }

    if cond.field not in allowed_fields:
        # Ignore unsupported fields
        return False

    actual_val = allowed_fields[cond.field]
    if actual_val is None:
        return False

    actual_str = str(actual_val).lower()
    target_str = str(cond.value).lower()

    if cond.operator == "equals":
        return actual_str == target_str
    elif cond.operator == "not_equals":
        return actual_str != target_str
    elif cond.operator == "contains":
        return target_str in actual_str
    elif cond.operator == "not_contains":
        return target_str not in actual_str
    
    return False


def _execute_actions(alert: Alert, actions: list[PlaybookAction], playbook_name: str) -> None:
    """Safely execute playbook actions on the alert object."""
    for action in actions:
        try:
            val = action.value
            if action.type == "set_severity":
                # Ensure valid enum
                alert.severity = AlertSeverity(val)
            elif action.type == "set_status":
                alert.status = AlertStatus(val)
                if alert.status == AlertStatus.RESOLVED:
                    # Generic closing note if auto-resolved
                    if not alert.ai_summary:
                        alert.ai_summary = f"Auto-resolved by playbook: {playbook_name}"
                    else:
                        alert.ai_summary += f"\n\nAuto-resolved by playbook: {playbook_name}"
            elif action.type == "assign_to":
                alert.assigned_to = val
            elif action.type == "add_tag":
                # KESTREL doesn't have a direct 'tags' column, but we can append it to the title or a generic field.
                # Since tags aren't fully implemented in the schema, we'll prefix the title for now.
                if f"[{val}]" not in alert.title:
                    alert.title = f"[{val}] {alert.title}"
        except ValueError as e:
            log.warning("playbook.action_failed", action_type=action.type, value=action.value, error=str(e))
