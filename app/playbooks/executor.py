"""
Playbook executor — evaluates active DB-stored playbooks against ingested alerts
and applies matching actions.
"""

from __future__ import annotations

import structlog
from sqlalchemy import select

from app.database import SessionLocal
from app.models import Alert, Playbook
from app.models.alert import AlertSeverity, AlertStatus

log = structlog.get_logger(__name__)

# ─── Severity / status maps ───────────────────────────────────────────────────

_SEVERITY_MAP: dict[str, AlertSeverity] = {
    "low": AlertSeverity.LOW,
    "medium": AlertSeverity.MEDIUM,
    "high": AlertSeverity.HIGH,
    "critical": AlertSeverity.CRITICAL,
}

_STATUS_MAP: dict[str, AlertStatus] = {
    "open": AlertStatus.OPEN,
    "in_progress": AlertStatus.IN_PROGRESS,
    "resolved": AlertStatus.RESOLVED,
    "false_positive": AlertStatus.FALSE_POSITIVE,
    "dismissed": AlertStatus.FALSE_POSITIVE,
}


def _get_alert_field(alert: Alert, field: str) -> str:
    """Return the string value of an alert field used in condition evaluation."""
    field = field.lower()
    if field == "severity":
        return (alert.severity.value if alert.severity else "").lower()
    if field == "source":
        return (alert.source or "").lower()
    if field == "category":
        return (alert.category or "").lower()
    if field == "title":
        return (alert.title or "").lower()
    if field == "source_ip":
        return (alert.source_ip or "").lower()
    return ""


def _evaluate_condition(alert: Alert, condition: dict) -> bool:
    """Return True if the alert satisfies the condition."""
    field = str(condition.get("field", "")).lower()
    operator = str(condition.get("operator", "")).lower()
    value = str(condition.get("value", "")).lower()

    actual = _get_alert_field(alert, field)

    if operator == "equals":
        return actual == value
    if operator == "not_equals":
        return actual != value
    if operator == "contains":
        return value in actual
    if operator == "not_contains":
        return value not in actual
    return False


def _evaluate_playbook(alert: Alert, playbook: Playbook) -> bool:
    """Return True if ALL conditions of the playbook match (AND logic)."""
    raw = playbook.conditions
    if not isinstance(raw, list):
        return False
    conditions: list[dict[str, object]] = [c for c in raw if isinstance(c, dict)]
    if not conditions:
        return False  # A playbook with no conditions never fires
    return all(_evaluate_condition(alert, c) for c in conditions)


def _apply_action(alert: Alert, action: dict) -> None:
    """Apply a single action to the alert in-place."""
    action_type = str(action.get("type", "")).lower()
    value = str(action.get("value", ""))

    if action_type == "set_severity":
        mapped = _SEVERITY_MAP.get(value.lower())
        if mapped:
            alert.severity = mapped
            log.debug("playbook.action.set_severity", alert_id=alert.id, severity=mapped.value)

    elif action_type == "set_status":
        mapped_status = _STATUS_MAP.get(value.lower())
        if mapped_status:
            alert.status = mapped_status
            log.debug("playbook.action.set_status", alert_id=alert.id, status=mapped_status.value)

    elif action_type == "add_tag":
        # Store tags in the enrichment JSON under "playbook_tags"
        enrichment = dict(alert.enrichment or {})
        tags: list[str] = list(enrichment.get("playbook_tags") or [])
        if value and value not in tags:
            tags.append(value)
        enrichment["playbook_tags"] = tags
        alert.enrichment = enrichment
        log.debug("playbook.action.add_tag", alert_id=alert.id, tag=value)

    elif action_type == "assign_to":
        if value:
            alert.assigned_to = value
            log.debug("playbook.action.assign_to", alert_id=alert.id, assignee=value)


async def run_playbooks_for_alerts(alert_ids: list[str]) -> None:
    """
    Background task: load all active playbooks, evaluate each against every new alert,
    and apply matching actions.  Never raises — errors are logged only.
    """
    if not alert_ids:
        return

    try:
        async with SessionLocal() as db:
            # Load active playbooks once
            pb_r = await db.execute(
                select(Playbook).where(Playbook.is_active == True)  # noqa: E712
            )
            playbooks: list[Playbook] = list(pb_r.scalars().all())

            if not playbooks:
                return  # Nothing to do

            for alert_id in alert_ids:
                try:
                    a_r = await db.execute(select(Alert).where(Alert.id == alert_id))
                    alert = a_r.scalar_one_or_none()
                    if not alert:
                        continue

                    fired_any = False
                    for pb in playbooks:
                        if _evaluate_playbook(alert, pb):
                            log.info(
                                "playbook.fired",
                                playbook_id=pb.id,
                                playbook_name=pb.name,
                                alert_id=alert_id,
                            )
                            for action in (pb.actions or []):
                                _apply_action(alert, action)
                            fired_any = True

                    if fired_any:
                        await db.flush()

                except Exception as exc:
                    log.warning("playbook.alert_error", alert_id=alert_id, error=str(exc))

            await db.commit()

    except Exception as exc:
        log.warning("playbook.executor_error", error=str(exc))
