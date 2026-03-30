"""
Suppression engine — evaluates active suppression rules against ingested alerts
and auto-marks matching alerts as false_positive.
"""

from __future__ import annotations

from datetime import datetime, timezone

import structlog
from sqlalchemy import select

from app.database import SessionLocal
from app.models import Alert, SuppressionRule
from app.models.alert import AlertStatus

log = structlog.get_logger(__name__)


def _get_alert_field(alert: Alert, field: str) -> str:
    """Return string value of an alert field for suppression matching."""
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


def _matches_condition(alert: Alert, cond: dict) -> bool:
    field = str(cond.get("field", "")).lower()
    operator = str(cond.get("operator", "")).lower()
    value = str(cond.get("value", "")).lower()
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


def _rule_matches(alert: Alert, rule: SuppressionRule) -> bool:
    conditions = rule.conditions if isinstance(rule.conditions, list) else []
    if not conditions:
        return False
    return all(_matches_condition(alert, c) for c in conditions)


async def apply_suppression_rules(alert_ids: list[str]) -> None:
    """
    Background task: check active suppression rules against new alerts.
    Matching alerts are marked false_positive; rule hit counts are updated.
    Never raises — errors are logged only.
    """
    if not alert_ids:
        return

    try:
        async with SessionLocal() as db:
            now = datetime.now(timezone.utc)

            # Load active, non-expired rules
            r = await db.execute(
                select(SuppressionRule).where(SuppressionRule.is_active == True)  # noqa: E712
            )
            rules: list[SuppressionRule] = list(r.scalars().all())

            # Filter out expired rules
            active_rules = [
                rule for rule in rules
                if rule.expires_at is None or rule.expires_at.replace(tzinfo=timezone.utc) > now
            ]

            if not active_rules:
                return

            for alert_id in alert_ids:
                try:
                    a_r = await db.execute(select(Alert).where(Alert.id == alert_id))
                    alert = a_r.scalar_one_or_none()
                    if not alert:
                        continue

                    for rule in active_rules:
                        if _rule_matches(alert, rule):
                            alert.status = AlertStatus.FALSE_POSITIVE
                            rule.hit_count = (rule.hit_count or 0) + 1
                            rule.last_hit_at = now
                            log.info(
                                "suppression.applied",
                                rule_id=rule.id,
                                rule_name=rule.name,
                                alert_id=alert_id,
                            )
                            break  # First matching rule wins

                except Exception as exc:
                    log.warning("suppression.alert_error", alert_id=alert_id, error=str(exc))

            await db.commit()

    except Exception as exc:
        log.warning("suppression.executor_error", error=str(exc))
