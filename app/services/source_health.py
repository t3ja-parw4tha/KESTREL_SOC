"""Source health persistence, SLO calculations, and stale-feed alerting."""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import SessionLocal
from app.models import Alert
from app.models.alert import AlertSeverity, AlertStatus
from app.models.source_health import SourceHealth

logger = logging.getLogger(__name__)


@dataclass
class SourceHealthSnapshot:
    source_id: str
    source_name: str | None
    source_type: str | None
    freshness_seconds: float | None
    ingest_lag_seconds: float | None
    error_budget_remaining_pct: float
    error_rate_pct: float
    window_successes: int
    window_failures: int
    consecutive_failures: int
    is_stale: bool
    last_seen_at: datetime | None
    last_success_at: datetime | None
    last_error_at: datetime | None
    last_error_message: str | None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _is_window_expired(now: datetime, started_at: datetime, hours: int) -> bool:
    return now - _as_utc(started_at) >= timedelta(hours=hours)


def _compute_error_budget_remaining_pct(successes: int, failures: int, allowed_failure_rate: float) -> tuple[float, float]:
    total = max(1, successes + failures)
    error_rate = failures / total
    if allowed_failure_rate <= 0:
        return (100.0 if failures == 0 else 0.0, error_rate * 100.0)
    consumed_ratio = error_rate / allowed_failure_rate
    remaining = max(0.0, (1.0 - consumed_ratio) * 100.0)
    return remaining, error_rate * 100.0


async def _get_or_create_source_health(
    db: AsyncSession,
    source_id: str,
    source_name: str | None = None,
    source_type: str | None = None,
) -> SourceHealth:
    existing = await db.get(SourceHealth, source_id)
    if existing is not None:
        if source_name and not existing.source_name:
            existing.source_name = source_name
        if source_type and not existing.source_type:
            existing.source_type = source_type
        return existing

    now = _utcnow()
    row = SourceHealth(
        source_id=source_id,
        source_name=source_name,
        source_type=source_type,
        window_started_at=now,
    )
    db.add(row)
    await db.flush()
    return row


async def record_source_ingestion(
    db: AsyncSession,
    *,
    source_id: str,
    source_name: str | None = None,
    source_type: str | None = None,
    events_received: int = 0,
    alerts_ingested: int = 0,
    processing_errors: int = 0,
    success: bool = True,
    last_error: str | None = None,
    ingest_lag_seconds: float | None = None,
) -> None:
    settings = get_settings()
    row = await _get_or_create_source_health(
        db,
        source_id=source_id,
        source_name=source_name,
        source_type=source_type,
    )
    now = _utcnow()

    if _is_window_expired(now, row.window_started_at, settings.source_health_window_hours):
        row.window_started_at = now
        row.window_successes = 0
        row.window_failures = 0

    row.last_seen_at = now
    row.events_received_total += max(0, int(events_received))
    row.alerts_ingested_total += max(0, int(alerts_ingested))
    row.processing_errors_total += max(0, int(processing_errors))

    if ingest_lag_seconds is not None:
        row.last_ingest_lag_seconds = max(0.0, float(ingest_lag_seconds))

    if success:
        row.last_success_at = now
        row.consecutive_failures = 0
        row.window_successes += 1
        row.last_error_message = None
    else:
        row.last_error_at = now
        row.last_error_message = (last_error or "ingestion failure")[:2000]
        row.consecutive_failures += 1
        row.window_failures += 1

    await db.flush()


async def build_health_snapshots(
    db: AsyncSession,
    *,
    only_source_ids: set[str] | None = None,
) -> list[SourceHealthSnapshot]:
    settings = get_settings()
    now = _utcnow()

    q = select(SourceHealth)
    if only_source_ids:
        q = q.where(SourceHealth.source_id.in_(only_source_ids))

    rows = (await db.execute(q)).scalars().all()
    snapshots: list[SourceHealthSnapshot] = []

    stale_after_seconds = settings.source_health_stale_after_minutes * 60
    allowed_failure_rate = settings.source_health_error_budget_failure_rate

    for row in rows:
        freshness_seconds = None
        if row.last_success_at is not None:
            freshness_seconds = max(0.0, (now - _as_utc(row.last_success_at)).total_seconds())

        remaining_pct, error_rate_pct = _compute_error_budget_remaining_pct(
            row.window_successes,
            row.window_failures,
            allowed_failure_rate,
        )

        is_stale = freshness_seconds is not None and freshness_seconds > stale_after_seconds

        snapshots.append(
            SourceHealthSnapshot(
                source_id=row.source_id,
                source_name=row.source_name,
                source_type=row.source_type,
                freshness_seconds=freshness_seconds,
                ingest_lag_seconds=row.last_ingest_lag_seconds,
                error_budget_remaining_pct=round(remaining_pct, 2),
                error_rate_pct=round(error_rate_pct, 2),
                window_successes=row.window_successes,
                window_failures=row.window_failures,
                consecutive_failures=row.consecutive_failures,
                is_stale=is_stale,
                last_seen_at=row.last_seen_at,
                last_success_at=row.last_success_at,
                last_error_at=row.last_error_at,
                last_error_message=row.last_error_message,
            )
        )

    return snapshots


async def evaluate_stale_feeds(db: AsyncSession) -> dict[str, int]:
    """Auto-open and auto-resolve stale-feed alerts with cooldown protection."""
    settings = get_settings()
    stale_after_seconds = settings.source_health_stale_after_minutes * 60
    cooldown = timedelta(minutes=settings.source_health_alert_cooldown_minutes)
    now = _utcnow()

    opened = 0
    resolved = 0

    rows = (await db.execute(select(SourceHealth))).scalars().all()
    for row in rows:
        if row.last_success_at is None:
            continue

        age_seconds = max(0.0, (now - _as_utc(row.last_success_at)).total_seconds())
        is_stale = age_seconds > stale_after_seconds
        title = f"Stale source feed: {row.source_id}"

        if is_stale:
            in_cooldown = (
                row.stale_alert_last_fired_at is not None
                and now - _as_utc(row.stale_alert_last_fired_at) < cooldown
            )
            if row.stale_alert_active or in_cooldown:
                continue

            open_alert = (
                await db.execute(
                    select(Alert).where(
                        Alert.title == title,
                        Alert.status.in_([AlertStatus.OPEN, AlertStatus.IN_PROGRESS]),
                    )
                )
            ).scalar_one_or_none()

            if open_alert is None:
                severity = AlertSeverity.HIGH if age_seconds > stale_after_seconds * 2 else AlertSeverity.MEDIUM
                db.add(
                    Alert(
                        id=str(uuid.uuid4()),
                        title=title,
                        source="SourceHealthMonitor",
                        severity=severity,
                        category="source_health",
                        status=AlertStatus.OPEN,
                        enrichment={
                            "source_id": row.source_id,
                            "stale_for_seconds": int(age_seconds),
                            "threshold_seconds": stale_after_seconds,
                        },
                    )
                )
                opened += 1

            row.stale_alert_active = True
            row.stale_alert_last_fired_at = now
            await db.flush()
            continue

        if row.stale_alert_active:
            open_alerts = (
                await db.execute(
                    select(Alert).where(
                        Alert.title == title,
                        Alert.status.in_([AlertStatus.OPEN, AlertStatus.IN_PROGRESS]),
                    )
                )
            ).scalars().all()
            for alert in open_alerts:
                alert.status = AlertStatus.RESOLVED
                enrichment = dict(alert.enrichment or {})
                enrichment["auto_resolved_reason"] = "source_feed_recovered"
                enrichment["resolved_at"] = now.isoformat()
                alert.enrichment = enrichment
                resolved += 1

            row.stale_alert_active = False
            await db.flush()

    return {"opened": opened, "resolved": resolved}


async def source_health_monitor_worker() -> None:
    """Periodic stale-feed monitor to keep stale alerts in sync with feed freshness."""
    settings = get_settings()
    poll_seconds = max(15, settings.source_health_monitor_poll_seconds)

    while True:
        try:
            async with SessionLocal() as db:
                await evaluate_stale_feeds(db)
                await db.commit()
        except Exception:  # noqa: BLE001
            logger.exception("source_health_monitor_failed")
        await asyncio.sleep(poll_seconds)
