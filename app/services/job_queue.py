"""Durable background job queue service with retries, DLQ, and idempotency."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import SessionLocal
from app.models import BackgroundJob

_logger = logging.getLogger("app.job_queue")


async def enqueue_job(
    db: AsyncSession,
    *,
    job_type: str,
    payload: dict,
    idempotency_key: str,
    max_attempts: int | None = None,
) -> BackgroundJob:
    """Insert a new job unless idempotency key already exists."""
    existing = (
        await db.execute(select(BackgroundJob).where(BackgroundJob.idempotency_key == idempotency_key))
    ).scalar_one_or_none()
    if existing:
        return existing

    settings = get_settings()
    row = BackgroundJob(
        id=str(uuid.uuid4()),
        job_type=job_type,
        status="pending",
        payload=payload,
        idempotency_key=idempotency_key,
        attempts=0,
        max_attempts=max_attempts or settings.job_queue_max_attempts,
        next_run_at=datetime.now(timezone.utc),
    )
    db.add(row)
    await db.flush()
    return row


def _backoff_seconds(attempt: int) -> int:
    settings = get_settings()
    base = max(1, settings.job_queue_retry_backoff_seconds)
    return base * (2 ** max(0, attempt - 1))


async def _dispatch_job(job: BackgroundJob) -> dict:
    payload = job.payload or {}

    if job.job_type == "alerts_suppression":
        from app.services.alert_tasks import run_suppression_for_alerts

        await run_suppression_for_alerts(list(payload.get("alert_ids") or []))
        return {"status": "ok"}

    if job.job_type == "alerts_enrichment":
        from app.services.alert_tasks import run_enrichment_for_alerts

        await run_enrichment_for_alerts(list(payload.get("alert_ids") or []))
        return {"status": "ok"}

    if job.job_type == "alerts_notifications":
        from app.services.alert_tasks import run_notifications_for_alerts

        await run_notifications_for_alerts(list(payload.get("alert_ids") or []))
        return {"status": "ok"}

    if job.job_type == "alerts_playbooks":
        from app.services.alert_tasks import run_playbooks_for_alerts_task

        await run_playbooks_for_alerts_task(list(payload.get("alert_ids") or []))
        return {"status": "ok"}

    if job.job_type == "scheduled_report_delivery":
        from app.services.scheduled_reports import execute_scheduled_report_delivery

        raw_sid = payload.get("schedule_id")
        if raw_sid is None:
            raise RuntimeError("scheduled_report_delivery requires schedule_id")
        schedule_id = int(raw_sid)
        result = await execute_scheduled_report_delivery(schedule_id=schedule_id)
        if result.get("status") == "error":
            raise RuntimeError(result.get("detail") or "scheduled report delivery failed")
        return result

    raise RuntimeError(f"Unknown job type: {job.job_type}")


async def process_due_jobs_once(*, limit: int = 50, job_types: list[str] | None = None) -> dict:
    """Process due jobs once; failed jobs are retried or moved to dead-letter."""
    now = datetime.now(timezone.utc)
    summary = {
        "picked": 0,
        "completed": 0,
        "failed": 0,
        "dead_letter": 0,
        "delivered": 0,
        "job_failed_items": 0,
    }

    async with SessionLocal() as db:
        stmt = (
            select(BackgroundJob)
            .where(
                BackgroundJob.status.in_(["pending", "failed"]),
                BackgroundJob.next_run_at <= now,
            )
            .order_by(BackgroundJob.created_at.asc())
            .limit(limit)
        )
        if job_types:
            stmt = stmt.where(BackgroundJob.job_type.in_(job_types))

        rows = (await db.execute(stmt)).scalars().all()
        summary["picked"] = len(rows)

        for row in rows:
            row.status = "processing"
            row.attempts = int(row.attempts or 0) + 1
            await db.commit()

            try:
                result = await _dispatch_job(row)
                row.status = "completed"
                row.last_error = None
                row.completed_at = datetime.now(timezone.utc)
                summary["completed"] += 1
                if isinstance(result, dict):
                    summary["delivered"] += int(result.get("delivered", 0) or 0)
                    summary["job_failed_items"] += int(result.get("failed", 0) or 0)
            except Exception as exc:  # noqa: BLE001
                row.last_error = str(exc)[:1000]
                if row.attempts >= row.max_attempts:
                    row.status = "dead_letter"
                    summary["dead_letter"] += 1
                else:
                    row.status = "failed"
                    row.next_run_at = datetime.now(timezone.utc) + timedelta(seconds=_backoff_seconds(row.attempts))
                    summary["failed"] += 1
                _logger.warning(
                    "job_queue.process_error job_id=%s job_type=%s error=%s",
                    row.id,
                    row.job_type,
                    str(exc),
                )
            await db.commit()

    return summary


async def job_queue_worker() -> None:
    """Polling worker loop to process durable jobs."""
    settings = get_settings()
    poll_seconds = max(1, settings.job_queue_poll_seconds)

    while True:
        await asyncio.sleep(poll_seconds)
        try:
            summary = await process_due_jobs_once(limit=settings.job_queue_batch_size)
            if summary["picked"]:
                _logger.info("job_queue.cycle", **summary)
        except Exception:  # noqa: BLE001
            _logger.exception("job_queue.worker_cycle_failed")
