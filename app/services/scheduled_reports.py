"""Background scheduled report delivery worker (P4-F1)."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, select

from app.config import get_settings
from app.database import SessionLocal
from app.models import AuditLog, ScheduledReport
from app.notifications.email import send_alert_email
from app.services.compliance import build_compliance_report
from app.services.job_queue import enqueue_job, process_due_jobs_once

_logger = logging.getLogger("app.scheduled_reports")


def next_run_for_cadence(cadence: str, ref: datetime | None = None) -> datetime:
    """Compute next execution time from cadence."""
    base = ref or datetime.now(timezone.utc)
    normalized = cadence.lower()
    if normalized == "daily":
        return base + timedelta(days=1)
    if normalized == "weekly":
        return base + timedelta(days=7)
    raise ValueError("Unsupported cadence")


def _render_report_email_body(schedule: ScheduledReport, report: dict) -> str:
    """Render a plaintext report body for scheduled email delivery."""
    kpis = report.get("kpis") or {}
    generated_at = report.get("generated_at") or ""
    return (
        f"KESTREL Scheduled Compliance Report\n"
        f"Schedule: {schedule.name}\n"
        f"Framework: {schedule.framework}\n"
        f"Generated At: {generated_at}\n\n"
        f"KPIs\n"
        f"- alerts_total: {kpis.get('alerts_total', 0)}\n"
        f"- alerts_resolved: {kpis.get('alerts_resolved', 0)}\n"
        f"- evidence_items: {kpis.get('evidence_items', 0)}\n"
        f"- audit_events: {kpis.get('audit_events', 0)}\n"
        f"- resolution_rate: {kpis.get('resolution_rate', 0.0)}\n"
    )


async def _run_schedule_once(schedule_id: int, now: datetime) -> dict:
    """Execute one schedule delivery cycle and persist audit/state transitions."""
    settings = get_settings()
    retry_minutes = max(1, settings.scheduled_reports_retry_minutes)

    async with SessionLocal() as db:
        row = (
            await db.execute(
                select(ScheduledReport).where(
                    and_(
                        ScheduledReport.id == schedule_id,
                        ScheduledReport.is_active.is_(True),
                        ScheduledReport.next_run_at.is_not(None),
                        ScheduledReport.next_run_at <= now,
                    )
                )
            )
        ).scalar_one_or_none()

        if not row:
            return {"schedule_id": schedule_id, "status": "skipped"}

        delivered = 0
        failed = 0
        errors: list[str] = []

        try:
            report = await build_compliance_report(db, row.framework, 30)
            subject = f"[KESTREL] Scheduled {row.framework.upper()} report - {row.name}"[:200]
            body = _render_report_email_body(row, report)

            recipients = row.recipients if isinstance(row.recipients, list) else []
            for recipient in recipients:
                to_email = str(recipient or "").strip()
                if not to_email:
                    continue
                ok = await send_alert_email(to_email, subject, body)
                if ok:
                    delivered += 1
                else:
                    failed += 1
                    errors.append(f"delivery_failed:{to_email[:128]}")

            row.last_run_at = now
            if delivered > 0:
                row.next_run_at = next_run_for_cadence(row.cadence, now)
            else:
                row.next_run_at = now + timedelta(minutes=retry_minutes)

            db.add(
                AuditLog(
                    id=str(uuid.uuid4()),
                    action="scheduled_report_delivery",
                    analyst="system",
                    details={
                        "schedule_id": row.id,
                        "framework": row.framework,
                        "cadence": row.cadence,
                        "delivered": delivered,
                        "failed": failed,
                        "recipients": recipients,
                        "delivery_format": row.delivery_format,
                        "next_run_at": row.next_run_at.isoformat() if row.next_run_at else None,
                        "errors": errors[:20],
                    },
                )
            )
            await db.commit()
            return {"schedule_id": row.id, "status": "processed", "delivered": delivered, "failed": failed}
        except Exception as exc:  # noqa: BLE001
            await db.rollback()
            _logger.exception("scheduled_report_delivery_failed schedule_id=%s", schedule_id)

            retry_at = now + timedelta(minutes=retry_minutes)
            row.last_run_at = now
            row.next_run_at = retry_at
            db.add(
                AuditLog(
                    id=str(uuid.uuid4()),
                    action="scheduled_report_delivery_error",
                    analyst="system",
                    details={
                        "schedule_id": row.id,
                        "error": str(exc)[:500],
                        "retry_at": retry_at.isoformat(),
                    },
                )
            )
            await db.commit()
            return {"schedule_id": row.id, "status": "error", "delivered": 0, "failed": 0}


async def execute_scheduled_report_delivery(schedule_id: int, now: datetime | None = None) -> dict:
    """Execute one queued scheduled-report delivery job."""
    run_at = now or datetime.now(timezone.utc)
    return await _run_schedule_once(schedule_id=schedule_id, now=run_at)


def _scheduled_delivery_key(schedule_id: int, run_at: datetime) -> str:
    rounded = run_at.replace(second=0, microsecond=0).isoformat()
    digest = hashlib.sha256(f"{schedule_id}:{rounded}".encode("utf-8")).hexdigest()
    return f"scheduled_report_delivery:{digest}"


async def run_due_scheduled_reports_once(now: datetime | None = None) -> dict:
    """Fetch and process all due schedules once."""
    run_at = now or datetime.now(timezone.utc)

    async with SessionLocal() as db:
        due_ids = (
            await db.execute(
                select(ScheduledReport.id)
                .where(
                    and_(
                        ScheduledReport.is_active.is_(True),
                        ScheduledReport.next_run_at.is_not(None),
                        ScheduledReport.next_run_at <= run_at,
                    )
                )
                .order_by(ScheduledReport.next_run_at.asc())
            )
        ).scalars().all()

        for schedule_id in due_ids:
            await enqueue_job(
                db,
                job_type="scheduled_report_delivery",
                payload={"schedule_id": int(schedule_id)},
                idempotency_key=_scheduled_delivery_key(int(schedule_id), run_at),
            )
        await db.commit()

    queue_summary = await process_due_jobs_once(
        limit=max(1, len(due_ids)),
        job_types=["scheduled_report_delivery"],
    )
    return {
        "due": len(due_ids),
        "processed": int(queue_summary.get("completed", 0)),
        "delivered": int(queue_summary.get("delivered", 0)),
        "failed": int(queue_summary.get("failed", 0)) + int(queue_summary.get("job_failed_items", 0)),
        "errors": int(queue_summary.get("dead_letter", 0)),
    }


async def scheduled_reports_worker() -> None:
    """Background polling loop for scheduled report delivery."""
    settings = get_settings()
    poll_seconds = max(10, settings.scheduled_reports_poll_seconds)

    while True:
        await asyncio.sleep(poll_seconds)
        try:
            summary = await run_due_scheduled_reports_once()
            if summary["processed"] or summary["errors"]:
                _logger.info("scheduled_reports_cycle", **summary)
        except Exception:  # noqa: BLE001
            _logger.exception("scheduled_reports_worker_cycle_failed")
