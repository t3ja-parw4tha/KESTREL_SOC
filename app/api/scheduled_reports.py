"""Scheduled report APIs (P4-6, P6-9)."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import ScheduledReport
from app.security.csrf import verify_csrf
from app.security.rbac import require_permission
from app.services.compliance import ALLOWED_FRAMEWORKS, build_compliance_report
from app.services.scheduled_reports import next_run_for_cadence

router = APIRouter(prefix="/scheduled-reports", tags=["scheduled-reports"])


def _next_run(cadence: str, ref: datetime | None = None) -> datetime:
    return next_run_for_cadence(cadence, ref)


class ScheduledReportCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=160)
    framework: str = Field(..., description="soc2 | iso27001 | pci-dss")
    cadence: str = Field(..., description="daily | weekly")
    recipients: list[str] = Field(..., min_length=1)
    delivery_format: str = Field(default="pdf")
    is_active: bool = True


class ScheduledReportUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    cadence: str | None = None
    recipients: list[str] | None = None
    delivery_format: str | None = None
    is_active: bool | None = None


@router.get("")
async def list_scheduled_reports(
    user: Annotated[dict, Depends(require_permission("dashboard:read"))],
    db: AsyncSession = Depends(get_db),
):
    owner = str(user.get("sub"))
    rows = (
        await db.execute(
            select(ScheduledReport)
            .where(ScheduledReport.owner == owner)
            .order_by(ScheduledReport.updated_at.desc())
        )
    ).scalars().all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "framework": r.framework,
            "cadence": r.cadence,
            "recipients": r.recipients,
            "delivery_format": r.delivery_format,
            "is_active": r.is_active,
            "next_run_at": r.next_run_at.isoformat() if r.next_run_at else None,
            "last_run_at": r.last_run_at.isoformat() if r.last_run_at else None,
        }
        for r in rows
    ]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_scheduled_report(
    body: ScheduledReportCreate,
    user: Annotated[dict, Depends(require_permission("dashboard:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    framework = body.framework.lower()
    cadence = body.cadence.lower()
    if framework not in ALLOWED_FRAMEWORKS:
        raise HTTPException(status_code=400, detail="Unsupported framework")
    if cadence not in {"daily", "weekly"}:
        raise HTTPException(status_code=400, detail="Unsupported cadence")

    row = ScheduledReport(
        owner=str(user.get("sub")),
        name=body.name,
        framework=framework,
        cadence=cadence,
        recipients=body.recipients,
        delivery_format=body.delivery_format,
        is_active=body.is_active,
        next_run_at=_next_run(cadence),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return {
        "id": row.id,
        "name": row.name,
        "framework": row.framework,
        "cadence": row.cadence,
        "recipients": row.recipients,
        "delivery_format": row.delivery_format,
        "is_active": row.is_active,
        "next_run_at": row.next_run_at.isoformat() if row.next_run_at else None,
        "last_run_at": row.last_run_at.isoformat() if row.last_run_at else None,
    }


@router.patch("/{schedule_id}")
async def update_scheduled_report(
    schedule_id: int,
    body: ScheduledReportUpdate,
    user: Annotated[dict, Depends(require_permission("dashboard:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    owner = str(user.get("sub"))
    row = (await db.execute(select(ScheduledReport).where(ScheduledReport.id == schedule_id, ScheduledReport.owner == owner))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    patch = body.model_dump(exclude_unset=True)
    if "cadence" in patch and patch["cadence"] not in {"daily", "weekly"}:
        raise HTTPException(status_code=400, detail="Unsupported cadence")

    for key, value in patch.items():
        setattr(row, key, value.lower() if key == "cadence" and isinstance(value, str) else value)

    await db.commit()
    await db.refresh(row)
    return {
        "id": row.id,
        "name": row.name,
        "framework": row.framework,
        "cadence": row.cadence,
        "recipients": row.recipients,
        "delivery_format": row.delivery_format,
        "is_active": row.is_active,
        "next_run_at": row.next_run_at.isoformat() if row.next_run_at else None,
        "last_run_at": row.last_run_at.isoformat() if row.last_run_at else None,
    }


@router.post("/{schedule_id}/run-now")
async def run_scheduled_report_now(
    schedule_id: int,
    user: Annotated[dict, Depends(require_permission("dashboard:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    owner = str(user.get("sub"))
    row = (await db.execute(select(ScheduledReport).where(ScheduledReport.id == schedule_id, ScheduledReport.owner == owner))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    report = await build_compliance_report(db, row.framework, 30)
    now = datetime.now(timezone.utc)
    row.last_run_at = now
    row.next_run_at = _next_run(row.cadence, now)

    # Compute checksum: SHA-256 of report_id + timestamp + framework
    checksum_input = f"{row.id}:{now.isoformat()}:{row.framework}"
    checksum = hashlib.sha256(checksum_input.encode()).hexdigest()
    row.last_checksum = checksum

    await db.commit()

    return {
        "schedule_id": row.id,
        "delivered_to": row.recipients,
        "delivery_format": row.delivery_format,
        "report_framework": row.framework,
        "next_run_at": row.next_run_at.isoformat() if row.next_run_at else None,
        "checksum": checksum,
        "report_preview": report,
    }


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scheduled_report(
    schedule_id: int,
    user: Annotated[dict, Depends(require_permission("dashboard:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    owner = str(user.get("sub"))
    row = (await db.execute(select(ScheduledReport).where(ScheduledReport.id == schedule_id, ScheduledReport.owner == owner))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Scheduled report not found")
    await db.delete(row)
    await db.commit()


# ── P6-9: Delivery receipts & trust chain ─────────────────────────────────────

class DeliveryReceiptCreate(BaseModel):
    recipients: list[str] = Field(..., min_length=1)
    delivery_method: str = Field(default="email")
    status: str = Field(default="delivered")
    checksum: str | None = None
    notes: str | None = None


@router.post("/{schedule_id}/delivery-receipts", status_code=status.HTTP_201_CREATED)
async def record_delivery_receipt(
    schedule_id: int,
    body: DeliveryReceiptCreate,
    user: Annotated[dict, Depends(require_permission("dashboard:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    """Record that a scheduled report was delivered."""
    owner = str(user.get("sub"))
    row = (
        await db.execute(
            select(ScheduledReport).where(
                ScheduledReport.id == schedule_id,
                ScheduledReport.owner == owner,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    now = datetime.now(timezone.utc)
    # Build checksum if not provided
    checksum = body.checksum
    if not checksum:
        checksum_input = f"{schedule_id}:{now.isoformat()}:{','.join(sorted(body.recipients))}"
        checksum = hashlib.sha256(checksum_input.encode()).hexdigest()

    receipt = {
        "delivered_at": now.isoformat(),
        "recipients": body.recipients,
        "delivery_method": body.delivery_method,
        "status": body.status,
        "checksum": checksum,
        "notes": body.notes,
    }

    existing = list(row.delivery_receipts or [])
    existing.append(receipt)
    row.delivery_receipts = existing
    row.last_checksum = checksum
    await db.commit()
    await db.refresh(row)

    return {
        "report_id": schedule_id,
        **receipt,
    }


@router.get("/{schedule_id}/delivery-status")
async def get_delivery_status(
    schedule_id: int,
    user: Annotated[dict, Depends(require_permission("dashboard:read"))],
    db: AsyncSession = Depends(get_db),
):
    """Return delivery receipts for a scheduled report."""
    owner = str(user.get("sub"))
    row = (
        await db.execute(
            select(ScheduledReport).where(
                ScheduledReport.id == schedule_id,
                ScheduledReport.owner == owner,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    receipts = list(row.delivery_receipts or [])
    return {
        "report_id": schedule_id,
        "report_name": row.name,
        "framework": row.framework,
        "last_checksum": row.last_checksum,
        "delivery_receipts": receipts,
        "total_deliveries": len(receipts),
    }
