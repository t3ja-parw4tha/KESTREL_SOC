"""Case management API for tracking SOC investigations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Alert, AuditLog, CaseRecord
from app.models.case import CaseSeverity, CaseStatus
from app.security.csrf import verify_csrf
from app.security.rbac import require_permission

router = APIRouter(prefix="/cases", tags=["cases"])

_CLOSURE_TAXONOMY = {
    "mitigated",
    "false_positive",
    "duplicate",
    "risk_accepted",
    "transferred",
    "no_action_required",
    "other",
}


class CaseCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=256)
    description: str | None = Field(default=None, max_length=2048)
    owner: str = Field(..., min_length=1, max_length=256)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    sla_hours: int = Field(default=72, ge=1, le=24 * 30)
    linked_alert_ids: list[str] = Field(default_factory=list, max_length=200)
    linked_incident_ids: list[str] = Field(default_factory=list, max_length=200)


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=256)
    description: str | None = Field(default=None, max_length=2048)
    owner: str | None = Field(default=None, min_length=1, max_length=256)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    status: Literal["open", "in_progress", "resolved", "closed"] | None = None
    sla_hours: int | None = Field(default=None, ge=1, le=24 * 30)
    linked_alert_ids: list[str] | None = Field(default=None, max_length=200)
    linked_incident_ids: list[str] | None = Field(default=None, max_length=200)
    closure_reason: str | None = Field(default=None, max_length=64)
    closure_notes: str | None = Field(default=None, max_length=2048)


class CaseResponse(BaseModel):
    id: str
    title: str
    description: str | None
    owner: str
    severity: str
    status: str
    sla_due_at: str | None
    sla_breached: bool
    linked_alert_ids: list[str]
    linked_incident_ids: list[str]
    closure_reason: str | None
    closure_notes: str | None
    closed_at: str | None
    created_by: str | None
    created_at: str | None
    updated_at: str | None


class CaseListResponse(BaseModel):
    items: list[CaseResponse]
    total: int


async def _validate_alert_links(db: AsyncSession, alert_ids: list[str]) -> list[str]:
    unique = sorted(set([a.strip() for a in alert_ids if a and a.strip()]))
    if not unique:
        return []
    rows = (await db.execute(select(Alert.id).where(Alert.id.in_(unique)))).scalars().all()
    found = set(rows)
    missing = [a for a in unique if a not in found]
    if missing:
        raise HTTPException(status_code=400, detail=f"Unknown alert IDs: {missing[:10]}")
    return unique


async def _validate_incident_links(db: AsyncSession, incident_ids: list[str]) -> list[str]:
    unique = sorted(set([i.strip() for i in incident_ids if i and i.strip()]))
    if not unique:
        return []
    rows = (
        await db.execute(
            select(Alert.incident_group_id)
            .where(Alert.incident_group_id.in_(unique))
            .group_by(Alert.incident_group_id)
        )
    ).scalars().all()
    found = set([r for r in rows if r])
    missing = [i for i in unique if i not in found]
    if missing:
        raise HTTPException(status_code=400, detail=f"Unknown incident IDs: {missing[:10]}")
    return unique


def _parse_severity(value: str) -> CaseSeverity:
    return CaseSeverity(str(value).lower())


def _parse_status(value: str) -> CaseStatus:
    return CaseStatus(str(value).lower())


def _case_to_response(row: CaseRecord) -> CaseResponse:
    linked_alert_ids = row.linked_alert_ids if isinstance(row.linked_alert_ids, list) else []
    linked_incident_ids = row.linked_incident_ids if isinstance(row.linked_incident_ids, list) else []
    now = datetime.now(timezone.utc)
    breached = bool(
        row.sla_due_at
        and row.status not in {CaseStatus.RESOLVED, CaseStatus.CLOSED}
        and row.sla_due_at.replace(tzinfo=timezone.utc) < now
    )
    return CaseResponse(
        id=row.id,
        title=row.title,
        description=row.description,
        owner=row.owner,
        severity=row.severity.value,
        status=row.status.value,
        sla_due_at=row.sla_due_at.isoformat() if row.sla_due_at else None,
        sla_breached=breached,
        linked_alert_ids=linked_alert_ids,
        linked_incident_ids=linked_incident_ids,
        closure_reason=row.closure_reason,
        closure_notes=row.closure_notes,
        closed_at=row.closed_at.isoformat() if row.closed_at else None,
        created_by=row.created_by,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


async def _write_case_audit(db: AsyncSession, actor: str | None, action: str, case_id: str, details: dict) -> None:
    db.add(
        AuditLog(
            id=str(uuid.uuid4()),
            action=action,
            analyst=actor,
            details={"case_id": case_id, **details},
        )
    )


def _enforce_closure_rules(new_status: CaseStatus, closure_reason: str | None) -> None:
    if new_status in {CaseStatus.RESOLVED, CaseStatus.CLOSED}:
        if not closure_reason:
            raise HTTPException(status_code=400, detail="closure_reason is required when resolving/closing a case")
        if closure_reason not in _CLOSURE_TAXONOMY:
            raise HTTPException(status_code=400, detail=f"Invalid closure_reason. Allowed: {sorted(_CLOSURE_TAXONOMY)}")


@router.get("", response_model=CaseListResponse)
async def list_cases(
    _user: Annotated[dict, Depends(require_permission("cases:read"))],
    db: AsyncSession = Depends(get_db),
    owner: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    sla_breached: bool | None = Query(default=None),
):
    stmt = select(CaseRecord).order_by(CaseRecord.updated_at.desc())
    if owner:
        stmt = stmt.where(CaseRecord.owner == owner)
    if severity:
        try:
            stmt = stmt.where(CaseRecord.severity == _parse_severity(severity))
        except Exception:
            pass
    if status_filter:
        try:
            stmt = stmt.where(CaseRecord.status == _parse_status(status_filter))
        except Exception:
            pass

    rows = (await db.execute(stmt)).scalars().all()
    items = [_case_to_response(r) for r in rows]
    if sla_breached is not None:
        items = [i for i in items if i.sla_breached is sla_breached]
    return CaseListResponse(items=items, total=len(items))


@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
async def create_case(
    body: CaseCreate,
    user: Annotated[dict, Depends(require_permission("cases:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    alert_ids = await _validate_alert_links(db, body.linked_alert_ids)
    incident_ids = await _validate_incident_links(db, body.linked_incident_ids)

    now = datetime.now(timezone.utc)
    row = CaseRecord(
        id=str(uuid.uuid4()),
        title=body.title.strip(),
        description=body.description,
        owner=body.owner.strip(),
        severity=_parse_severity(body.severity),
        status=CaseStatus.OPEN,
        sla_due_at=now + timedelta(hours=int(body.sla_hours)),
        linked_alert_ids=alert_ids,
        linked_incident_ids=incident_ids,
        created_by=str(user.get("sub")) if user.get("sub") else None,
    )
    db.add(row)
    await _write_case_audit(
        db,
        actor=str(user.get("sub")) if user.get("sub") else None,
        action="case_created",
        case_id=row.id,
        details={
            "owner": row.owner,
            "severity": row.severity.value,
            "sla_due_at": row.sla_due_at.isoformat() if row.sla_due_at else None,
            "linked_alert_count": len(alert_ids),
            "linked_incident_count": len(incident_ids),
        },
    )
    await db.commit()
    await db.refresh(row)
    return _case_to_response(row)


@router.get("/taxonomy/closure-reasons")
async def list_closure_reasons(
    _user: Annotated[dict, Depends(require_permission("cases:read"))],
):
    return {
        "items": sorted(list(_CLOSURE_TAXONOMY)),
        "count": len(_CLOSURE_TAXONOMY),
    }


@router.get("/metrics/summary")
async def case_metrics_summary(
    _user: Annotated[dict, Depends(require_permission("cases:read"))],
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    total = (await db.execute(select(func.count()).select_from(CaseRecord))).scalar() or 0
    open_cases = (
        await db.execute(
            select(func.count())
            .select_from(CaseRecord)
            .where(CaseRecord.status.in_([CaseStatus.OPEN, CaseStatus.IN_PROGRESS]))
        )
    ).scalar() or 0
    breached = (
        await db.execute(
            select(func.count())
            .select_from(CaseRecord)
            .where(
                CaseRecord.sla_due_at.is_not(None),
                CaseRecord.sla_due_at < now,
                CaseRecord.status.in_([CaseStatus.OPEN, CaseStatus.IN_PROGRESS]),
            )
        )
    ).scalar() or 0
    return {
        "total_cases": int(total),
        "open_cases": int(open_cases),
        "sla_breached_open_cases": int(breached),
    }


@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: str,
    _user: Annotated[dict, Depends(require_permission("cases:read"))],
    db: AsyncSession = Depends(get_db),
):
    row = await db.get(CaseRecord, case_id)
    if not row:
        raise HTTPException(status_code=404, detail="Case not found")
    return _case_to_response(row)


@router.patch("/{case_id}", response_model=CaseResponse)
async def update_case(
    case_id: str,
    body: CaseUpdate,
    user: Annotated[dict, Depends(require_permission("cases:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    row = await db.get(CaseRecord, case_id)
    if not row:
        raise HTTPException(status_code=404, detail="Case not found")

    patch = body.model_dump(exclude_unset=True)
    if not patch:
        return _case_to_response(row)

    if "linked_alert_ids" in patch and patch["linked_alert_ids"] is not None:
        row.linked_alert_ids = await _validate_alert_links(db, patch["linked_alert_ids"])
    if "linked_incident_ids" in patch and patch["linked_incident_ids"] is not None:
        row.linked_incident_ids = await _validate_incident_links(db, patch["linked_incident_ids"])

    if "title" in patch and patch["title"] is not None:
        row.title = patch["title"].strip()
    if "description" in patch:
        row.description = patch["description"]
    if "owner" in patch and patch["owner"] is not None:
        row.owner = patch["owner"].strip()
    if "severity" in patch and patch["severity"] is not None:
        row.severity = _parse_severity(patch["severity"])
    if "sla_hours" in patch and patch["sla_hours"] is not None:
        row.sla_due_at = datetime.now(timezone.utc) + timedelta(hours=int(patch["sla_hours"]))

    new_status = row.status
    if "status" in patch and patch["status"] is not None:
        new_status = _parse_status(patch["status"])

    closure_reason = patch.get("closure_reason", row.closure_reason)
    _enforce_closure_rules(new_status, closure_reason)

    if "closure_reason" in patch:
        if patch["closure_reason"] is not None and patch["closure_reason"] not in _CLOSURE_TAXONOMY:
            raise HTTPException(status_code=400, detail=f"Invalid closure_reason. Allowed: {sorted(_CLOSURE_TAXONOMY)}")
        row.closure_reason = patch["closure_reason"]
    if "closure_notes" in patch:
        row.closure_notes = patch["closure_notes"]

    row.status = new_status
    if row.status in {CaseStatus.RESOLVED, CaseStatus.CLOSED}:
        row.closed_at = datetime.now(timezone.utc)
    elif "status" in patch:
        row.closed_at = None

    await _write_case_audit(
        db,
        actor=str(user.get("sub")) if user.get("sub") else None,
        action="case_updated",
        case_id=row.id,
        details={
            "updated_fields": sorted(list(patch.keys())),
            "status": row.status.value,
            "owner": row.owner,
            "closure_reason": row.closure_reason,
            "linked_alert_count": len(row.linked_alert_ids if isinstance(row.linked_alert_ids, list) else []),
            "linked_incident_count": len(row.linked_incident_ids if isinstance(row.linked_incident_ids, list) else []),
        },
    )

    await db.commit()
    await db.refresh(row)
    return _case_to_response(row)
