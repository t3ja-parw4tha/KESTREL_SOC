"""Alerts API router."""

from typing import Annotated

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, ConfigDict

from app.database import get_db
from app.models import Alert, AlertDecision, AuditLog
from app.models.alert import AlertStatus, AlertSeverity
from app.schemas.alert import CommentSchema
from app.security.rbac import require_permission

router = APIRouter(prefix="/alerts", tags=["alerts"])

STATUS_MAP = {
    "open": AlertStatus.OPEN,
    "new": AlertStatus.OPEN,
    "in_progress": AlertStatus.IN_PROGRESS,
    "investigating": AlertStatus.IN_PROGRESS,
    "resolved": AlertStatus.RESOLVED,
    "dismissed": AlertStatus.FALSE_POSITIVE,
    "false_positive": AlertStatus.FALSE_POSITIVE,
}


class AlertListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    source: str
    severity: str
    status: str
    category: str
    risk_score: int | None
    risk_level: str | None
    created_at: str | None


class AlertListResponse(BaseModel):
    items: list[AlertListItem]
    total: int
    page: int
    limit: int


class AlertDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    source: str
    severity: str
    status: str
    category: str
    asset_id: str | None
    user_id: str | None
    source_ip: str | None
    mitre_techniques: list | None
    raw: dict | None
    enrichment: dict | None
    risk_score: int | None
    risk_level: str | None
    confidence: float | None
    incident_group_id: str | None
    correlated_alert_ids: list | None
    ai_summary: str | None
    ai_key_facts: dict | None
    ai_evidence: dict | None
    ai_remediation: dict | None
    created_at: str | None
    decision: dict | None


class AlertPatchRequest(BaseModel):
    status: str | None = None
    assigned_to: str | None = None


class CommentResponse(BaseModel):
    id: str
    text: str
    timestamp: str


class TimelineItem(BaseModel):
    action: str
    timestamp: str
    analyst: str | None
    details: dict | None


class TimelineResponse(BaseModel):
    items: list[TimelineItem]


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    source: str | None = Query(None),
    category: str | None = Query(None),
    search: str | None = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
):
    """List alerts with optional filters and pagination."""
    q = select(Alert)
    count_q = select(func.count()).select_from(Alert)

    if severity:
        try:
            sev_enum = AlertSeverity(severity)
            q = q.where(Alert.severity == sev_enum)
            count_q = count_q.where(Alert.severity == sev_enum)
        except ValueError:
            pass
    if status:
        try:
            st_enum = STATUS_MAP.get(status.lower(), AlertStatus.OPEN)
            q = q.where(Alert.status == st_enum)
            count_q = count_q.where(Alert.status == st_enum)
        except ValueError:
            pass
    if source:
        q = q.where(Alert.source == source)
        count_q = count_q.where(Alert.source == source)
    if category:
        q = q.where(Alert.category == category)
        count_q = count_q.where(Alert.category == category)
    if search:
        q = q.where(Alert.title.ilike(f"%{search}%"))
        count_q = count_q.where(Alert.title.ilike(f"%{search}%"))

    total_r = await db.execute(count_q)
    total = total_r.scalar() or 0

    q = q.order_by(Alert.created_at.desc()).offset((page - 1) * limit).limit(limit)
    result = await db.execute(q)
    rows = result.scalars().all()

    items = [
        AlertListItem(
            id=r.id,
            title=r.title,
            source=r.source,
            severity=r.severity.value if r.severity else "",
            status=r.status.value if r.status else "",
            category=r.category,
            risk_score=r.risk_score,
            risk_level=r.risk_level,
            created_at=r.created_at.isoformat() if r.created_at else None,
        )
        for r in rows
    ]
    return AlertListResponse(items=items, total=total, page=page, limit=limit)


@router.get("/{alert_id}", response_model=AlertDetailResponse)
async def get_alert(
    alert_id: str,
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
):
    """Return full alert with decision, enrichment, and AI summary."""
    r = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = r.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    dec_r = await db.execute(
        select(AlertDecision).where(AlertDecision.alert_id == alert_id).order_by(AlertDecision.generated_at.desc()).limit(1)
    )
    decision_row = dec_r.scalar_one_or_none()
    decision = None
    if decision_row:
        decision = {
            "risk_score": decision_row.risk_score,
            "risk_level": decision_row.risk_level,
            "confidence": decision_row.confidence,
            "explanation": decision_row.explanation,
            "recommended_actions": decision_row.recommended_actions,
            "mitre_techniques": decision_row.mitre_techniques,
        }

    corr_ids = None
    if alert.correlated_alert_ids and isinstance(alert.correlated_alert_ids, dict):
        corr_ids = alert.correlated_alert_ids.get("ids") or []

    return AlertDetailResponse(
        id=alert.id,
        title=alert.title,
        source=alert.source,
        severity=alert.severity.value if alert.severity else "",
        status=alert.status.value if alert.status else "",
        category=alert.category,
        asset_id=alert.asset_id,
        user_id=alert.user_id,
        source_ip=alert.source_ip,
        mitre_techniques=alert.mitre_techniques if isinstance(alert.mitre_techniques, list) else (alert.mitre_techniques.get("items", []) if isinstance(alert.mitre_techniques, dict) else []),
        raw=alert.raw,
        enrichment=alert.enrichment,
        risk_score=alert.risk_score,
        risk_level=alert.risk_level,
        confidence=alert.confidence,
        incident_group_id=alert.incident_group_id,
        correlated_alert_ids=corr_ids,
        ai_summary=alert.ai_summary,
        ai_key_facts=alert.ai_key_facts,
        ai_evidence=alert.ai_evidence,
        ai_remediation=alert.ai_remediation,
        created_at=alert.created_at.isoformat() if alert.created_at else None,
        decision=decision,
    )


@router.patch("/{alert_id}")
async def update_alert(
    alert_id: str,
    body: AlertPatchRequest,
    _user: Annotated[dict, Depends(require_permission("alerts:update_status"))],
    db: AsyncSession = Depends(get_db),
):
    """Update alert status and/or assigned_to; log to audit."""
    r = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = r.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    details = {}
    if body.status is not None:
        st_enum = STATUS_MAP.get(body.status.lower(), AlertStatus.OPEN)
        details["old_status"] = alert.status.value if alert.status else None
        alert.status = st_enum
        details["new_status"] = st_enum.value
    if body.assigned_to is not None:
        details["assigned_to"] = body.assigned_to
        alert.assigned_to = body.assigned_to

    audit = AuditLog(
        id=str(uuid.uuid4()),
        action="alert_updated",
        alert_id=alert_id,
        analyst=str(_user.get("sub", "")),
        details=details,
    )
    db.add(audit)
    await db.flush()
    return {"id": alert_id, "status": "ok"}


@router.post("/{alert_id}/comments", response_model=CommentResponse)
async def add_comment(
    alert_id: str,
    body: CommentSchema,
    _user: Annotated[dict, Depends(require_permission("alerts:comment"))],
    db: AsyncSession = Depends(get_db),
):
    """Add comment to alert and log to audit."""
    r = await db.execute(select(Alert).where(Alert.id == alert_id))
    if not r.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Alert not found")

    audit_id = str(uuid.uuid4())
    audit = AuditLog(
        id=audit_id,
        action="comment",
        alert_id=alert_id,
        analyst=str(_user.get("sub", "")),
        details={"text": body.text},
    )
    db.add(audit)
    await db.flush()
    return CommentResponse(
        id=audit_id,
        text=body.text,
        timestamp=audit.timestamp.isoformat() if audit.timestamp else "",
    )


@router.get("/{alert_id}/timeline", response_model=TimelineResponse)
async def get_alert_timeline(
    alert_id: str,
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
):
    """Return chronological list of all actions on this alert."""
    r = await db.execute(select(Alert).where(Alert.id == alert_id))
    if not r.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Alert not found")

    audit_q = select(AuditLog).where(AuditLog.alert_id == alert_id).order_by(AuditLog.timestamp.asc())
    audit_r = await db.execute(audit_q)
    audit_rows = audit_r.scalars().all()

    dec_q = select(AlertDecision).where(AlertDecision.alert_id == alert_id).order_by(AlertDecision.generated_at.asc())
    dec_r = await db.execute(dec_q)
    dec_rows = dec_r.scalars().all()

    items: list[TimelineItem] = []
    for row in audit_rows:
        items.append(
            TimelineItem(
                action=row.action,
                timestamp=row.timestamp.isoformat() if row.timestamp else "",
                analyst=row.analyst,
                details=row.details,
            )
        )
    for row in dec_rows:
        items.append(
            TimelineItem(
                action="decision",
                timestamp=row.generated_at.isoformat() if getattr(row, "generated_at", None) else "",
                analyst=None,
                details={"risk_score": row.risk_score, "risk_level": row.risk_level},
            )
        )
    items.sort(key=lambda x: x.timestamp)
    return TimelineResponse(items=items)
