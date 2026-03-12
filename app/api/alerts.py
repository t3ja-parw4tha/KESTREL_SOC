"""Alerts API router."""

import re
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, ConfigDict, model_validator

from app.database import get_db
from app.models import Alert, AlertDecision, AuditLog, User
from app.models.alert import AlertStatus, AlertSeverity
from app.schemas.alert import CommentSchema
from app.security.rbac import require_permission, get_role_permissions
from app.security.csrf import verify_csrf

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
    assigned_to: str | None
    asset_id: str | None
    user_id: str | None
    source_ip: str | None
    dest_ip: str | None
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
    ai_next_steps: dict | None
    created_at: str | None
    decision: dict | None


class AlertPatchRequest(BaseModel):
    status: str | None = None
    assigned_to: str | None = None
    assign_comment: str | None = None  # Required when reassigning to a different analyst


# Bulk update: strict limits for security and stability
BULK_ALERT_IDS_MAX = 200
BULK_ALERT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9\-]{1,36}$")


class BulkAlertPatchRequest(BaseModel):
    """Bulk update alerts. At least one of status or assigned_to must be set."""

    alert_ids: list[str]
    status: str | None = None
    assigned_to: str | None = None
    assign_comment: str | None = None

    @model_validator(mode="after")
    def validate_bulk_request(self):
        if not self.alert_ids:
            raise ValueError("alert_ids must not be empty")
        if len(self.alert_ids) > BULK_ALERT_IDS_MAX:
            raise ValueError(f"At most {BULK_ALERT_IDS_MAX} alert IDs allowed")
        seen = set()
        for aid in self.alert_ids:
            if not (aid and len(aid) <= 36 and BULK_ALERT_ID_PATTERN.match(aid)):
                raise ValueError(f"Invalid alert_id: {aid!r}")
            if aid in seen:
                raise ValueError(f"Duplicate alert_id: {aid}")
            seen.add(aid)
        if self.status is None and self.assigned_to is None:
            raise ValueError("At least one of status or assigned_to must be set")
        if self.status is not None and self.status.lower() not in STATUS_MAP:
            raise ValueError(f"Invalid status: {self.status}. Allowed: {list(STATUS_MAP.keys())}")
        if self.assigned_to is not None and isinstance(self.assigned_to, str) and len(self.assigned_to.strip()) > 256:
            raise ValueError("assigned_to must be at most 256 characters")
        if self.assign_comment is not None and len(self.assign_comment) > 2000:
            raise ValueError("assign_comment must be at most 2000 characters")
        return self


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
    assigned_to: str | None = Query(None),
    date_from: str | None = Query(None, description="ISO 8601 date/datetime lower bound for created_at"),
    date_to: str | None = Query(None, description="ISO 8601 date/datetime upper bound for created_at"),
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
    if assigned_to:
        q = q.where(Alert.assigned_to == assigned_to)
        count_q = count_q.where(Alert.assigned_to == assigned_to)
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from)
            q = q.where(Alert.created_at >= dt_from)
            count_q = count_q.where(Alert.created_at >= dt_from)
        except ValueError:
            pass  # Ignore malformed date
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
            q = q.where(Alert.created_at <= dt_to)
            count_q = count_q.where(Alert.created_at <= dt_to)
        except ValueError:
            pass  # Ignore malformed date

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
        assigned_to=alert.assigned_to,
        asset_id=alert.asset_id,
        user_id=alert.user_id,
        source_ip=alert.source_ip,
        dest_ip=alert.dest_ip,
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
        ai_next_steps=alert.ai_next_steps,
        created_at=alert.created_at.isoformat() if alert.created_at else None,
        decision=decision,
    )


async def _resolve_username(db: AsyncSession, user_sub: int) -> str | None:
    """Look up the username for the current JWT sub (user ID)."""
    r = await db.execute(select(User).where(User.id == user_sub))
    u = r.scalar_one_or_none()
    return u.username if u else None


@router.patch("/bulk", response_model=dict)
async def bulk_update_alerts(
    body: BulkAlertPatchRequest,
    _user: Annotated[dict, Depends(require_permission("alerts:bulk_update"))],
    _csrf: None = Depends(verify_csrf),
    db: AsyncSession = Depends(get_db),
):
    """
    Bulk update status and/or assignment for up to 200 alerts.
    Reassigning to another user requires alerts:assign and a non-empty assign_comment.
    """
    user_sub = int(_user.get("sub", 0) or 0)
    role = _user.get("role", "")
    current_username = await _resolve_username(db, user_sub)

    # Reassign to another user: require alerts:assign and assign_comment
    assignee = (body.assigned_to or "").strip() or None
    if assignee and assignee != current_username:
        if "alerts:assign" not in get_role_permissions(role):
            raise HTTPException(
                status_code=403,
                detail="Insufficient permission to assign alerts to other users",
            )
        if not (body.assign_comment or "").strip():
            raise HTTPException(
                status_code=422,
                detail="assign_comment is required when bulk assigning to another user",
            )

    # Load all alerts by id (only those that exist)
    result = await db.execute(
        select(Alert).where(Alert.id.in_(body.alert_ids))
    )
    alerts = {a.id: a for a in result.scalars().all()}
    not_found = [aid for aid in body.alert_ids if aid not in alerts]

    updated = 0
    for aid in body.alert_ids:
        alert = alerts.get(aid)
        if not alert:
            continue
        if body.status is not None:
            st_enum = STATUS_MAP.get(body.status.lower(), AlertStatus.OPEN)
            alert.status = st_enum
        if body.assigned_to is not None:
            alert.assigned_to = assignee
        updated += 1

    # Single audit entry for bulk action (no PII in details beyond counts and action type)
    audit = AuditLog(
        id=str(uuid.uuid4()),
        action="bulk_alert_update",
        alert_id=None,
        analyst=str(user_sub),
        details={
            "alert_count": len(body.alert_ids),
            "updated_count": updated,
            "not_found_count": len(not_found),
            "status": body.status,
            "assigned_to": assignee if assignee else None,
        },
    )
    db.add(audit)
    await db.commit()

    return {
        "updated": updated,
        "failed": len(not_found),
        "error_ids": not_found,
    }


@router.patch("/{alert_id}")
async def update_alert(
    alert_id: str,
    body: AlertPatchRequest,
    _user: Annotated[dict, Depends(require_permission("alerts:update_status"))],
    _csrf: None = Depends(verify_csrf),
    db: AsyncSession = Depends(get_db),
):
    """
    Update alert status and/or assigned_to.

    Assignment rules:
    - Status → in_progress: auto-assigns to acting user ONLY when alert is currently unassigned.
    - Pick up (null → self): requires alerts:pick_up. No comment needed.
    - Drop own (self → null): any role. No comment needed.
    - Reassign to someone else / unassign someone else: requires alerts:assign + assign_comment.
      assign_comment is also stored as a timeline comment for team visibility.
    """
    r = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = r.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    user_sub = int(_user.get("sub", 0) or 0)
    role = _user.get("role", "")
    details: dict = {}

    # Resolve current username only when needed (status auto-assign or assignment change)
    needs_username = (
        body.status is not None and body.status.lower() in ("in_progress", "investigating")
    ) or "assigned_to" in body.model_fields_set
    current_username: str | None = None
    if needs_username:
        current_username = await _resolve_username(db, user_sub)

    # ── STATUS CHANGE ─────────────────────────────────────────────────────────
    if body.status is not None:
        st_enum = STATUS_MAP.get(body.status.lower(), AlertStatus.OPEN)
        details["old_status"] = alert.status.value if alert.status else None
        alert.status = st_enum
        details["new_status"] = st_enum.value
        # Auto-assign ONLY when: status moves to in_progress AND alert is unassigned.
        # Never overwrite an existing assignee — that must be done via explicit reassignment.
        if st_enum == AlertStatus.IN_PROGRESS and alert.assigned_to is None and current_username:
            alert.assigned_to = current_username
            details["auto_assigned"] = current_username

    # ── ASSIGNMENT CHANGE ─────────────────────────────────────────────────────
    # Use model_fields_set so sending {"assigned_to": null} is also caught.
    if "assigned_to" in body.model_fields_set:
        new_assignee = body.assigned_to or None
        old_assignee = alert.assigned_to

        if new_assignee is None and old_assignee == current_username:
            # Case A: Dropping own assignment (self → null). No extra permission needed.
            details["previous_assigned_to"] = old_assignee
            alert.assigned_to = None

        elif new_assignee == current_username and old_assignee is None:
            # Case B: Picking up an unassigned alert (null → self).
            if "alerts:pick_up" not in get_role_permissions(role) and "alerts:assign" not in get_role_permissions(role):
                raise HTTPException(status_code=403, detail="Insufficient permission to pick up alerts")
            details["assigned_to"] = new_assignee
            alert.assigned_to = new_assignee

        else:
            # Case C: Reassigning to another user OR unassigning someone else's alert.
            # Both require alerts:assign AND a non-empty reason comment.
            if "alerts:assign" not in get_role_permissions(role):
                raise HTTPException(status_code=403, detail="Insufficient permission to assign alerts")
            comment_text = (body.assign_comment or "").strip()
            if not comment_text:
                raise HTTPException(
                    status_code=422,
                    detail="assign_comment is required when reassigning or unassigning another analyst's alert",
                )
            details["previous_assigned_to"] = old_assignee
            details["assigned_to"] = new_assignee
            details["assign_reason"] = comment_text
            alert.assigned_to = new_assignee
            # Store the reason as a timeline comment so the whole team can see it.
            prefix = "Unassigned" if new_assignee is None else f"Reassigned to {new_assignee}"
            if old_assignee:
                prefix += f" (was {old_assignee})"
            reassign_comment = AuditLog(
                id=str(uuid.uuid4()),
                action="comment",
                alert_id=alert_id,
                analyst=str(user_sub),
                details={"text": f"[{prefix}] {comment_text}"},
            )
            db.add(reassign_comment)

    audit = AuditLog(
        id=str(uuid.uuid4()),
        action="alert_updated",
        alert_id=alert_id,
        analyst=str(user_sub),
        details=details,
    )
    db.add(audit)
    await db.flush()
    return {"id": alert_id, "status": "ok"}


@router.post("/{alert_id}/pick-up")
async def pick_up_alert(
    alert_id: str,
    _user: Annotated[dict, Depends(require_permission("alerts:pick_up"))],
    _csrf: None = Depends(verify_csrf),
    db: AsyncSession = Depends(get_db),
):
    """
    Pick up an unassigned alert — assigns to current user and sets status to
    in_progress if currently open. Returns 409 if already assigned to someone else.
    No-op (200) if already assigned to the current user.
    """
    r = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = r.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    user_sub = int(_user.get("sub", 0) or 0)
    current_username = await _resolve_username(db, user_sub)
    if not current_username:
        raise HTTPException(status_code=500, detail="Cannot resolve current user")

    # No-op: already assigned to self
    if alert.assigned_to == current_username:
        return {"id": alert_id, "status": "ok", "assigned_to": current_username, "noop": True}

    # 409: assigned to someone else
    if alert.assigned_to and alert.assigned_to != current_username:
        raise HTTPException(
            status_code=409,
            detail=f"Alert is already assigned to {alert.assigned_to}. A senior analyst or admin can reassign it.",
        )

    # Pick up: assign to self; set in_progress if status is open
    alert.assigned_to = current_username
    if alert.status == AlertStatus.OPEN:
        alert.status = AlertStatus.IN_PROGRESS

    audit = AuditLog(
        id=str(uuid.uuid4()),
        action="alert_picked_up",
        alert_id=alert_id,
        analyst=str(user_sub),
        details={"assigned_to": current_username},
    )
    db.add(audit)
    await db.flush()
    return {"id": alert_id, "status": "ok", "assigned_to": current_username}


@router.post("/{alert_id}/comments", response_model=CommentResponse)
async def add_comment(
    alert_id: str,
    body: CommentSchema,
    _user: Annotated[dict, Depends(require_permission("alerts:comment"))],
    _csrf: None = Depends(verify_csrf),
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
    for dec_row in dec_rows:
        items.append(
            TimelineItem(
                action="decision",
                timestamp=dec_row.generated_at.isoformat() if getattr(dec_row, "generated_at", None) else "",
                analyst=None,
                details={"risk_score": dec_row.risk_score, "risk_level": dec_row.risk_level},
            )
        )
    items.sort(key=lambda x: x.timestamp)
    return TimelineResponse(items=items)
