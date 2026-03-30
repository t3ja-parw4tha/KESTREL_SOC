"""Incidents API router."""

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Alert, AlertDecision
from app.security.csrf import verify_csrf
from app.security.rbac import require_permission


class ResponseActionItem(BaseModel):
    id: str
    label: str
    completed: bool
    assignee: str | None = None


class ResponseActionsPayload(BaseModel):
    actions: list[ResponseActionItem]

router = APIRouter(prefix="/incidents", tags=["incidents"])


class IncidentListItem(BaseModel):
    incident_id: str
    title: str
    description: str
    severity: str
    status: str
    assigned_to: str | None
    alert_count: int
    max_risk_score: int | None
    highest_severity: str
    alert_ids: list[str]
    created_at: str | None
    updated_at: str | None
    mitre_tactics: list[str]


class IncidentDetailAlert(BaseModel):
    id: str
    title: str
    severity: str
    risk_score: int | None
    created_at: str | None
    source: str | None


class IncidentDetailResponse(BaseModel):
    incident_id: str
    title: str
    description: str
    severity: str
    status: str
    assigned_to: str | None
    alert_count: int
    created_at: str | None
    updated_at: str | None
    mitre_tactics: list[str]
    alerts: list[IncidentDetailAlert]
    mitre_techniques: list[dict]
    attack_timeline: list[dict]
    recommended_actions: list[str]


class IncidentListResponse(BaseModel):
    items: list[IncidentListItem]
    total: int


def _severity_str(sev) -> str:
    if hasattr(sev, "value"):
        return sev.value
    return str(sev or "low")


def _extract_tactics(alerts: list) -> list[str]:
    """Extract unique tactic names from alert MITRE technique data."""
    tactics: dict[str, bool] = {}
    for a in alerts:
        mt = a.mitre_techniques
        items = []
        if isinstance(mt, list):
            items = mt
        elif isinstance(mt, dict) and "items" in mt:
            items = mt.get("items") or []
        for t in items:
            if isinstance(t, dict):
                tactic = t.get("tactic") or t.get("phase") or t.get("tactic_name") or ""
                if tactic:
                    tactics[tactic] = True
    return list(tactics.keys())


def _pick_title_description(alerts: list) -> tuple[str, str]:
    """Pick title and description from the most severe / most recent alert."""
    if not alerts:
        return "Unnamed Incident", "No details available."
    # Severity order: critical > high > medium > low
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    best = max(
        alerts,
        key=lambda a: (
            sev_order.get(_severity_str(a.severity), 0),
            a.risk_score or 0,
        ),
    )
    title = best.title or f"Incident from alert {best.id}"
    desc = best.description or f"Security incident containing {len(alerts)} correlated alert(s)."
    return title, desc


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    _user: Annotated[dict, Depends(require_permission("incidents:read"))],
    db: AsyncSession = Depends(get_db),
):
    """
    Group alerts by incident_group_id and return incident list sorted by risk score.
    """
    subq = (
        select(
            Alert.incident_group_id,
            func.count(Alert.id).label("cnt"),
            func.max(Alert.risk_score).label("max_score"),
            func.max(Alert.severity).label("max_sev"),
            func.min(Alert.created_at).label("first_seen"),
            func.max(Alert.created_at).label("last_seen"),
        )
        .where(Alert.incident_group_id.is_not(None))
        .group_by(Alert.incident_group_id)
    )
    r = await db.execute(subq)
    rows = r.all()
    if not rows:
        return IncidentListResponse(items=[], total=0)

    incident_ids = [row.incident_group_id for row in rows]
    alert_q = select(Alert).where(Alert.incident_group_id.in_(incident_ids))
    alert_r = await db.execute(alert_q)
    all_alerts = alert_r.scalars().all()
    alerts_by_incident: dict[str, list] = {}
    for a in all_alerts:
        gid = a.incident_group_id or ""
        alerts_by_incident.setdefault(gid, []).append(a)

    items = []
    for row in rows:
        gid = row.incident_group_id
        alerts_in = alerts_by_incident.get(gid, [])
        alert_ids = [a.id for a in alerts_in]
        sev = _severity_str(row.max_sev)
        title, desc = _pick_title_description(alerts_in)
        tactics = _extract_tactics(alerts_in)
        items.append(
            IncidentListItem(
                incident_id=gid,
                title=title,
                description=desc,
                severity=sev,
                status="open",
                assigned_to=None,
                alert_count=row.cnt,
                max_risk_score=row.max_score,
                highest_severity=sev,
                alert_ids=alert_ids,
                created_at=row.first_seen.isoformat() if row.first_seen else None,
                updated_at=row.last_seen.isoformat() if row.last_seen else None,
                mitre_tactics=tactics,
            )
        )
    items.sort(key=lambda x: (x.max_risk_score or 0), reverse=True)
    return IncidentListResponse(items=items, total=len(items))


class CreateIncidentRequest(BaseModel):
    alert_ids: list[str] = Field(..., min_length=1, description="Alert IDs to group into this incident")
    title_override: str | None = Field(default=None, max_length=256)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_incident(
    body: CreateIncidentRequest,
    _user: Annotated[dict, Depends(require_permission("incidents:write"))],
    _csrf: None = Depends(verify_csrf),
    db: AsyncSession = Depends(get_db),
):
    """Manually create an incident by grouping a set of alerts under a new incident_group_id."""
    alerts = (
        await db.execute(select(Alert).where(Alert.id.in_(body.alert_ids)))
    ).scalars().all()
    if not alerts:
        raise HTTPException(status_code=404, detail="No matching alerts found")

    # If some alerts already belong to an incident, reject to prevent conflicts
    already_grouped = [a.id for a in alerts if a.incident_group_id]
    if already_grouped:
        raise HTTPException(
            status_code=409,
            detail=f"Alert(s) already in an incident: {already_grouped[:5]}",
        )

    new_group_id = str(uuid.uuid4())
    for a in alerts:
        a.incident_group_id = new_group_id
    await db.flush()

    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    alert_list = list(alerts)
    title, desc = _pick_title_description(alert_list)
    if body.title_override:
        title = body.title_override.strip()
    tactics = _extract_tactics(alert_list)
    sev = max((_severity_str(a.severity) for a in alerts), key=lambda s: sev_order.get(s, 0))
    max_risk = max((a.risk_score or 0 for a in alerts), default=0)

    return IncidentListItem(
        incident_id=new_group_id,
        title=title,
        description=desc,
        severity=sev,
        status="open",
        assigned_to=None,
        alert_count=len(alerts),
        max_risk_score=max_risk,
        highest_severity=sev,
        alert_ids=[a.id for a in alerts],
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
        mitre_tactics=tactics,
    )


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident(
    incident_id: str,
    _user: Annotated[dict, Depends(require_permission("incidents:read"))],
    db: AsyncSession = Depends(get_db),
) -> IncidentDetailResponse:
    """
    Return all alerts in the incident, aggregated MITRE techniques, attack timeline,
    and combined recommended actions.
    """
    r = await db.execute(
        select(Alert).where(Alert.incident_group_id == incident_id).order_by(Alert.created_at.asc())
    )
    alerts = r.scalars().all()
    if not alerts:
        raise HTTPException(status_code=404, detail="Incident not found")

    title, desc = _pick_title_description(list(alerts))
    tactics = _extract_tactics(list(alerts))

    # Severity: highest across all alerts
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    highest_sev = max(alerts, key=lambda a: sev_order.get(_severity_str(a.severity), 0))
    severity = _severity_str(highest_sev.severity)

    created_at = alerts[0].created_at.isoformat() if alerts[0].created_at else None
    updated_at = alerts[-1].created_at.isoformat() if alerts[-1].created_at else None

    mitre_seen: dict[str, dict] = {}
    for a in alerts:
        mt = a.mitre_techniques
        if isinstance(mt, list):
            for t in mt:
                if isinstance(t, dict) and t.get("technique_id"):
                    mitre_seen[t["technique_id"]] = t
        elif isinstance(mt, dict) and "items" in mt:
            for t in mt.get("items") or []:
                if isinstance(t, dict) and t.get("technique_id"):
                    mitre_seen[t["technique_id"]] = t
    mitre_list = list(mitre_seen.values())

    timeline = []
    for a in alerts:
        timeline.append(
            {
                "alert_id": a.id,
                "title": a.title,
                "timestamp": a.created_at.isoformat() if a.created_at else None,
                "severity": _severity_str(a.severity),
                "type": "correlation",
                "actor": "System",
                "event": f"Alert correlated: {a.title}",
                "time": a.created_at.isoformat() if a.created_at else None,
            }
        )

    alert_ids = [a.id for a in alerts]
    dec_r = await db.execute(
        select(AlertDecision)
        .where(AlertDecision.alert_id.in_(alert_ids))
        .order_by(AlertDecision.alert_id, AlertDecision.generated_at.desc())
    )
    all_decisions = dec_r.scalars().all()
    latest_decision: dict[str, AlertDecision | None] = {}
    for dec in all_decisions:
        if dec.alert_id not in latest_decision:
            latest_decision[dec.alert_id] = dec

    recommended: list[str] = []
    for a in alerts:
        adec = latest_decision.get(a.id)
        if adec and adec.recommended_actions:
            ra = adec.recommended_actions
            if isinstance(ra, list):
                recommended.extend(ra)
            elif isinstance(ra, dict) and "items" in ra:
                recommended.extend(ra.get("items") or [])
    recommended = list(dict.fromkeys(recommended))

    alert_details = [
        IncidentDetailAlert(
            id=a.id,
            title=a.title,
            severity=_severity_str(a.severity),
            risk_score=a.risk_score,
            created_at=a.created_at.isoformat() if a.created_at else None,
            source=getattr(a, "source", None),
        )
        for a in alerts
    ]

    return IncidentDetailResponse(
        incident_id=incident_id,
        title=title,
        description=desc,
        severity=severity,
        status="open",
        assigned_to=None,
        alert_count=len(alerts),
        created_at=created_at,
        updated_at=updated_at,
        mitre_tactics=tactics,
        alerts=alert_details,
        mitre_techniques=mitre_list,
        attack_timeline=timeline,
        recommended_actions=recommended,
    )


def _get_anchor_alert(alerts: list) -> Alert | None:
    """Return the first (earliest) alert in the incident to store incident-level metadata."""
    return alerts[0] if alerts else None


@router.get("/{incident_id}/actions", response_model=list[ResponseActionItem])
async def get_incident_actions(
    incident_id: str,
    _user: Annotated[dict, Depends(require_permission("incidents:read"))],
    db: AsyncSession = Depends(get_db),
) -> list[ResponseActionItem]:
    """Return saved response actions for an incident."""
    r = await db.execute(
        select(Alert).where(Alert.incident_group_id == incident_id).order_by(Alert.created_at.asc())
    )
    alerts = r.scalars().all()
    if not alerts:
        raise HTTPException(status_code=404, detail="Incident not found")

    anchor = _get_anchor_alert(list(alerts))
    if not anchor:
        return []

    enrichment = dict(anchor.enrichment or {})
    saved: list[dict] = enrichment.get("incident_actions") or []
    return [ResponseActionItem(**a) for a in saved if isinstance(a, dict)]


@router.put("/{incident_id}/actions", response_model=list[ResponseActionItem])
async def save_incident_actions(
    incident_id: str,
    body: ResponseActionsPayload,
    _user: Annotated[dict, Depends(require_permission("incidents:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> list[ResponseActionItem]:
    """Save (replace) response actions for an incident."""
    r = await db.execute(
        select(Alert).where(Alert.incident_group_id == incident_id).order_by(Alert.created_at.asc())
    )
    alerts = r.scalars().all()
    if not alerts:
        raise HTTPException(status_code=404, detail="Incident not found")

    anchor = _get_anchor_alert(list(alerts))
    if not anchor:
        raise HTTPException(status_code=404, detail="Incident has no alerts")

    enrichment = dict(anchor.enrichment or {})
    enrichment["incident_actions"] = [a.model_dump() for a in body.actions]
    anchor.enrichment = enrichment
    await db.flush()
    await db.commit()
    return body.actions
