"""Incidents API router."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Alert, AlertDecision
from app.security.rbac import require_permission

router = APIRouter(prefix="/incidents", tags=["incidents"])


class IncidentListItem(BaseModel):
    incident_id: str
    alert_count: int
    max_risk_score: int | None
    highest_severity: str
    alert_ids: list[str]


class IncidentDetailAlert(BaseModel):
    id: str
    title: str
    severity: str
    risk_score: int | None
    created_at: str | None


class IncidentDetailResponse(BaseModel):
    incident_id: str
    alerts: list[IncidentDetailAlert]
    mitre_techniques: list[dict]
    attack_timeline: list[dict]
    recommended_actions: list[str]


class IncidentListResponse(BaseModel):
    items: list[IncidentListItem]
    total: int


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

    score_by_id = {row.incident_group_id: (row.max_score or 0) for row in rows}
    items = []
    for row in rows:
        gid = row.incident_group_id
        alerts_in = alerts_by_incident.get(gid, [])
        alert_ids = [a.id for a in alerts_in]
        items.append(
            IncidentListItem(
                incident_id=gid,
                alert_count=row.cnt,
                max_risk_score=row.max_score,
                highest_severity=row.max_sev.value if hasattr(row.max_sev, "value") else str(row.max_sev or ""),
                alert_ids=alert_ids,
            )
        )
    items.sort(key=lambda x: (x.max_risk_score or 0), reverse=True)
    return IncidentListResponse(items=items, total=len(items))


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident(
    incident_id: str,
    _user: Annotated[dict, Depends(require_permission("incidents:read"))],
    db: AsyncSession = Depends(get_db),
) -> IncidentDetailResponse:
    """
    Return all alerts in the incident, aggregated MITRE techniques, attack timeline, and combined recommended actions.
    """
    r = await db.execute(select(Alert).where(Alert.incident_group_id == incident_id).order_by(Alert.created_at.asc()))
    alerts = r.scalars().all()
    if not alerts:
        raise HTTPException(status_code=404, detail="Incident not found")

    mitre_seen: dict[str, dict] = {}
    for a in alerts:
        mt = a.mitre_techniques
        if isinstance(mt, list):
            for t in mt:
                if isinstance(t, dict) and t.get("technique_id"):
                    mitre_seen[t["technique_id"]] = t
        elif isinstance(mt, dict) and "items" in mt:
            for t in mt["items"] or []:
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
                "severity": a.severity.value if hasattr(a.severity, "value") else str(a.severity),
            }
        )

    alert_ids = [a.id for a in alerts]
    dec_r = await db.execute(
        select(AlertDecision)
        .where(AlertDecision.alert_id.in_(alert_ids))
        .order_by(AlertDecision.alert_id, AlertDecision.generated_at.desc())
    )
    all_decisions = dec_r.scalars().all()
    latest_decision: dict[str, AlertDecision] = {}
    for dec in all_decisions:
        if dec.alert_id not in latest_decision:
            latest_decision[dec.alert_id] = dec

    recommended: list[str] = []
    for a in alerts:
        dec = latest_decision.get(a.id)
        if dec and dec.recommended_actions:
            ra = dec.recommended_actions
            if isinstance(ra, list):
                recommended.extend(ra)
            elif isinstance(ra, dict) and "items" in ra:
                recommended.extend(ra["items"] or [])
    recommended = list(dict.fromkeys(recommended))

    alert_details = [
        IncidentDetailAlert(
            id=a.id,
            title=a.title,
            severity=a.severity.value if hasattr(a.severity, "value") else str(a.severity),
            risk_score=a.risk_score,
            created_at=a.created_at.isoformat() if a.created_at else None,
        )
        for a in alerts
    ]

    return IncidentDetailResponse(
        incident_id=incident_id,
        alerts=alert_details,
        mitre_techniques=mitre_list,
        attack_timeline=timeline,
        recommended_actions=recommended,
    )
