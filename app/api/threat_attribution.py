"""Threat actor attribution endpoints (P4-4)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.threat_actor_attribution import attribute_actors
from app.database import get_db
from app.models.alert import Alert
from app.security.rbac import require_permission

router = APIRouter(prefix="/threat-attribution", tags=["threat-attribution"])


def _extract_techniques_from_alert(alert: Alert) -> list[str]:
    payload = alert.mitre_techniques
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        items = payload.get("items") or []
    else:
        items = []

    out: list[str] = []
    for item in items:
        if isinstance(item, dict) and item.get("technique_id"):
            out.append(str(item["technique_id"]))
        elif isinstance(item, str):
            out.append(item)
    return out


@router.get("/alerts/{alert_id}")
async def attribute_by_alert(
    alert_id: str,
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
):
    alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    techniques = _extract_techniques_from_alert(alert)
    candidates = attribute_actors(techniques)
    return {
        "alert_id": alert_id,
        "incident_group_id": alert.incident_group_id,
        "techniques": techniques,
        "candidates": candidates,
    }


@router.get("/incidents/{incident_group_id}")
async def attribute_by_incident(
    incident_group_id: str,
    _user: Annotated[dict, Depends(require_permission("incidents:read"))],
    db: AsyncSession = Depends(get_db),
):
    rows = (
        await db.execute(select(Alert).where(Alert.incident_group_id == incident_group_id))
    ).scalars().all()
    if not rows:
        raise HTTPException(status_code=404, detail="Incident not found")

    merged: list[str] = []
    for alert in rows:
        merged.extend(_extract_techniques_from_alert(alert))

    candidates = attribute_actors(merged)
    return {
        "incident_group_id": incident_group_id,
        "alert_count": len(rows),
        "techniques": sorted(set(merged)),
        "candidates": candidates,
    }
