"""Decisions API router."""

from datetime import datetime, timezone
from typing import Annotated
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.decision_engine.engine import run_decision_engine
from app.core.decision_engine.types import DecisionInput, NormalizedAlert
from app.database import get_db
from app.models import Alert, AlertDecision
from app.security.rbac import require_permission

router = APIRouter(prefix="/decisions", tags=["decisions"])


class DecisionRunRequest(BaseModel):
    alert_id: str


class DecisionRunResponse(BaseModel):
    alert_id: str
    risk_score: int
    risk_level: str
    confidence: float
    explanation: list[str]
    recommended_actions: list[str]
    mitre_techniques: list[dict]
    correlated_alert_ids: list[str]
    incident_group_id: str | None
    engine_version: str
    correlation_rule_triggered: str | None = None


def _alert_to_normalized(alert: Alert) -> NormalizedAlert:
    mitre_list = alert.mitre_techniques
    if isinstance(mitre_list, dict) and "items" in mitre_list:
        mitre_list = mitre_list["items"]
    elif not isinstance(mitre_list, list):
        mitre_list = []
    return NormalizedAlert(
        id=alert.id,
        title=alert.title,
        source=alert.source,
        severity=alert.severity.value if alert.severity else str(alert.severity),
        category=alert.category,
        asset_id=alert.asset_id,
        user_id=alert.user_id,
        source_ip=alert.source_ip,
        alert_type="",
        timestamp=alert.created_at or datetime.now(timezone.utc),
        raw=alert.raw,
        mitre_techniques=mitre_list or None,
        enrichment=alert.enrichment,
    )


@router.get("")
async def list_decisions(
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
):
    """List decisions (stub)."""
    return {"items": [], "total": 0}


@router.post("/run", response_model=DecisionRunResponse)
async def run_decision(
    body: DecisionRunRequest,
    _user: Annotated[dict, Depends(require_permission("decisions:run"))],
    db: AsyncSession = Depends(get_db),
) -> DecisionRunResponse:
    """Run decision engine for an alert; fetch alert and recent correlated alerts, save and return DecisionOutput."""
    r = await db.execute(select(Alert).where(Alert.id == body.alert_id))
    alert = r.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    normalized = _alert_to_normalized(alert)
    recent_alerts: list[NormalizedAlert] = []

    if alert.incident_group_id:
        group_r = await db.execute(
            select(Alert).where(Alert.incident_group_id == alert.incident_group_id, Alert.id != alert.id).limit(20)
        )
        for row in group_r.scalars().all():
            recent_alerts.append(_alert_to_normalized(row))

    decision_input = DecisionInput(alert=normalized, asset=None, threat=None, history=None)
    output = run_decision_engine(decision_input, recent_alerts=recent_alerts)

    decision_id = str(uuid.uuid4())
    dec = AlertDecision(
        id=decision_id,
        alert_id=alert.id,
        risk_score=output.risk_score,
        risk_level=output.risk_level,
        confidence=output.confidence,
        explanation={"items": output.explanation},
        recommended_actions={"items": output.recommended_actions},
        mitre_techniques={"items": output.mitre_techniques},
        correlated_alert_ids={"ids": output.correlated_alert_ids} if output.correlated_alert_ids else None,
        incident_group_id=output.incident_group_id,
        engine_version=output.engine_version,
    )
    db.add(dec)

    alert.risk_score = output.risk_score
    alert.risk_level = output.risk_level
    alert.confidence = output.confidence
    alert.incident_group_id = output.incident_group_id
    alert.correlated_alert_ids = {"ids": output.correlated_alert_ids} if output.correlated_alert_ids else None
    if output.mitre_techniques:
        alert.mitre_techniques = output.mitre_techniques
    await db.flush()

    return DecisionRunResponse(
        alert_id=alert.id,
        risk_score=output.risk_score,
        risk_level=output.risk_level,
        confidence=output.confidence,
        explanation=output.explanation,
        recommended_actions=output.recommended_actions,
        mitre_techniques=output.mitre_techniques,
        correlated_alert_ids=output.correlated_alert_ids,
        incident_group_id=output.incident_group_id,
        engine_version=output.engine_version,
        correlation_rule_triggered=output.correlation_rule_triggered,
    )
