"""AI assistant chat + shift handover endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.client import run_ai_completion
from app.database import get_db
from app.models import AIChatMessage, Alert
from app.models.alert import AlertSeverity, AlertStatus
from app.security.csrf import verify_csrf
from app.security.rbac import require_permission

router = APIRouter(prefix="/ai-assistant", tags=["ai-assistant"])


class ChatRequest(BaseModel):
    context_type: str = Field(pattern="^(alert|incident)$")
    context_id: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=2, max_length=4000)


class ChatMessageResponse(BaseModel):
    id: str
    role: str
    message: str
    analyst: str | None
    created_at: str | None


class ChatResponse(BaseModel):
    reply: ChatMessageResponse
    context_type: str
    context_id: str


class ShiftHandoverResponse(BaseModel):
    generated_at: str
    open_incidents: int
    critical_open_alerts: int
    high_open_alerts: int
    handover: str


async def _validate_context(db: AsyncSession, context_type: str, context_id: str) -> None:
    if context_type == "alert":
        alert = (await db.execute(select(Alert.id).where(Alert.id == context_id))).scalar_one_or_none()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert context not found")
        return

    # incident context uses incident_group_id in alerts table
    incident_anchor = (
        await db.execute(select(Alert.id).where(Alert.incident_group_id == context_id).limit(1))
    ).scalar_one_or_none()
    if not incident_anchor:
        raise HTTPException(status_code=404, detail="Incident context not found")


async def _build_context_snippet(db: AsyncSession, context_type: str, context_id: str) -> str:
    if context_type == "alert":
        alert = (
            await db.execute(select(Alert).where(Alert.id == context_id))
        ).scalar_one_or_none()
        if not alert:
            return ""
        return (
            f"Alert ID: {alert.id}\n"
            f"Title: {alert.title}\n"
            f"Severity: {alert.severity.value if alert.severity else ''}\n"
            f"Status: {alert.status.value if alert.status else ''}\n"
            f"Source: {alert.source}\n"
            f"Category: {alert.category}\n"
            f"Asset: {alert.asset_id or 'n/a'}\n"
            f"User: {alert.user_id or 'n/a'}\n"
            f"Source IP: {alert.source_ip or 'n/a'}\n"
            f"Risk score: {alert.risk_score if alert.risk_score is not None else 'n/a'}\n"
            f"AI Summary: {alert.ai_summary or 'n/a'}"
        )

    rows = (
        await db.execute(
            select(Alert)
            .where(Alert.incident_group_id == context_id)
            .order_by(Alert.created_at.desc())
            .limit(20)
        )
    ).scalars().all()
    if not rows:
        return ""
    lines = [f"Incident ID: {context_id}", f"Alert count in scope: {len(rows)}"]
    for a in rows[:8]:
        lines.append(
            f"- [{a.severity.value if a.severity else ''}] {a.title} (risk={a.risk_score if a.risk_score is not None else 'n/a'}, src={a.source})"
        )
    return "\n".join(lines)


@router.get("/history", response_model=list[ChatMessageResponse])
async def get_chat_history(
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    context_type: str = Query(pattern="^(alert|incident)$"),
    context_id: str = Query(min_length=1, max_length=64),
    db: AsyncSession = Depends(get_db),
) -> list[ChatMessageResponse]:
    await _validate_context(db, context_type, context_id)
    rows = (
        await db.execute(
            select(AIChatMessage)
            .where(
                AIChatMessage.context_type == context_type,
                AIChatMessage.context_id == context_id,
            )
            .order_by(AIChatMessage.created_at.asc())
            .limit(200)
        )
    ).scalars().all()
    return [
        ChatMessageResponse(
            id=r.id,
            role=r.role,
            message=r.message,
            analyst=r.analyst,
            created_at=r.created_at.isoformat() if r.created_at else None,
        )
        for r in rows
    ]


@router.post("/chat", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    user: Annotated[dict, Depends(require_permission("ai:generate"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> ChatResponse:
    await _validate_context(db, body.context_type, body.context_id)

    user_msg = AIChatMessage(
        id=str(uuid.uuid4()),
        context_type=body.context_type,
        context_id=body.context_id,
        role="user",
        message=body.message,
        analyst=str(user.get("sub")) if user.get("sub") else None,
    )
    db.add(user_msg)
    await db.flush()

    context_snippet = await _build_context_snippet(db, body.context_type, body.context_id)
    system = (
        "You are a senior SOC analyst assistant. Be concise, evidence-driven, and operational. "
        "When unsure, say uncertainty explicitly. Do not invent indicators. "
        "Output plain text with short bullets and concrete next actions."
    )
    prompt = (
        f"Investigation context:\n{context_snippet}\n\n"
        f"Analyst question:\n{body.message}\n\n"
        "Answer with:\n"
        "1) What this likely means\n"
        "2) Highest-confidence evidence\n"
        "3) Immediate next 3 actions\n"
        "4) What to verify before escalation"
    )

    reply_text = ""
    try:
        reply_text = (await run_ai_completion(system=system, prompt=prompt)).strip()
    except Exception:
        reply_text = ""

    if not reply_text:
        reply_text = (
            "No AI provider response was returned. Use this fallback workflow:\n"
            "- Confirm alert/incident scope and affected entities\n"
            "- Validate high-risk indicators (IPs, users, hosts) against enrichment\n"
            "- Contain suspicious assets/accounts and preserve evidence\n"
            "- Document findings and escalate if impact is unclear"
        )

    assistant_msg = AIChatMessage(
        id=str(uuid.uuid4()),
        context_type=body.context_type,
        context_id=body.context_id,
        role="assistant",
        message=reply_text,
        analyst=None,
    )
    db.add(assistant_msg)
    await db.flush()
    await db.refresh(assistant_msg)

    return ChatResponse(
        reply=ChatMessageResponse(
            id=assistant_msg.id,
            role=assistant_msg.role,
            message=assistant_msg.message,
            analyst=assistant_msg.analyst,
            created_at=assistant_msg.created_at.isoformat() if assistant_msg.created_at else None,
        ),
        context_type=body.context_type,
        context_id=body.context_id,
    )


@router.post("/shift-handover", response_model=ShiftHandoverResponse)
async def generate_shift_handover(
    _user: Annotated[dict, Depends(require_permission("ai:generate"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> ShiftHandoverResponse:
    now = datetime.now(timezone.utc)

    open_incident_ids = (
        await db.execute(
            select(func.count(func.distinct(Alert.incident_group_id)))
            .where(
                Alert.incident_group_id.is_not(None),
                Alert.status.in_([AlertStatus.OPEN, AlertStatus.IN_PROGRESS]),
            )
        )
    ).scalar() or 0

    critical_open = (
        await db.execute(
            select(func.count(Alert.id)).where(
                Alert.status.in_([AlertStatus.OPEN, AlertStatus.IN_PROGRESS]),
                Alert.severity == AlertSeverity.CRITICAL,
            )
        )
    ).scalar() or 0
    high_open = (
        await db.execute(
            select(func.count(Alert.id)).where(
                Alert.status.in_([AlertStatus.OPEN, AlertStatus.IN_PROGRESS]),
                Alert.severity == AlertSeverity.HIGH,
            )
        )
    ).scalar() or 0

    recent = (
        await db.execute(
            select(Alert)
            .where(Alert.status.in_([AlertStatus.OPEN, AlertStatus.IN_PROGRESS]))
            .order_by(Alert.risk_score.desc(), Alert.created_at.desc())
            .limit(20)
        )
    ).scalars().all()

    lines = [
        f"Open incidents: {open_incident_ids}",
        f"Critical open alerts: {critical_open}",
        f"High open alerts: {high_open}",
    ]
    for a in recent[:10]:
        lines.append(
            f"- [{a.severity.value if a.severity else ''}] {a.title} | src={a.source} | risk={a.risk_score if a.risk_score is not None else 'n/a'} | incident={a.incident_group_id or 'none'}"
        )

    system = (
        "You are a SOC shift lead assistant generating handover notes for the next analyst. "
        "Prioritize active risk and clearly state pending actions."
    )
    prompt = (
        "Create a concise handover with these sections:\n"
        "- Executive Summary\n"
        "- Top Active Incidents\n"
        "- High-Priority Pending Actions\n"
        "- Watchlist for Next Shift\n\n"
        "Data:\n"
        + "\n".join(lines)
    )

    handover = ""
    try:
        handover = (await run_ai_completion(system=system, prompt=prompt)).strip()
    except Exception:
        handover = ""

    if not handover:
        top = "\n".join(lines[3:8]) if len(lines) > 3 else "- No active high-priority alerts."
        handover = (
            "Executive Summary\n"
            f"- Open incidents: {open_incident_ids}\n"
            f"- Critical open alerts: {critical_open}\n"
            f"- High open alerts: {high_open}\n\n"
            "Top Active Incidents\n"
            f"{top}\n\n"
            "High-Priority Pending Actions\n"
            "- Validate containment status for all critical/high alerts\n"
            "- Confirm ownership for unassigned open alerts\n"
            "- Update timeline comments before shift end\n\n"
            "Watchlist for Next Shift\n"
            "- Repeated source IPs and recurring hostnames in open alerts\n"
            "- Any incident with rising risk score or new correlated alerts"
        )

    return ShiftHandoverResponse(
        generated_at=now.isoformat(),
        open_incidents=int(open_incident_ids),
        critical_open_alerts=int(critical_open),
        high_open_alerts=int(high_open),
        handover=handover,
    )
