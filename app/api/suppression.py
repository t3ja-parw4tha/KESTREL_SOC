"""Alert suppression rules API."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import AuditLog, SuppressionRule
from app.security.csrf import verify_csrf
from app.security.rbac import require_permission

router = APIRouter(prefix="/suppression", tags=["suppression"])

# ─── Schemas ──────────────────────────────────────────────────────────────────

class SuppressionCondition(BaseModel):
    field: str = Field(..., description="Alert field: severity, source, category, title, source_ip")
    operator: str = Field(..., description="equals | not_equals | contains | not_contains")
    value: str = Field(..., min_length=1, max_length=256)


class SuppressionRuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str | None = Field(None, max_length=512)
    conditions: list[SuppressionCondition] = Field(..., min_length=1)
    expires_hours: int | None = Field(None, ge=1, le=8760, description="Expire after N hours; None = permanent")


class SuppressionRuleResponse(BaseModel):
    id: int
    name: str
    description: str | None
    is_active: bool
    conditions: list[dict]
    expires_at: str | None
    created_by: str | None
    created_at: str
    hit_count: int
    last_hit_at: str | None

    @classmethod
    def from_orm(cls, r: SuppressionRule) -> "SuppressionRuleResponse":
        return cls(
            id=r.id,
            name=r.name,
            description=r.description,
            is_active=r.is_active,
            conditions=r.conditions if isinstance(r.conditions, list) else [],
            expires_at=r.expires_at.isoformat() if r.expires_at else None,
            created_by=r.created_by,
            created_at=r.created_at.isoformat() if r.created_at else "",
            hit_count=r.hit_count,
            last_hit_at=r.last_hit_at.isoformat() if r.last_hit_at else None,
        )


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("", response_model=list[SuppressionRuleResponse])
async def list_suppression_rules(
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
) -> list[SuppressionRuleResponse]:
    """List all suppression rules."""
    r = await db.execute(select(SuppressionRule).order_by(SuppressionRule.created_at.desc()))
    rules = r.scalars().all()
    return [SuppressionRuleResponse.from_orm(rule) for rule in rules]


@router.post("", response_model=SuppressionRuleResponse, status_code=201)
async def create_suppression_rule(
    body: SuppressionRuleCreate,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> SuppressionRuleResponse:
    """Create a new suppression rule (admin only)."""
    expires_at = None
    if body.expires_hours is not None:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=body.expires_hours)

    actor = user.get("username") or user.get("sub") or "unknown"
    rule = SuppressionRule(
        name=body.name,
        description=body.description,
        is_active=True,
        conditions=[c.model_dump() for c in body.conditions],
        expires_at=expires_at,
        created_by=actor,
    )
    db.add(rule)
    await db.flush()
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="suppression.rule_create",
        analyst=str(actor),
        ip_address=None,
        details={
            "rule_name": rule.name,
            "condition_count": len(body.conditions),
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    ))
    await db.commit()
    await db.refresh(rule)
    return SuppressionRuleResponse.from_orm(rule)


@router.patch("/{rule_id}/toggle", response_model=SuppressionRuleResponse)
async def toggle_suppression_rule(
    rule_id: int,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> SuppressionRuleResponse:
    """Enable or disable a suppression rule."""
    rule = await db.get(SuppressionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    previous_state = bool(rule.is_active)
    rule.is_active = not rule.is_active
    actor = user.get("username") or user.get("sub") or "unknown"
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="suppression.rule_toggle",
        analyst=str(actor),
        ip_address=None,
        details={"rule_id": rule_id, "rule_name": rule.name, "was_active": previous_state, "now_active": bool(rule.is_active)},
    ))
    await db.commit()
    await db.refresh(rule)
    return SuppressionRuleResponse.from_orm(rule)


@router.delete("/{rule_id}", status_code=204)
async def delete_suppression_rule(
    rule_id: int,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a suppression rule."""
    rule = await db.get(SuppressionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    actor = user.get("username") or user.get("sub") or "unknown"
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="suppression.rule_delete",
        analyst=str(actor),
        ip_address=None,
        details={"rule_id": rule_id, "rule_name": rule.name, "condition_count": len(rule.conditions) if isinstance(rule.conditions, list) else 0},
    ))
    await db.delete(rule)
    await db.commit()
