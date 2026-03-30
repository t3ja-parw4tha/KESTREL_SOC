"""Automation Playbooks API."""

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import AuditLog, Playbook
from app.playbooks.library import PLAYBOOK_LIBRARY, get_playbook_template
from app.schemas.playbook import (
    InstallPlaybookLibraryRequest,
    InstallPlaybookLibraryResponse,
    PlaybookAction,
    PlaybookCondition,
    PlaybookCreate,
    PlaybookResponse,
    PlaybookTemplateResponse,
    PlaybookUpdate,
)
from app.security.csrf import verify_csrf
from app.security.rbac import get_current_user, require_permission


# ─── Dry-run schemas ──────────────────────────────────────────────────────────

class DryRunActionItem(BaseModel):
    action_type: str
    risk_level: str
    description: str
    would_execute: bool = True


class DryRunResponse(BaseModel):
    playbook_id: str
    playbook_name: str
    action_count: int
    high_risk_count: int
    actions: list[DryRunActionItem]
    requires_approval: bool  # True if any action is "high" risk


def _action_risk_level(action_type: str) -> str:
    """Map action types to risk levels."""
    high_risk = {"isolate_host", "disable_user", "quarantine"}
    medium_risk = {"block_ip"}
    low_risk = {"notify", "escalate"}
    if action_type in high_risk:
        return "high"
    if action_type in medium_risk:
        return "medium"
    if action_type in low_risk:
        return "low"
    return "medium"

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


def _actor_name(user: dict | None) -> str | None:
    if not user:
        return None
    return str(user.get("username") or user.get("sub") or "") or None


def _add_playbook_audit(
    db: AsyncSession,
    *,
    action: str,
    actor: str | None,
    playbook_id: int | None,
    details: dict,
) -> None:
    db.add(
        AuditLog(
            id=str(uuid.uuid4()),
            action=action,
            alert_id=str(playbook_id) if playbook_id is not None else None,
            analyst=actor,
            details=details,
        )
    )


@router.get("/library", response_model=list[PlaybookTemplateResponse])
async def list_playbook_library(
    _user: Annotated[dict, Depends(get_current_user)],
) -> list[PlaybookTemplateResponse]:
    """List built-in playbook templates for rapid SOC onboarding."""
    return [
        PlaybookTemplateResponse(
            key=t.key,
            name=t.name,
            description=t.description,
            trigger_type=t.trigger_type,
            conditions=[PlaybookCondition.model_validate(c) for c in t.conditions],
            actions=[PlaybookAction.model_validate(a) for a in t.actions],
        )
        for t in PLAYBOOK_LIBRARY
    ]


@router.post("/library/install", response_model=InstallPlaybookLibraryResponse)
async def install_playbook_library(
    body: InstallPlaybookLibraryRequest,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> InstallPlaybookLibraryResponse:
    """Install selected built-in templates as active/inactive playbooks."""
    installed: list[str] = []
    skipped: list[str] = []

    for key in body.template_keys:
        template = get_playbook_template(key)
        if template is None:
            skipped.append(key)
            continue

        existing = (
            await db.execute(select(Playbook).where(Playbook.name == template.name))
        ).scalar_one_or_none()
        if existing and not body.overwrite_existing:
            skipped.append(template.key)
            continue

        if existing and body.overwrite_existing:
            existing.description = template.description
            existing.trigger_type = template.trigger_type
            existing.conditions = template.conditions
            existing.actions = template.actions
            existing.is_active = body.activate
            existing.updated_at = datetime.now(timezone.utc)
            installed.append(template.key)
            continue

        playbook = Playbook(
            name=template.name,
            description=template.description,
            is_active=body.activate,
            trigger_type=template.trigger_type,
            conditions=template.conditions,
            actions=template.actions,
            created_by_id=int(user["sub"]),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(playbook)
        installed.append(template.key)

    _add_playbook_audit(
        db,
        action="playbook.library_install",
        actor=_actor_name(user),
        playbook_id=None,
        details={
            "requested": len(body.template_keys),
            "installed": len(installed),
            "skipped": len(skipped),
            "activate": body.activate,
            "overwrite_existing": body.overwrite_existing,
        },
    )
    await db.commit()
    return InstallPlaybookLibraryResponse(installed=installed, skipped=skipped)


@router.get("", response_model=list[PlaybookResponse])
async def list_playbooks(
    _user: Annotated[dict, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """List all playbooks (read-only for all authenticated users)."""
    stmt = select(Playbook).order_by(Playbook.name.asc())
    r = await db.execute(stmt)
    playbooks = r.scalars().all()
    return playbooks


@router.get("/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(
    playbook_id: int,
    _user: Annotated[dict, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Get a specific playbook by ID."""
    playbook = await db.get(Playbook, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook


@router.post("", response_model=PlaybookResponse, status_code=201)
async def create_playbook(
    body: PlaybookCreate,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    """Create a new automation playbook (admin only)."""
    # Check for duplicate name
    existing = await db.execute(select(Playbook).where(Playbook.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Playbook with this name already exists")

    # The jsonable_encoder is typically used, but SQLAlchemy JSON can take list of dicts directly
    conditions_data = [c.model_dump() for c in body.conditions]
    actions_data = [a.model_dump() for a in body.actions]

    playbook = Playbook(
        name=body.name,
        description=body.description,
        is_active=body.is_active,
        trigger_type=body.trigger_type,
        conditions=conditions_data,
        actions=actions_data,
        created_by_id=int(user["sub"]),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(playbook)
    await db.flush()
    _add_playbook_audit(
        db,
        action="playbook.create",
        actor=_actor_name(user),
        playbook_id=playbook.id,
        details={
            "name": playbook.name,
            "trigger_type": playbook.trigger_type,
            "is_active": playbook.is_active,
            "action_count": len(actions_data),
        },
    )
    await db.commit()
    await db.refresh(playbook)
    return playbook


@router.patch("/{playbook_id}", response_model=PlaybookResponse)
async def update_playbook(
    playbook_id: int,
    body: PlaybookUpdate,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    """Update an existing playbook (admin only)."""
    playbook = await db.get(Playbook, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if body.name is not None:
        # Check duplicate
        existing = await db.execute(select(Playbook).where(Playbook.name == body.name, Playbook.id != playbook_id))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Playbook with this name already exists")
        playbook.name = body.name

    if body.description is not None:
        playbook.description = body.description
    if body.is_active is not None:
        playbook.is_active = body.is_active
    if body.trigger_type is not None:
        playbook.trigger_type = body.trigger_type
    if body.conditions is not None:
        playbook.conditions = [c.model_dump() for c in body.conditions]
    if body.actions is not None:
        playbook.actions = [a.model_dump() for a in body.actions]

    playbook.updated_at = datetime.now(timezone.utc)
    _add_playbook_audit(
        db,
        action="playbook.update",
        actor=_actor_name(user),
        playbook_id=playbook.id,
        details={
            "name": playbook.name,
            "is_active": playbook.is_active,
            "trigger_type": playbook.trigger_type,
            "updated_fields": sorted(list(body.model_fields_set)),
        },
    )
    await db.commit()
    await db.refresh(playbook)
    return playbook


@router.post("/{playbook_id}/dry-run", response_model=DryRunResponse)
async def dry_run_playbook(
    playbook_id: int,
    _user: Annotated[dict, Depends(require_permission("playbooks:run"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> DryRunResponse:
    """Simulate playbook execution without running actions.

    Returns a list of actions with their risk levels and descriptions.
    """
    playbook = await db.get(Playbook, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    raw_actions = playbook.actions
    if isinstance(raw_actions, list):
        actions_data: list[dict] = [a for a in raw_actions if isinstance(a, dict)]
    else:
        actions_data = []
    items: list[DryRunActionItem] = []
    for action in actions_data:
        action_type = str(action.get("type", "unknown"))
        risk = _action_risk_level(action_type)
        value = action.get("value", "")
        description = f"{action_type}: {value}" if value else action_type
        items.append(
            DryRunActionItem(
                action_type=action_type,
                risk_level=risk,
                description=description,
                would_execute=True,
            )
        )

    high_risk_count = sum(1 for item in items if item.risk_level == "high")

    return DryRunResponse(
        playbook_id=str(playbook_id),
        playbook_name=playbook.name,
        action_count=len(items),
        high_risk_count=high_risk_count,
        actions=items,
        requires_approval=high_risk_count > 0,
    )


@router.delete("/{playbook_id}", status_code=204)
async def delete_playbook(
    playbook_id: int,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    """Delete a playbook (admin only)."""
    playbook = await db.get(Playbook, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    _add_playbook_audit(
        db,
        action="playbook.delete",
        actor=_actor_name(user),
        playbook_id=playbook.id,
        details={"name": playbook.name},
    )
    await db.delete(playbook)
    await db.commit()
