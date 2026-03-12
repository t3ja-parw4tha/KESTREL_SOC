"""Automation Playbooks API."""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Playbook
from app.schemas.playbook import PlaybookCreate, PlaybookUpdate, PlaybookResponse
from app.security.rbac import get_current_user, require_permission

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


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
    await db.commit()
    await db.refresh(playbook)
    return playbook


@router.patch("/{playbook_id}", response_model=PlaybookResponse)
async def update_playbook(
    playbook_id: int,
    body: PlaybookUpdate,
    _user: Annotated[dict, Depends(require_permission("admin:write"))],
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
    await db.commit()
    await db.refresh(playbook)
    return playbook


@router.delete("/{playbook_id}", status_code=204)
async def delete_playbook(
    playbook_id: int,
    _user: Annotated[dict, Depends(require_permission("admin:write"))],
    db: AsyncSession = Depends(get_db),
):
    """Delete a playbook (admin only)."""
    playbook = await db.get(Playbook, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    await db.delete(playbook)
    await db.commit()
