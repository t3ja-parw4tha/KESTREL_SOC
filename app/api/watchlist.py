"""Threat intel IOC watchlist API endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import AuditLog, IOCWatchlistEntry
from app.security.csrf import verify_csrf
from app.security.rbac import require_permission
from app.services.watchlist import infer_indicator_type, normalize_indicator

router = APIRouter(prefix="/watchlist", tags=["watchlist"])


class WatchlistItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    indicator: str
    indicator_type: str
    confidence: int
    notes: str | None
    is_active: bool
    match_count: int
    last_matched_at: str | None
    created_by: str | None
    created_at: str | None
    updated_at: str | None


class WatchlistCreateRequest(BaseModel):
    indicator: str = Field(min_length=2, max_length=256)
    indicator_type: str | None = Field(default=None, pattern="^(ip|domain|hash)$")
    confidence: int = Field(default=70, ge=0, le=100)
    notes: str | None = Field(default=None, max_length=1024)


class WatchlistUpdateRequest(BaseModel):
    confidence: int | None = Field(default=None, ge=0, le=100)
    notes: str | None = Field(default=None, max_length=1024)
    is_active: bool | None = None


def _to_item(row: IOCWatchlistEntry) -> WatchlistItem:
    return WatchlistItem(
        id=row.id,
        indicator=row.indicator,
        indicator_type=row.indicator_type,
        confidence=row.confidence,
        notes=row.notes,
        is_active=row.is_active,
        match_count=row.match_count,
        last_matched_at=row.last_matched_at.isoformat() if row.last_matched_at else None,
        created_by=row.created_by,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


@router.get("", response_model=list[WatchlistItem])
async def list_watchlist(
    _user: Annotated[dict, Depends(require_permission("watchlist:read"))],
    db: AsyncSession = Depends(get_db),
    active_only: bool = Query(False),
) -> list[WatchlistItem]:
    stmt = select(IOCWatchlistEntry).order_by(IOCWatchlistEntry.created_at.desc())
    if active_only:
        stmt = stmt.where(IOCWatchlistEntry.is_active.is_(True))

    rows = (await db.execute(stmt)).scalars().all()
    return [_to_item(r) for r in rows]


@router.post("", response_model=WatchlistItem, status_code=201)
async def create_watchlist_item(
    body: WatchlistCreateRequest,
    user: Annotated[dict, Depends(require_permission("watchlist:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> WatchlistItem:
    inferred = body.indicator_type or infer_indicator_type(body.indicator)
    if inferred is None:
        raise HTTPException(status_code=400, detail="Could not infer indicator type; provide indicator_type")

    normalized = normalize_indicator(body.indicator, inferred)
    existing = (
        await db.execute(select(IOCWatchlistEntry).where(IOCWatchlistEntry.indicator == normalized))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Indicator already exists in watchlist")

    actor = str(user.get("sub")) if user.get("sub") else None
    row = IOCWatchlistEntry(
        indicator=normalized,
        indicator_type=inferred,
        confidence=body.confidence,
        notes=body.notes,
        is_active=True,
        created_by=actor,
    )
    db.add(row)
    await db.flush()
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="watchlist.ioc_add",
        analyst=actor,
        ip_address=None,
        details={"indicator": normalized, "indicator_type": inferred, "confidence": body.confidence},
    ))
    await db.commit()
    await db.refresh(row)
    return _to_item(row)


@router.patch("/{watchlist_id}", response_model=WatchlistItem)
async def update_watchlist_item(
    watchlist_id: int,
    body: WatchlistUpdateRequest,
    _user: Annotated[dict, Depends(require_permission("watchlist:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> WatchlistItem:
    row = await db.get(IOCWatchlistEntry, watchlist_id)
    if not row:
        raise HTTPException(status_code=404, detail="Watchlist item not found")

    payload = body.model_dump(exclude_unset=True)
    for key, value in payload.items():
        setattr(row, key, value)

    await db.commit()
    await db.refresh(row)
    return _to_item(row)


@router.delete("/{watchlist_id}", status_code=204)
async def delete_watchlist_item(
    watchlist_id: int,
    user: Annotated[dict, Depends(require_permission("watchlist:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> None:
    row = await db.get(IOCWatchlistEntry, watchlist_id)
    if not row:
        raise HTTPException(status_code=404, detail="Watchlist item not found")
    actor = str(user.get("sub")) if user.get("sub") else None
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="watchlist.ioc_remove",
        analyst=actor,
        ip_address=None,
        details={"watchlist_id": watchlist_id, "indicator": row.indicator, "indicator_type": row.indicator_type},
    ))
    await db.delete(row)
    await db.commit()
