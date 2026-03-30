"""Custom dashboard APIs (P4-5)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import DashboardLayout
from app.security.csrf import verify_csrf
from app.security.rbac import require_permission

router = APIRouter(prefix="/custom-dashboards", tags=["custom-dashboards"])


class DashboardLayoutCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=512)
    widgets: list[dict[str, Any]] = Field(default_factory=list)
    is_default: bool = False


class DashboardLayoutUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=512)
    widgets: list[dict[str, Any]] | None = None
    is_default: bool | None = None


@router.get("")
async def list_dashboards(
    user: Annotated[dict, Depends(require_permission("dashboard:read"))],
    db: AsyncSession = Depends(get_db),
):
    owner = str(user.get("sub"))
    rows = (
        await db.execute(
            select(DashboardLayout)
            .where(DashboardLayout.owner == owner)
            .order_by(DashboardLayout.is_default.desc(), DashboardLayout.updated_at.desc())
        )
    ).scalars().all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "widgets": r.widgets,
            "is_default": r.is_default,
            "owner": r.owner,
        }
        for r in rows
    ]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_dashboard(
    body: DashboardLayoutCreate,
    user: Annotated[dict, Depends(require_permission("dashboard:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    owner = str(user.get("sub"))
    if body.is_default:
        # Keep a single default dashboard per user.
        defaults = (await db.execute(select(DashboardLayout).where(DashboardLayout.owner == owner, DashboardLayout.is_default.is_(True)))).scalars().all()
        for d in defaults:
            d.is_default = False

    row = DashboardLayout(
        owner=owner,
        name=body.name,
        description=body.description,
        widgets=body.widgets,
        is_default=body.is_default,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "widgets": row.widgets,
        "is_default": row.is_default,
        "owner": row.owner,
    }


@router.patch("/{layout_id}")
async def update_dashboard(
    layout_id: int,
    body: DashboardLayoutUpdate,
    user: Annotated[dict, Depends(require_permission("dashboard:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    owner = str(user.get("sub"))
    row = (await db.execute(select(DashboardLayout).where(DashboardLayout.id == layout_id, DashboardLayout.owner == owner))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Dashboard not found")

    patch = body.model_dump(exclude_unset=True)
    if patch.get("is_default") is True:
        defaults = (await db.execute(select(DashboardLayout).where(DashboardLayout.owner == owner, DashboardLayout.is_default.is_(True)))).scalars().all()
        for d in defaults:
            d.is_default = False

    for key, value in patch.items():
        setattr(row, key, value)

    await db.commit()
    await db.refresh(row)
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "widgets": row.widgets,
        "is_default": row.is_default,
        "owner": row.owner,
    }


@router.delete("/{layout_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_dashboard(
    layout_id: int,
    user: Annotated[dict, Depends(require_permission("dashboard:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    owner = str(user.get("sub"))
    row = (await db.execute(select(DashboardLayout).where(DashboardLayout.id == layout_id, DashboardLayout.owner == owner))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    await db.delete(row)
    await db.commit()
