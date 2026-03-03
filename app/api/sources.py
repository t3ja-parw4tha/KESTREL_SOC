"""Sources API router."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.security.rbac import require_permission

router = APIRouter(prefix="/sources", tags=["sources"])


@router.get("")
async def list_sources(
    _user: Annotated[dict, Depends(require_permission("sources:read"))],
):
    """List configured sources (stub)."""
    return {"items": []}
