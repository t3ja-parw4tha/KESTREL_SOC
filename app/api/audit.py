"""Audit log API (admin only)."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.security.rbac import require_permission

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
async def list_audit_logs(
    _user: Annotated[dict, Depends(require_permission("audit:read"))],
):
    """List audit log entries (admin only)."""
    return {"items": [], "total": 0}
