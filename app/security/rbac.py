"""
Role-based access control: permissions and require_permission dependency.

Apply require_permission(permission) to protected routes; logs to audit table.
"""

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
import uuid
from app.models import AuditLog
from app.security.auth import verify_token, blocklist_check
from app.security.exceptions import SecurityError

# Current role permissions map (for audit/documentation).
# Authoritative source: PERMISSIONS dict below.
# Key additions in P6 hardening:
#   - incidents:write added to analyst/senior_analyst/admin (create incidents from triage)
#   - playbooks:run covers both execute and dry-run (simulation) operations
#   - users:manage required for /auth/users/{id}/activity (admin-only audit view)

# Role hierarchy: each role has its own permissions (senior includes analyst conceptually in UI).
PERMISSIONS: dict[str, list[str]] = {
    "viewer": [
        # Read-only across the platform — no writes, no AI, no ingest.
        "dashboard:read",
        "alerts:read",
        "assets:read",
        "incidents:read",
        "mitre:read",
        "watchlist:read",
        "cases:read",
    ],
    "analyst": [
        "alerts:read",
        "assets:read",
        "assets:write",
        "evidence:write",
        "alerts:write",
        "alerts:update_status",
        "alerts:bulk_update",  # Bulk status/self-assign only
        "alerts:comment",
        "alerts:pick_up",   # Assign to self only (pick up unassigned alerts)
        "incidents:read",
        "incidents:write",  # Create and update incidents from triage
        "ingest:write",
        "mitre:read",
        "ai:generate",
        "dashboard:read",
        "dashboard:write",  # Custom layouts + scheduled reports (own team dashboards)
        "watchlist:read",
        "watchlist:write",
        "cases:read",
        "cases:write",
    ],
    "senior_analyst": [
        "alerts:read",
        "assets:read",
        "assets:write",
        "evidence:write",
        "alerts:write",
        "alerts:update_status",
        "alerts:bulk_update",
        "alerts:comment",
        "alerts:pick_up",   # Can also pick up
        "alerts:assign",    # Can assign to others / reassign
        "incidents:read",
        "incidents:write",
        "mitre:read",
        "ai:generate",
        "dashboard:read",
        "dashboard:write",  # Create/manage scheduled reports and custom dashboards
        "decisions:read",
        "decisions:run",
        "playbooks:run",    # Run and dry-run playbooks
        "sources:read",
        "watchlist:read",
        "watchlist:write",
        "cases:read",
        "cases:write",
    ],
    "admin": [
        "alerts:read",
        "assets:read",
        "assets:write",
        "evidence:write",
        "alerts:write",
        "alerts:update_status",
        "alerts:bulk_update",
        "alerts:comment",
        "alerts:pick_up",
        "alerts:assign",
        "alerts:delete",
        "incidents:read",
        "incidents:write",
        "ingest:write",
        "mitre:read",
        "ai:generate",
        "dashboard:read",
        "dashboard:write",  # Create/manage scheduled reports and custom dashboards
        "decisions:read",
        "decisions:run",
        "playbooks:run",    # Run and dry-run playbooks
        "sources:read",
        "sources:manage",
        "users:manage",
        "admin:write",
        "audit:read",
        "system:config",
        "watchlist:read",
        "watchlist:write",
        "cases:read",
        "cases:write",
    ],
}


def get_role_permissions(role: str) -> set[str]:
    """Return set of permission strings for role."""
    return set(PERMISSIONS.get(role, []))


async def get_current_user_optional(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict | None:
    """
    Optional auth: return token payload if valid Bearer present, else None.
    Does not blocklist-check (use get_current_user for protected routes).
    """
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        payload = verify_token(token)
    except SecurityError:
        return None
    if payload.get("type") != "access":
        return None
    blocked = await blocklist_check(db, payload.get("jti", ""))
    if blocked:
        return None
    return payload


async def get_current_user(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """
    Require valid access token. Returns 401 if missing/invalid/blocklisted.
    """
    payload = await get_current_user_optional(request, db)
    if payload is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Not authenticated")
    return payload


def require_permission(permission: str):
    """
    FastAPI dependency factory: require the given permission. Injects current user dict.

    Usage:
        @router.get("/alerts")
        async def list_alerts(user: Annotated[dict, Depends(require_permission("alerts:read"))]):
    """
    from fastapi import HTTPException

    async def _dep(
        request: Request,
        db: Annotated[AsyncSession, Depends(get_db)],
        user: Annotated[dict, Depends(get_current_user)],
    ):
        role = user.get("role") or "analyst"
        allowed = get_role_permissions(role)
        if permission not in allowed:
            audit = AuditLog(
                id=str(uuid.uuid4()),
                action="access_denied",
                analyst=str(user["sub"]) if user.get("sub") else None,
                ip_address=request.client.host if request.client else None,
                details={"resource": request.url.path, "permission": permission, "role": role},
            )
            db.add(audit)
            await db.flush()
            raise HTTPException(status_code=403, detail="Insufficient permission")
        audit = AuditLog(
            id=str(uuid.uuid4()),
            action="access",
            analyst=str(user["sub"]) if user.get("sub") else None,
            ip_address=request.client.host if request.client else None,
            details={"resource": request.url.path, "permission": permission},
        )
        db.add(audit)
        await db.flush()
        return user

    return _dep
