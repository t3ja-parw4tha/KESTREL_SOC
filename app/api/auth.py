"""Authentication and session API routes."""

from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, Request, Response, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models import ApiKey, Session, User
from app.schemas.auth import (
    ApiKeyCreateRequest,
    ApiKeyResponse,
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    SessionResponse,
    CreateUserRequest,
    UpdateUserRequest,
)
from app.security.auth import (
    REFRESH_TOKEN_COOKIE,
    create_access_token,
    create_refresh_token,
    verify_token,
    blocklist_add,
    blocklist_check,
    hash_password,
    verify_password,
    validate_password_policy,
    check_lockout,
    record_failed_login,
    clear_failed_logins,
    get_progressive_delay,
    get_recent_failure_count,
    create_session,
    get_user_sessions,
    revoke_session_by_id,
    generate_api_key,
    hash_api_key,
)
from app.security.rbac import get_current_user, require_permission, get_role_permissions
from app.security.exceptions import SecurityError

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE_MAX_AGE = 7 * 24 * 3600  # 7 days


def _set_refresh_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE,
        value=token,
        max_age=REFRESH_COOKIE_MAX_AGE,
        httponly=True,
        secure=not get_settings().debug,
        samesite="lax",
        path="/",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=REFRESH_TOKEN_COOKIE, path="/")


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    response: Response,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user; set httpOnly refresh cookie; return access token."""
    import asyncio

    locked, locked_until = await check_lockout(db, body.username)
    if locked:
        raise HTTPException(
            status_code=423,
            detail=f"Account locked until {locked_until.isoformat() if locked_until else 'later'}",
        )
    fail_count = await get_recent_failure_count(db, body.username)
    if fail_count > 0:
        delay = get_progressive_delay(fail_count)
        await asyncio.sleep(delay)
    stmt = select(User).where(User.username == body.username, User.is_active.is_(True))
    r = await db.execute(stmt)
    user = r.scalar_one_or_none()
    if not user or not verify_password(body.password, user.password_hash):
        await record_failed_login(db, body.username, request.client.host if request.client else None)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    await clear_failed_logins(db, user.username)
    access_token, _ = create_access_token(user.id, user.role)
    refresh_token, refresh_jti = create_refresh_token(user.id, user.role)
    await create_session(
        db,
        user.id,
        refresh_jti,
        request.client.host if request.client else None,
        request.headers.get("user-agent"),
    )
    from app.config import get_settings
    settings = get_settings()
    expires_in = getattr(settings, "access_token_expire_minutes", 15) * 60
    _set_refresh_cookie(response, refresh_token)
    return LoginResponse(access_token=access_token, token_type="bearer", expires_in=expires_in)


@router.post("/setup")
async def first_time_setup(
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create first admin user. Only works if no users exist."""
    count_r = await db.execute(select(func.count()).select_from(User))
    count = count_r.scalar()
    if count and count > 0:
        raise HTTPException(
            status_code=403,
            detail="Setup already completed. Use admin account.",
        )
    from app.security.auth import hash_password, validate_password_policy

    validate_password_policy(body.password, body.username)
    user = User(
        username=body.username,
        email=f"{body.username}@kestrel.local",
        password_hash=hash_password(body.password),
        role="admin",
        is_active=True,
        updated_at=datetime.now(timezone.utc),
    )
    db.add(user)
    await db.commit()
    return {"created": True, "username": user.username}


@router.get("/setup-status")
async def setup_status(db: AsyncSession = Depends(get_db)):
    """Check if initial setup is complete."""
    count_r = await db.execute(select(func.count()).select_from(User))
    count = count_r.scalar() or 0
    return {"setup_complete": count > 0}

@router.post("/users", status_code=201)
async def create_user(
    body: CreateUserRequest,
    _admin: dict = Depends(require_permission("admin:write")),
    db: AsyncSession = Depends(get_db),
):
    """Admin only: create a new user with a specific role."""
    from app.security.auth import hash_password, validate_password_policy

    validate_password_policy(body.password, body.username)
    existing = await db.execute(select(User).where(User.username == body.username))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username already exists")
    user = User(
        username=body.username,
        email=body.email or f"{body.username}@kestrel.local",
        password_hash=hash_password(body.password),
        role=body.role,
        is_active=True,
        updated_at=datetime.now(timezone.utc),
    )
    db.add(user)
    await db.commit()
    return {"username": user.username, "role": user.role, "created": True}


@router.get("/users")
async def list_users(
    _admin: dict = Depends(require_permission("admin:write")),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(User).order_by(User.created_at.desc()))
    users = r.scalars().all()
    return {
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "is_active": u.is_active,
                "created_at": u.created_at.isoformat() if u.created_at else None,
            }
            for u in users
        ]
    }


@router.patch("/users/{user_id}")
async def update_user(
    user_id: int,
    body: UpdateUserRequest,
    _admin: dict = Depends(require_permission("admin:write")),
    db: AsyncSession = Depends(get_db),
):
    r = await db.execute(select(User).where(User.id == user_id))
    u = r.scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    if body.role is not None:
        u.role = body.role
    if body.is_active is not None:
        u.is_active = body.is_active
    u.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"updated": True}

@router.post("/refresh", response_model=LoginResponse)
async def refresh(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Validate refresh cookie; rotate tokens; set new httpOnly cookie."""
    token = request.cookies.get(REFRESH_TOKEN_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = verify_token(token)
    except SecurityError:
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")
    jti = payload.get("jti")
    if await blocklist_check(db, jti):
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="Token revoked")
    user_id = int(payload["sub"])
    role = payload.get("role", "analyst")
    # Revoke old refresh (rotation)
    await blocklist_add(db, jti, datetime.fromtimestamp(payload["exp"], tz=timezone.utc))
    # New tokens
    access_token, _ = create_access_token(user_id, role)
    refresh_token, refresh_jti = create_refresh_token(user_id, role)
    await create_session(
        db,
        user_id,
        refresh_jti,
        request.client.host if request.client else None,
        request.headers.get("user-agent"),
    )
    from app.config import get_settings
    settings = get_settings()
    expires_in = getattr(settings, "access_token_expire_minutes", 15) * 60
    _set_refresh_cookie(response, refresh_token)
    return LoginResponse(access_token=access_token, token_type="bearer", expires_in=expires_in)


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Blocklist access jti and refresh jti; clear cookie."""
    auth = request.headers.get("Authorization")
    if auth and auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1].strip()
        try:
            payload = verify_token(token)
            exp_ts = payload.get("exp")
            if exp_ts:
                await blocklist_add(db, payload["jti"], datetime.fromtimestamp(exp_ts, tz=timezone.utc))
        except SecurityError:
            pass
    refresh_token = request.cookies.get(REFRESH_TOKEN_COOKIE)
    if refresh_token:
        try:
            payload = verify_token(refresh_token)
            exp_ts = payload.get("exp")
            if exp_ts:
                await blocklist_add(db, payload["jti"], datetime.fromtimestamp(exp_ts, tz=timezone.utc))
        except SecurityError:
            pass
    _clear_refresh_cookie(response)
    return {"status": "ok"}


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Validate old password; enforce new password policy; update hash."""
    user_id = int(user["sub"])
    stmt = select(User).where(User.id == user_id)
    r = await db.execute(stmt)
    u = r.scalar_one_or_none()
    if not u or not verify_password(body.old_password, u.password_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    validate_password_policy(body.new_password, u.username)
    u.password_hash = hash_password(body.new_password)
    return {"status": "ok"}


@router.get("/sessions", response_model=list[SessionResponse])
async def list_sessions(
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """List active sessions for current user."""
    user_id = int(user["sub"])
    sessions = await get_user_sessions(db, user_id)
    return [
        SessionResponse(
            id=s.id,
            ip_address=s.ip_address,
            user_agent=s.user_agent,
            created_at=s.created_at.isoformat() if s.created_at else "",
            last_activity=s.last_activity.isoformat() if s.last_activity else None,
        )
        for s in sessions
    ]


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Revoke a specific session (blocklist its refresh token)."""
    user_id = int(user["sub"])
    stmt = select(Session).where(Session.id == session_id, Session.user_id == user_id)
    r = await db.execute(stmt)
    session = r.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    # Blocklist refresh token so it cannot be used again (exp far future)
    block_exp = datetime.now(timezone.utc) + timedelta(days=8)
    await blocklist_add(db, session.refresh_jti, block_exp)
    await db.delete(session)
    await db.flush()
    return {"status": "ok"}


@router.post("/api-keys", response_model=ApiKeyResponse)
async def create_api_key(
    body: ApiKeyCreateRequest,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_permission("users:manage")),
):
    """Generate new API key (admin only). Key returned once."""
    import json
    allowed = get_role_permissions(user.get("role", ""))
    for p in body.permissions:
        if p not in allowed:
            raise HTTPException(status_code=403, detail=f"Permission not allowed: {p}")
    plain_key, key_hash = generate_api_key(body.permissions)
    created_by = int(user["sub"])
    api_key = ApiKey(
        key_hash=key_hash,
        name=body.name,
        permissions=json.dumps(body.permissions),
        created_by_id=created_by,
    )
    db.add(api_key)
    await db.flush()
    return ApiKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key=plain_key,
        permissions=body.permissions,
        created_at=api_key.created_at.isoformat() if api_key.created_at else "",
    )
