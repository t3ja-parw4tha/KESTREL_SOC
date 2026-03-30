"""Enterprise SSO routes (OIDC for Okta/Entra ID)."""

import httpx
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request, Response, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import jwt as pyjwt

from app.database import get_db
from app.models import Alert, AuditLog, SSOGroupRoleMapping, SSOProvider, User
from app.models.alert import AlertSeverity, AlertStatus
from app.security.auth import (
    create_access_token,
    create_refresh_token,
    create_session,
    REFRESH_TOKEN_COOKIE,
    hash_password,
)
from app.config import get_settings
from app.security.rbac import require_permission
from app.services.ldap_sync import fetch_ldap_users

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth/sso", tags=["sso"])

REFRESH_COOKIE_MAX_AGE = 7 * 24 * 3600
_ROLE_RANK = {"viewer": 1, "analyst": 2, "senior_analyst": 3, "admin": 4}


class GroupRoleMappingCreate(BaseModel):
    group_name: str = Field(..., min_length=1, max_length=255)
    role: Literal["viewer", "analyst", "senior_analyst", "admin"]
    is_active: bool = True


class GroupRoleMappingUpdate(BaseModel):
    group_name: str | None = Field(default=None, min_length=1, max_length=255)
    role: Literal["viewer", "analyst", "senior_analyst", "admin"] | None = None
    is_active: bool | None = None


class GroupRoleMappingResponse(BaseModel):
    id: int
    provider_id: int
    group_name: str
    role: str
    is_active: bool
    created_at: datetime | None
    updated_at: datetime | None

def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE,
        value=token,
        max_age=REFRESH_COOKIE_MAX_AGE,
        httponly=True,
        secure=not get_settings().debug,
        samesite="lax",
        path="/",
    )


def _extract_idp_groups(payload: dict[str, Any]) -> list[str]:
    raw_groups = payload.get("groups")
    if isinstance(raw_groups, list):
        return [str(g).strip() for g in raw_groups if str(g).strip()]
    if isinstance(raw_groups, str) and raw_groups.strip():
        return [raw_groups.strip()]
    return []


async def _resolve_role_from_groups(
    db: AsyncSession,
    provider_id: int,
    idp_groups: list[str],
) -> str | None:
    """Return highest-mapped role from IdP groups, or None if no mapping exists."""
    if not idp_groups:
        return None

    normalized_groups = {g.lower() for g in idp_groups}
    mappings = (
        await db.execute(
            select(SSOGroupRoleMapping).where(
                SSOGroupRoleMapping.provider_id == provider_id,
                SSOGroupRoleMapping.is_active.is_(True),
            )
        )
    ).scalars().all()

    matched_roles: list[str] = []
    for mapping in mappings:
        if mapping.group_name.lower() in normalized_groups:
            matched_roles.append(mapping.role)

    if not matched_roles:
        return None

    return max(matched_roles, key=lambda role: _ROLE_RANK.get(role, 0))


async def _emit_sso_drift_alert(
    db: AsyncSession,
    provider: SSOProvider,
    email: str,
    reason: str,
    idp_groups: list[str],
    mapped_role: str | None,
    existing_role: str | None,
) -> None:
    """Create auditable drift records when SSO governance detects mismatches."""
    details = {
        "provider_id": provider.id,
        "provider_domain": provider.domain,
        "email": email,
        "reason": reason,
        "idp_groups": idp_groups,
        "mapped_role": mapped_role,
        "existing_role": existing_role,
    }
    db.add(
        AuditLog(
            id=str(uuid.uuid4()),
            action="sso_group_sync_drift",
            analyst="system",
            details=details,
        )
    )

    severity = AlertSeverity.HIGH if reason == "unmapped_group_default_deny" else AlertSeverity.MEDIUM
    title = (
        f"SSO governance denied unmapped group login for {email}"
        if reason == "unmapped_group_default_deny"
        else f"SSO role drift corrected for {email}: {existing_role} -> {mapped_role}"
    )
    db.add(
        Alert(
            id=str(uuid.uuid4()),
            title=title[:512],
            source="sso-governance",
            severity=severity,
            category="identity",
            status=AlertStatus.OPEN,
            user_id=email,
            enrichment=details,
            raw={"event": "sso_governance_drift", **details},
        )
    )

async def _get_oidc_config(issuer_url: str) -> dict:
    """Fetch OpenID configuration for the provider."""
    # Ensure no training slash 
    base = issuer_url.rstrip("/")
    if not base.endswith("/.well-known/openid-configuration"):
        url = f"{base}/.well-known/openid-configuration"
    else:
        url = base

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=10.0)
        resp.raise_for_status()
        return resp.json()

@router.get("/login")
async def sso_login(
    request: Request,
    email: str,
    db: AsyncSession = Depends(get_db),
):
    """Initiate OIDC login flow based on email domain."""
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email address")
    
    domain = email.split("@")[1].lower()
    stmt = select(SSOProvider).where(SSOProvider.domain == domain, SSOProvider.is_active.is_(True))
    r = await db.execute(stmt)
    provider = r.scalar_one_or_none()
    
    if not provider:
        raise HTTPException(status_code=404, detail=f"SSO not configured for domain {domain}")

    try:
        oidc_config = await _get_oidc_config(provider.issuer_url)
    except Exception as e:
        logger.error("Failed to fetch OIDC config for %s: %s", domain, e)
        raise HTTPException(status_code=502, detail="Failed to contact identity provider")

    auth_endpoint = oidc_config.get("authorization_endpoint")
    if not auth_endpoint:
        raise HTTPException(status_code=500, detail="Invalid OIDC configuration from provider")

    import secrets
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    # Store in session middleware (added in main.py)
    request.session["sso_state"] = state
    request.session["sso_nonce"] = nonce
    request.session["sso_provider_id"] = provider.id

    # Build callback URL from request host
    base_url = f"{request.url.scheme}://{request.url.netloc}"
    # But usually frontend initiates. We can use a relative or absolute URL. 
    # The actual callback is to parsing it on backend. Let's use backend origin.
    redirect_uri = f"{base_url}/api/v1/auth/sso/callback"

    params = {
        "response_type": "code",
        "client_id": provider.client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "login_hint": email,
    }

    url = f"{auth_endpoint}?{urlencode(params)}"
    return RedirectResponse(url)


@router.get("/callback")
async def sso_callback(
    request: Request,
    state: str | None = None,
    code: str | None = None,
    error: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Handle OIDC callback from IdP, exchange code, verify JWT, issue our tokens."""
    if error:
        logger.warning("SSO error returned from IdP: %s", error)
        return RedirectResponse("/?error=sso_failed")

    if not code or not state:
        return RedirectResponse("/?error=missing_params")

    session_state = request.session.pop("sso_state", None)
    nonce = request.session.pop("sso_nonce", None)
    provider_id = request.session.pop("sso_provider_id", None)

    if not session_state or state != session_state:
        logger.warning("SSO state mismatch or missing session")
        return RedirectResponse("/?error=invalid_state")

    stmt = select(SSOProvider).where(SSOProvider.id == provider_id, SSOProvider.is_active.is_(True))
    r = await db.execute(stmt)
    provider = r.scalar_one_or_none()
    
    if not provider:
        return RedirectResponse("/?error=provider_not_found")

    try:
        oidc_config = await _get_oidc_config(provider.issuer_url)
    except Exception as e:
        logger.error("Failed to fetch OIDC config during callback: %s", e)
        return RedirectResponse("/?error=idp_unreachable")

    token_endpoint = oidc_config.get("token_endpoint")
    jwks_uri = oidc_config.get("jwks_uri")
    
    if not token_endpoint or not jwks_uri:
        return RedirectResponse("/?error=invalid_idp_config")

    base_url = f"{request.url.scheme}://{request.url.netloc}"
    redirect_uri = f"{base_url}/api/v1/auth/sso/callback"

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": provider.client_id,
                "client_secret": provider.client_secret,
            },
        )
        if token_resp.status_code != 200:
            logger.error("Token exchange failed: %s", token_resp.text)
            return RedirectResponse("/?error=token_exchange_failed")
            
        token_data = token_resp.json()
        id_token = token_data.get("id_token")

        if not id_token:
            return RedirectResponse("/?error=no_id_token")

        # Fetch JWKS to verify signature (PyJWT handles it nicely with PyJWKClient)
        jwks_client = pyjwt.PyJWKClient(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)

        try:
            payload = pyjwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                audience=provider.client_id,
                issuer=oidc_config.get("issuer", provider.issuer_url),
            )
        except pyjwt.InvalidTokenError as e:
            logger.error("ID Token verification failed: %s", e)
            return RedirectResponse("/?error=invalid_id_token")

    # Validate nonce
    if payload.get("nonce") != nonce:
        logger.warning("SSO nonce mismatch")
        return RedirectResponse("/?error=invalid_nonce")

    # The user authenticated successfully with their IdP.
    sso_sub = payload.get("sub")
    email = payload.get("email") or payload.get("upn") or payload.get("preferred_username")

    if not sso_sub or not email:
        return RedirectResponse("/?error=missing_claims")

    email = email.lower()
    idp_groups = _extract_idp_groups(payload)

    mapped_role = await _resolve_role_from_groups(db, provider.id, idp_groups)
    if mapped_role is None:
        await _emit_sso_drift_alert(
            db=db,
            provider=provider,
            email=email,
            reason="unmapped_group_default_deny",
            idp_groups=idp_groups,
            mapped_role=None,
            existing_role=None,
        )
        await db.commit()
        return RedirectResponse("/?error=access_denied")

    # Look for existing user
    user_stmt = select(User).where((User.sso_id == sso_sub) | (User.email == email))
    user_result = await db.execute(user_stmt)
    db_user = user_result.scalars().first()

    if db_user:
        if not db_user.is_active:
            return RedirectResponse("/?error=account_disabled")
        # Update sso_id if they previously logged in with password but now use SSO
        if db_user.sso_id != sso_sub:
            db_user.sso_id = sso_sub
        if db_user.role != mapped_role:
            previous_role = db_user.role
            db_user.role = mapped_role
            await _emit_sso_drift_alert(
                db=db,
                provider=provider,
                email=email,
                reason="role_mapping_drift_corrected",
                idp_groups=idp_groups,
                mapped_role=mapped_role,
                existing_role=previous_role,
            )
        await db.commit()
    else:
        # Auto-provision new user
        # Generate random username based on email
        base_username = email.split("@")[0]
        # Ensure unique
        existing = await db.execute(select(User).where(User.username.like(f"{base_username}%")))
        if existing.first():
            import uuid
            username = f"{base_username}_{uuid.uuid4().hex[:4]}"
        else:
            username = base_username

        db_user = User(
            username=username,
            email=email,
            # Keep local password auth effectively disabled but satisfy strict DB schemas.
            password_hash=hash_password(f"sso-only-{sso_sub}"),
            role=mapped_role,
            is_active=True,
            sso_id=sso_sub,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(db_user)
        await db.commit()

    # Issue KESTREL local tokens
    access_token, _ = create_access_token(db_user.id, db_user.role)
    refresh_token, refresh_jti = create_refresh_token(db_user.id, db_user.role)
    
    await create_session(
        db,
        db_user.id,
        refresh_jti,
        request.client.host if request.client else None,
        request.headers.get("user-agent"),
    )

    response = RedirectResponse("/?sso_success=true")
    # We can't easily pass the access token in URL fragment cleanly from backend redirect, 
    # but we can set it as a temporary cookie that JS reads and deletes, OR we can rely solely 
    # on the refresh token which is HttpOnly. 
    # KESTREL's frontend expects the access token to be returned in JSON from `/login`.
    # A common SPA pattern: set short-lived cookie with access token, frontend reads it, drops it.
    response.set_cookie(
        key="sso_access_token",
        value=access_token,
        max_age=60,
        httponly=False, # Must be readable by JS
        samesite="lax",
        path="/"
    )
    _set_refresh_cookie(response, refresh_token)
    
    return response


@router.get("/providers")
async def list_sso_providers(
    _admin: dict = Depends(require_permission("admin:write")),
    db: AsyncSession = Depends(get_db),
):
    """List all configured SSO providers (admin only)."""
    rows = (await db.execute(select(SSOProvider).order_by(SSOProvider.id.asc()))).scalars().all()
    return [
        {
            "id": r.id,
            "provider_type": r.name,
            "domain": r.domain,
            "client_id": r.client_id,
            "is_active": r.is_active,
        }
        for r in rows
    ]


@router.post("/ldap/sync")
async def ldap_sync(
    _admin: dict = Depends(require_permission("admin:write")),
    db: AsyncSession = Depends(get_db),
):
    """Sync users from LDAP into local user table (role defaults to analyst)."""
    ldap_users = fetch_ldap_users()

    created = 0
    updated = 0
    skipped = 0
    for entry in ldap_users:
        username = (entry.get("username") or "").strip().lower()
        email = (entry.get("email") or "").strip().lower()
        if not username or not email:
            skipped += 1
            continue

        existing_stmt = select(User).where((User.username == username) | (User.email == email))
        existing = (await db.execute(existing_stmt)).scalars().first()
        if existing:
            changed = False
            if existing.email != email:
                existing.email = email
                changed = True
            if existing.username != username:
                existing.username = username
                changed = True
            if changed:
                existing.updated_at = datetime.now(timezone.utc)
                updated += 1
            else:
                skipped += 1
            continue

        user = User(
            username=username,
            email=email,
            password_hash=hash_password(f"ldap-only-{username}"),
            role="analyst",
            is_active=True,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(user)
        created += 1

    await db.commit()
    return {
        "fetched": len(ldap_users),
        "created": created,
        "updated": updated,
        "skipped": skipped,
    }


@router.get("/providers/{provider_id}/group-mappings", response_model=list[GroupRoleMappingResponse])
async def list_group_role_mappings(
    provider_id: int,
    _admin: dict = Depends(require_permission("admin:write")),
    db: AsyncSession = Depends(get_db),
):
    provider = (await db.execute(select(SSOProvider).where(SSOProvider.id == provider_id))).scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail="SSO provider not found")

    rows = (
        await db.execute(
            select(SSOGroupRoleMapping)
            .where(SSOGroupRoleMapping.provider_id == provider_id)
            .order_by(SSOGroupRoleMapping.group_name.asc())
        )
    ).scalars().all()
    return [
        GroupRoleMappingResponse(
            id=r.id,
            provider_id=r.provider_id,
            group_name=r.group_name,
            role=r.role,
            is_active=r.is_active,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in rows
    ]


@router.post("/providers/{provider_id}/group-mappings", response_model=GroupRoleMappingResponse, status_code=201)
async def create_group_role_mapping(
    provider_id: int,
    body: GroupRoleMappingCreate,
    _admin: dict = Depends(require_permission("admin:write")),
    db: AsyncSession = Depends(get_db),
):
    provider = (await db.execute(select(SSOProvider).where(SSOProvider.id == provider_id))).scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail="SSO provider not found")

    normalized_group = body.group_name.strip()
    existing = (
        await db.execute(
            select(SSOGroupRoleMapping).where(
                SSOGroupRoleMapping.provider_id == provider_id,
                SSOGroupRoleMapping.group_name == normalized_group,
            )
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Group mapping already exists for provider")

    row = SSOGroupRoleMapping(
        provider_id=provider_id,
        group_name=normalized_group,
        role=body.role,
        is_active=body.is_active,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return GroupRoleMappingResponse(
        id=row.id,
        provider_id=row.provider_id,
        group_name=row.group_name,
        role=row.role,
        is_active=row.is_active,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.patch("/providers/{provider_id}/group-mappings/{mapping_id}", response_model=GroupRoleMappingResponse)
async def update_group_role_mapping(
    provider_id: int,
    mapping_id: int,
    body: GroupRoleMappingUpdate,
    _admin: dict = Depends(require_permission("admin:write")),
    db: AsyncSession = Depends(get_db),
):
    row = (
        await db.execute(
            select(SSOGroupRoleMapping).where(
                SSOGroupRoleMapping.id == mapping_id,
                SSOGroupRoleMapping.provider_id == provider_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Group mapping not found")

    payload = body.model_dump(exclude_unset=True)
    if "group_name" in payload and payload["group_name"]:
        payload["group_name"] = str(payload["group_name"]).strip()
    if "group_name" in payload and payload["group_name"] != row.group_name:
        dup = (
            await db.execute(
                select(SSOGroupRoleMapping).where(
                    SSOGroupRoleMapping.provider_id == provider_id,
                    SSOGroupRoleMapping.group_name == payload["group_name"],
                    SSOGroupRoleMapping.id != row.id,
                )
            )
        ).scalar_one_or_none()
        if dup:
            raise HTTPException(status_code=409, detail="Group mapping already exists for provider")

    for key, value in payload.items():
        setattr(row, key, value)

    await db.commit()
    await db.refresh(row)
    return GroupRoleMappingResponse(
        id=row.id,
        provider_id=row.provider_id,
        group_name=row.group_name,
        role=row.role,
        is_active=row.is_active,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.delete("/providers/{provider_id}/group-mappings/{mapping_id}", status_code=204)
async def delete_group_role_mapping(
    provider_id: int,
    mapping_id: int,
    _admin: dict = Depends(require_permission("admin:write")),
    db: AsyncSession = Depends(get_db),
):
    row = (
        await db.execute(
            select(SSOGroupRoleMapping).where(
                SSOGroupRoleMapping.id == mapping_id,
                SSOGroupRoleMapping.provider_id == provider_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Group mapping not found")
    await db.delete(row)
    await db.commit()
