"""Enterprise SSO routes (OIDC for Okta/Entra ID)."""

import httpx
import logging
from datetime import datetime, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request, Response, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import jwt as pyjwt

from app.database import get_db
from app.models import SSOProvider, User
from app.security.auth import (
    create_access_token,
    create_refresh_token,
    create_session,
    REFRESH_TOKEN_COOKIE,
)
from app.config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth/sso", tags=["sso"])

REFRESH_COOKIE_MAX_AGE = 7 * 24 * 3600

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

    # Build callback URL
    app_settings = get_settings()
    # E.g., http://localhost:5173 or platform base url. We get it from request host for now.
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
    state: str = None,
    code: str = None,
    error: str = None,
    db: AsyncSession = Depends(get_db),
):
    """Handle OIDC callback from IdP, exchange code, verify JWT, issue our tokens."""
    if error:
        logger.warning("SSO error returned from IdP: %s", error)
        return RedirectResponse(f"/?error=sso_failed")

    if not code or not state:
        return RedirectResponse(f"/?error=missing_params")

    session_state = request.session.pop("sso_state", None)
    nonce = request.session.pop("sso_nonce", None)
    provider_id = request.session.pop("sso_provider_id", None)

    if not session_state or state != session_state:
        logger.warning("SSO state mismatch or missing session")
        return RedirectResponse(f"/?error=invalid_state")

    stmt = select(SSOProvider).where(SSOProvider.id == provider_id, SSOProvider.is_active.is_(True))
    r = await db.execute(stmt)
    provider = r.scalar_one_or_none()
    
    if not provider:
        return RedirectResponse(f"/?error=provider_not_found")

    try:
        oidc_config = await _get_oidc_config(provider.issuer_url)
    except Exception as e:
        logger.error("Failed to fetch OIDC config during callback: %s", e)
        return RedirectResponse(f"/?error=idp_unreachable")

    token_endpoint = oidc_config.get("token_endpoint")
    jwks_uri = oidc_config.get("jwks_uri")
    
    if not token_endpoint or not jwks_uri:
        return RedirectResponse(f"/?error=invalid_idp_config")

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
            return RedirectResponse(f"/?error=token_exchange_failed")
            
        token_data = token_resp.json()
        id_token = token_data.get("id_token")

        if not id_token:
            return RedirectResponse(f"/?error=no_id_token")

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
            return RedirectResponse(f"/?error=invalid_id_token")

    # Validate nonce
    if payload.get("nonce") != nonce:
        logger.warning("SSO nonce mismatch")
        return RedirectResponse(f"/?error=invalid_nonce")

    # The user authenticated successfully with their IdP.
    sso_sub = payload.get("sub")
    email = payload.get("email") or payload.get("upn") or payload.get("preferred_username")

    if not sso_sub or not email:
        return RedirectResponse(f"/?error=missing_claims")

    email = email.lower()

    # Look for existing user
    stmt = select(User).where((User.sso_id == sso_sub) | (User.email == email))
    r = await db.execute(stmt)
    user = r.scalars().first()

    if user:
        if not user.is_active:
            return RedirectResponse(f"/?error=account_disabled")
        # Update sso_id if they previously logged in with password but now use SSO
        if user.sso_id != sso_sub:
            user.sso_id = sso_sub
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

        user = User(
            username=username,
            email=email,
            password_hash=None, # No local password
            role="analyst",     # Default role
            is_active=True,
            sso_id=sso_sub,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(user)
        await db.commit()

    # Issue KESTREL local tokens
    access_token, _ = create_access_token(user.id, user.role)
    refresh_token, refresh_jti = create_refresh_token(user.id, user.role)
    
    await create_session(
        db,
        user.id,
        refresh_jti,
        request.client.host if request.client else None,
        request.headers.get("user-agent"),
    )

    response = RedirectResponse(f"/?sso_success=true")
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
