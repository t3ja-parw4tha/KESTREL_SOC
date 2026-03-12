"""CSRF protection via double-submit with server-side session token."""

import hmac
import secrets

from fastapi import Depends, HTTPException, Request

from app.security.rbac import get_current_user

CSRF_SESSION_KEY = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"

# Safe HTTP methods that do not require CSRF validation
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def generate_csrf_token() -> str:
    return secrets.token_hex(32)


async def get_csrf_token(
    request: Request,
    _user: dict = Depends(get_current_user),
) -> dict:
    """Generate and store a CSRF token in the server-side session."""
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = generate_csrf_token()
        request.session[CSRF_SESSION_KEY] = token
    return {"csrf_token": token}


async def verify_csrf(request: Request) -> None:
    """FastAPI dependency: validate CSRF token on state-changing requests.

    Safe methods (GET, HEAD, OPTIONS) are always skipped.

    Non-browser API clients (API key auth, direct integrations) will not have a
    server-side CSRF session token — those requests are skipped automatically.
    Only browser sessions that have fetched a CSRF token via GET /auth/csrf-token
    are subject to strict validation.
    """
    if request.method.upper() in _SAFE_METHODS:
        return

    session_token: str = request.session.get(CSRF_SESSION_KEY, "")

    # No session token means this is a non-browser API client — skip enforcement.
    # When a browser user is logged in, the session token is always set after
    # the initial GET /auth/csrf-token call made post-login.
    if not session_token:
        return

    header_token: str = request.headers.get(CSRF_HEADER, "")

    if not header_token:
        raise HTTPException(status_code=403, detail="CSRF token missing")

    if not hmac.compare_digest(session_token.encode(), header_token.encode()):
        raise HTTPException(status_code=403, detail="CSRF token mismatch")
