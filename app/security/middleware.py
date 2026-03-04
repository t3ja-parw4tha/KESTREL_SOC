"""
OWASP-aligned security middleware: headers, rate limiting, validation, CORS, audit.

Order of registration (last added = first to run): Request ID → Security headers
→ CORS → Rate limit → Request validation → Audit.
"""

import ipaddress
import json
import logging
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Callable

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings
from app.security.sanitization import sanitize_for_log

logger = logging.getLogger(__name__)

# --- Constants ---
MAX_BODY_BYTES = 10 * 1024 * 1024  # 10MB
MAX_URL_LENGTH = 2048
MAX_HEADER_VALUE_BYTES = 8192
RATE_VIOLATIONS_BLOCK_THRESHOLD = 10
RATE_VIOLATIONS_WINDOW_HOURS = 1
REQUEST_ID_HEADER = "X-Request-ID"
UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)

# Rate limit tiers: (limit, window_seconds)
RATE_TIERS = {
    "auth_login": (5, 60),
    "auth_refresh": (10, 60),
    "ingest": (100, 60),
    "ai": (20, 3600),
    "default": (200, 60),
}


def get_real_ip(request: Request) -> str:
    """
    Extract client IP from X-Forwarded-For (rightmost trusted) or direct client.
    Validates each IP in chain; never trust client-supplied IPs for security decisions
    without validation.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",")]
        for part in reversed(parts):
            try:
                ip = ipaddress.ip_address(part)
                if ip.is_global or ip.is_private:
                    return str(ip)
            except ValueError:
                continue
    if request.client:
        return request.client.host
    return "0.0.0.0"


def _get_rate_tier(path: str, method: str) -> str:
    if path.rstrip("/").endswith("/auth/login") and method == "POST":
        return "auth_login"
    if path.rstrip("/").endswith("/auth/refresh") and method == "POST":
        return "auth_refresh"
    if "/ingest" in path:
        return "ingest"
    if path.startswith("/ai") or "/ai/" in path:
        return "ai"
    return "default"


async def _get_rate_limit_key(request: Request, tier: str, real_ip: str) -> str:
    if tier == "ingest":
        api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").replace("Bearer ", "")
        if api_key:
            return f"key:{api_key[:32]}"
    if tier == "ai":
        auth = request.headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            return f"user:{auth[:64]}"
    return f"ip:{real_ip}"


# --- 1. Request ID middleware ---
class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        req_id = request.headers.get(REQUEST_ID_HEADER)
        if req_id and not UUID_REGEX.match(req_id.strip()):
            return Response(status_code=400, content=json.dumps({"detail": "Invalid X-Request-ID"}))
        if not req_id:
            req_id = str(uuid.uuid4())
        request.state.request_id = req_id
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = req_id
        return response


# --- 2. Security headers middleware ---
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        response = await call_next(request)
        csp = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self' https://api.virustotal.com https://api.abuseipdb.com; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "upgrade-insecure-requests"
        )
        response.headers["Content-Security-Policy"] = csp
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=(), usb=(), bluetooth=()"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if "Server" in response.headers:
            del response.headers["Server"]
        if "X-Powered-By" in response.headers:
            del response.headers["X-Powered-By"]
        if "X-AspNet-Version" in response.headers:
            del response.headers["X-AspNet-Version"]
        return response


# --- 3. CORS middleware (configured in setup_security via Starlette) ---
# We use CORSMiddleware from Starlette with config from env.


# --- 4. Rate limiting middleware ---
class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        from app.models import RateLimitBucket, RateLimitViolation
        from app.database import SessionLocal
        from sqlalchemy import select, delete
        from datetime import timedelta

        real_ip = get_real_ip(request)
        path = request.url.path or ""
        method = request.method or "GET"

        async with SessionLocal() as db:
            try:
                # Block IP if too many violations
                cutoff = datetime.now(timezone.utc) - timedelta(hours=RATE_VIOLATIONS_WINDOW_HOURS)
                stmt = select(RateLimitViolation).where(
                    RateLimitViolation.ip_address == real_ip,
                    RateLimitViolation.created_at >= cutoff,
                )
                result = await db.execute(stmt)
                violations = list(result.scalars().all())
                if len(violations) >= RATE_VIOLATIONS_BLOCK_THRESHOLD:
                    return Response(
                        status_code=429,
                        content=json.dumps({"detail": "Too many rate limit violations; try again later"}),
                        headers={"Retry-After": "3600"},
                    )

                tier = _get_rate_tier(path, method)
                limit, window_sec = RATE_TIERS[tier]
                key = await _get_rate_limit_key(request, tier, real_ip)
                window_start = datetime.fromtimestamp(
                    int(time.time()) // window_sec * window_sec,
                    tz=timezone.utc,
                )

                bucket_key = f"{key}:{tier}"
                bucket_stmt = select(RateLimitBucket).where(
                    RateLimitBucket.key == bucket_key,
                    RateLimitBucket.window_start == window_start,
                )
                bucket_result = await db.execute(bucket_stmt)
                bucket = bucket_result.scalar_one_or_none()
                if not bucket:
                    await db.execute(delete(RateLimitBucket).where(RateLimitBucket.key == bucket_key))
                    bucket = RateLimitBucket(key=bucket_key, tier=tier, window_start=window_start, count=0)
                    db.add(bucket)
                bucket.count += 1
                await db.flush()
                await db.commit()

                remaining = max(0, limit - bucket.count)
                reset_ts = int(window_start.timestamp()) + window_sec

                if bucket.count > limit:
                    viol = RateLimitViolation(ip_address=real_ip)
                    db.add(viol)
                    await db.commit()
                    return Response(
                        status_code=429,
                        content=json.dumps({"detail": "Too many requests"}),
                        headers={
                            "Retry-After": str(window_sec),
                            "X-RateLimit-Limit": str(limit),
                            "X-RateLimit-Remaining": "0",
                            "X-RateLimit-Reset": str(reset_ts),
                        },
                    )

                response = await call_next(request)
                response.headers["X-RateLimit-Limit"] = str(limit)
                response.headers["X-RateLimit-Remaining"] = str(remaining)
                response.headers["X-RateLimit-Reset"] = str(reset_ts)
                return response
            except Exception as e:
                logger.exception("Rate limit middleware error: %s", e)
                return await call_next(request)


# --- 5. Request validation middleware ---
class RequestValidationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        settings = get_settings()
        max_url = getattr(settings, "max_url_length", MAX_URL_LENGTH)
        max_header = getattr(settings, "max_header_value_bytes", MAX_HEADER_VALUE_BYTES)
        max_body = getattr(settings, "max_request_body_bytes", MAX_BODY_BYTES)

        if request.scope.get("http_version") == "1.0":
            return Response(status_code=505, content=json.dumps({"detail": "HTTP/1.0 not allowed"}))

        url = str(request.url)
        if len(url) > max_url:
            return Response(status_code=414, content=json.dumps({"detail": "URI too long"}))

        for name, value in request.headers.items():
            if len(value.encode("utf-8")) > max_header:
                return Response(status_code=400, content=json.dumps({"detail": "Header value too large"}))

        content_type = request.headers.get("Content-Type", "")
        if request.method in ("POST", "PATCH", "PUT"):
            if not content_type or "application/json" not in content_type.split(";")[0].strip().lower():
                return Response(
                    status_code=415,
                    content=json.dumps({"detail": "Content-Type must be application/json"}),
                )
            content_length = request.headers.get("Content-Length")
            if content_length and int(content_length) > max_body:
                return Response(status_code=413, content=json.dumps({"detail": "Request body too large"}))

        response = await call_next(request)
        return response


# --- 6. Audit logging middleware ---
class AuditLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        import uuid
        from app.models import AuditLog
        from app.database import SessionLocal
        from app.security.auth import verify_token
        from app.security.exceptions import SecurityError

        start = time.perf_counter()

        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000
        # StreamingResponse has body_iterator; we don't capture length

        real_ip = get_real_ip(request)
        path = sanitize_for_log(request.url.path or "")
        method = sanitize_for_log(request.method or "")
        user_agent = sanitize_for_log(request.headers.get("User-Agent", "")[:512])
        request_id = getattr(request.state, "request_id", None)

        user_id = None
        try:
            auth = request.headers.get("Authorization")
            if auth and auth.startswith("Bearer "):
                payload = verify_token(auth.split(" ", 1)[1].strip())
                user_id = int(payload.get("sub", 0)) or None
        except (SecurityError, ValueError, KeyError):
            pass

        details = None
        status = getattr(response, "status_code", 0)
        if status == 404 and ".." in (request.url.path or ""):
            details = "suspicious:path_traversal_attempt"
        elif status == 401:
            details = "suspicious:repeated_401"

        async with SessionLocal() as db:
            try:
                audit_entry = AuditLog(
                    id=str(uuid.uuid4()),
                    action="request",
                    request_id=str(request_id) if request_id else None,
                    method=method,
                    path=path[:512],
                    status_code=status,
                    analyst=str(user_id) if user_id else None,
                    ip_address=real_ip,
                    user_agent=user_agent,
                    duration_ms=round(duration_ms, 2),
                    details={"raw": details} if details else None,
                )
                db.add(audit_entry)
                await db.commit()
            except Exception as e:
                logger.warning("Audit log write failed: %s", e)

        return response


def setup_security(app: FastAPI) -> None:
    """
    Register all security middleware in correct order.
    Last added = first to run: so we add in reverse order (Audit first, Request ID last).
    """
    from starlette.middleware.cors import CORSMiddleware

    settings = get_settings()
    origins = [o.strip() for o in settings.allowed_origins.split(",") if o.strip()]
    if not origins:
        origins = ["http://localhost:8000"]

    # 6. Audit logging (innermost)
    app.add_middleware(AuditLoggingMiddleware)
    # 5. Request validation
    app.add_middleware(RequestValidationMiddleware)
    # 4. Rate limiting
    app.add_middleware(RateLimitMiddleware)
    # 3. CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", REQUEST_ID_HEADER, "X-API-Key"],
        expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", REQUEST_ID_HEADER],
        max_age=3600,
    )
    # 2. Security headers
    app.add_middleware(SecurityHeadersMiddleware)
    # 1. Request ID (outermost)
    app.add_middleware(RequestIDMiddleware)
