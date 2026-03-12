"""SOC Platform API application entrypoint."""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api import alerts, audit, auth, dashboard, decisions, health, ai, incidents, ingest, mitre, pages, reports, security_dashboard, sources, sso, playbooks, settings as settings_router
from app.api.health import set_start_time
from app.config import get_settings
from app.database import Base, engine
from app import models  # noqa: F401 - register models with Base.metadata
from app.observability.correlation import CorrelationIDMiddleware
from app.observability.logging import setup_logging
from app.observability.metrics import setup_metrics
from app.observability.tracing import setup_tracing
from app.security.auth import ensure_jwt_keys
from app.security.exceptions import SecurityError
from app.security.middleware import setup_security
from starlette.middleware.sessions import SessionMiddleware

_cleanup_logger = logging.getLogger("app.cleanup")

CLEANUP_INTERVAL_SECONDS = 3600  # run every hour
BUCKET_MAX_AGE_HOURS = 2
VIOLATION_MAX_AGE_HOURS = 1


async def _cleanup_stale_records() -> None:
    """Hourly background task: purge expired rate-limit buckets, violations, and token blocklist rows."""
    from sqlalchemy import delete as sa_delete
    from app.database import SessionLocal
    from app.models import RateLimitBucket, RateLimitViolation, TokenBlocklist

    while True:
        await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
        try:
            now = datetime.now(timezone.utc)
            bucket_cutoff = now - timedelta(hours=BUCKET_MAX_AGE_HOURS)
            violation_cutoff = now - timedelta(hours=VIOLATION_MAX_AGE_HOURS)

            async with SessionLocal() as db:
                await db.execute(
                    sa_delete(RateLimitBucket).where(RateLimitBucket.window_start < bucket_cutoff)
                )
                await db.execute(
                    sa_delete(RateLimitViolation).where(RateLimitViolation.created_at < violation_cutoff)
                )
                await db.execute(
                    sa_delete(TokenBlocklist).where(TokenBlocklist.exp < now)
                )
                await db.commit()
            _cleanup_logger.debug("Stale record cleanup complete")
        except Exception:  # noqa: BLE001
            _cleanup_logger.exception("Cleanup task failed")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()
    setup_logging(settings.log_level)
    set_start_time(time.time())

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Startup: run migrations (create tables). Shutdown: dispose engine."""
        if not settings.debug:
            default_secret = "change-me-in-production"
            if settings.secret_key.get_secret_value() == default_secret:
                raise RuntimeError(
                    "SECRET_KEY must be set to a secure value in production. "
                    "Set SECRET_KEY in .env or use the setup wizard."
                )
        ensure_jwt_keys()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        cleanup_task = asyncio.create_task(_cleanup_stale_records())
        yield
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        await engine.dispose()

    app = FastAPI(
        title="KESTREL API",
        description="AI-assisted SOC triage and detection platform",
        version=settings.service_version,
        # Disable interactive API docs in production to reduce attack surface.
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        openapi_url="/openapi.json" if settings.debug else None,
        lifespan=lifespan,
    )

    # Observability (CorrelationID must be first middleware = add last)
    app.add_middleware(CorrelationIDMiddleware)
    setup_metrics(app)
    setup_tracing(app, engine)

    # Session middleware (Required by Authlib for OIDC state/nonce tracking)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key.get_secret_value(),
        session_cookie="kestrel_sso_session",
        max_age=3600,
        same_site="lax",
        https_only=not settings.debug,
    )

    # Security middleware
    setup_security(app)

    # Exception handlers
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={
                "detail": jsonable_encoder(
                    exc.errors(),
                    custom_encoder={Exception: lambda err: str(err)},
                ),
                "body": jsonable_encoder(
                    exc.body,
                    custom_encoder={Exception: lambda err: str(err)},
                ),
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )

    @app.exception_handler(SecurityError)
    async def security_exception_handler(request: Request, exc: SecurityError):
        return JSONResponse(
            status_code=400,
            content={"detail": str(exc)},
        )

    @app.exception_handler(Exception)
    async def internal_exception_handler(request: Request, exc: Exception):
        import logging

        logging.getLogger(__name__).exception("Unhandled exception: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    # Routers
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(alerts.router, prefix="/api/v1")
    app.include_router(dashboard.router, prefix="/api/v1")
    app.include_router(ingest.router, prefix="/api/v1")
    app.include_router(decisions.router, prefix="/api/v1")
    app.include_router(sso.router, prefix="/api/v1")
    app.include_router(playbooks.router, prefix="/api/v1")
    app.include_router(ai.router, prefix="/api/v1")
    app.include_router(incidents.router, prefix="/api/v1")
    app.include_router(mitre.router, prefix="/api/v1")
    app.include_router(sources.router, prefix="/api/v1")
    app.include_router(audit.router, prefix="/api/v1")
    app.include_router(settings_router.router, prefix="/api/v1")
    app.include_router(reports.router, prefix="/api/v1")
    app.include_router(health.router)
    app.include_router(security_dashboard.router, prefix="/api/v1")
    app.include_router(pages.router)

    return app


app = create_app()

