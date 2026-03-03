"""SOC Platform API application entrypoint."""

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api import alerts, audit, auth, decisions, health, ai, incidents, ingest, mitre, pages, security_dashboard, sources
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


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()
    setup_logging(settings.log_level)
    set_start_time(time.time())

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Startup: run migrations (create tables). Shutdown: dispose engine."""
        ensure_jwt_keys()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        yield
        await engine.dispose()

    app = FastAPI(
        title="SOC Platform API",
        description="AI-assisted SOC log aggregation and incident triage",
        version=settings.service_version,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Observability (CorrelationID must be first middleware = add last)
    app.add_middleware(CorrelationIDMiddleware)
    setup_metrics(app)
    setup_tracing(app, engine)

    # Security middleware
    setup_security(app)

    # Exception handlers
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={"detail": exc.errors(), "body": exc.body},
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
    app.include_router(ingest.router, prefix="/api/v1")
    app.include_router(decisions.router, prefix="/api/v1")
    app.include_router(ai.router, prefix="/api/v1")
    app.include_router(incidents.router, prefix="/api/v1")
    app.include_router(mitre.router, prefix="/api/v1")
    app.include_router(sources.router, prefix="/api/v1")
    app.include_router(audit.router, prefix="/api/v1")
    app.include_router(health.router)
    app.include_router(security_dashboard.router, prefix="/api/v1")
    app.include_router(pages.router)

    return app


app = create_app()
