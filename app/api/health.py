"""Health check API router."""

from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import func, select

from app.config import get_settings
from app.database import engine
from app.models import Alert
from app.observability.health import (
    HealthStatus,
    check_ai_provider,
    check_database,
    check_disk_space,
    check_virustotal,
)

router = APIRouter(prefix="/health", tags=["health"])

# Uptime tracking (set at app startup)
_start_time: float | None = None


def set_start_time(t: float) -> None:
    global _start_time
    _start_time = t


@router.get("")
async def health():
    """
    Health check: status, database, version, alert_count, uptime.
    Use /health/ready for full component checks.
    """
    import time
    settings = get_settings()
    uptime = (time.time() - _start_time) if _start_time else 0
    db_status = "unknown"
    alert_count = 0
    try:
        async with engine.connect() as conn:
            await conn.execute(select(1))
            db_status = "ok"
            r = await conn.execute(select(func.count()).select_from(Alert))
            alert_count = r.scalar() or 0
    except Exception:
        db_status = "error"
    return {
        "status": "healthy" if db_status == "ok" else "degraded",
        "database": db_status,
        "version": settings.service_version,
        "alert_count": alert_count,
        "uptime": round(uptime, 1),
    }


@router.get("/live")
async def health_live():
    """Kubernetes liveness probe. Returns 200 if app process is running."""
    return {
        "status": "alive",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/ready")
async def health_ready():
    """
    Kubernetes readiness probe. Returns 200 only if app can serve traffic.
    Checks: database, disk space, optional VT/AI. Returns 503 if critical unhealthy.
    """
    import time
    settings = get_settings()
    uptime = (time.time() - _start_time) if _start_time else 0

    # Run component checks
    db_health = await check_database(engine)
    disk_health = await check_disk_space()
    vt_health = await check_virustotal()
    ai_health = await check_ai_provider()

    components: dict[str, dict] = {}
    for h in [db_health, disk_health, vt_health, ai_health]:
        components[h.name] = {
            "status": h.status.value,
            "latency_ms": round(h.latency_ms, 2) if h.latency_ms else None,
        }
        if h.message:
            components[h.name]["message"] = h.message

    # Overall status: unhealthy if DB or disk critical
    critical = [db_health, disk_health]
    has_unhealthy = any(c.status == HealthStatus.UNHEALTHY for c in critical)
    has_degraded = any(c.status == HealthStatus.DEGRADED for c in [db_health, disk_health, vt_health, ai_health])

    if has_unhealthy:
        overall = HealthStatus.UNHEALTHY
    elif has_degraded:
        overall = HealthStatus.DEGRADED
    else:
        overall = HealthStatus.HEALTHY

    # Alert/incident counts (best effort)
    alerts_total = 0
    open_critical = 0
    open_high = 0
    try:
        async with engine.connect() as conn:
            r = await conn.execute(select(func.count()).select_from(Alert))
            alerts_total = r.scalar() or 0
            # Stub models don't have status/severity yet - use total as placeholder
            open_critical = 0
            open_high = 0
    except Exception:
        pass

    payload = {
        "status": overall.value,
        "version": settings.service_version,
        "uptime_seconds": round(uptime, 1),
        "components": components,
        "alerts": {
            "total": alerts_total,
            "open_critical": open_critical,
            "open_high": open_high,
        },
    }
    status_code = 503 if overall == HealthStatus.UNHEALTHY else 200
    return JSONResponse(content=payload, status_code=status_code)
