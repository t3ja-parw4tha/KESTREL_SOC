"""Health check components for readiness probe."""

import shutil
import time
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import text


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    name: str
    status: HealthStatus
    latency_ms: float
    message: str | None = None
    last_checked: str = ""


async def check_database(engine) -> ComponentHealth:
    """Check database connectivity."""
    start = time.time()
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        latency = (time.time() - start) * 1000
        status = HealthStatus.HEALTHY
        if latency > 100:
            status = HealthStatus.DEGRADED
        return ComponentHealth(
            name="database",
            status=status,
            latency_ms=latency
        )
    except Exception as e:
        return ComponentHealth(
            name="database",
            status=HealthStatus.UNHEALTHY,
            latency_ms=0,
            message=str(e)
        )


async def check_virustotal() -> ComponentHealth:
    """Check VirusTotal API availability (stub - returns healthy if not configured)."""
    from app.config import get_settings
    settings = get_settings()
    if not settings.virustotal_api_key.get_secret_value():
        return ComponentHealth(
            name="virustotal",
            status=HealthStatus.DEGRADED,
            latency_ms=0,
            message="API key not configured"
        )
    # TODO: ping VT API with known safe hash when implemented
    return ComponentHealth(
        name="virustotal",
        status=HealthStatus.HEALTHY,
        latency_ms=0
    )


async def check_ai_provider() -> ComponentHealth:
    """Check AI provider availability (stub - returns healthy if not configured)."""
    from app.config import get_settings
    settings = get_settings()
    if settings.ai_provider == "openai" and not settings.openai_api_key.get_secret_value():
        return ComponentHealth(
            name="ai_provider",
            status=HealthStatus.DEGRADED,
            latency_ms=0,
            message="OpenAI API key not configured"
        )
    if settings.ai_provider == "anthropic" and not settings.anthropic_api_key.get_secret_value():
        return ComponentHealth(
            name="ai_provider",
            status=HealthStatus.DEGRADED,
            latency_ms=0,
            message="Anthropic API key not configured"
        )
    # TODO: minimal token generation test when implemented
    return ComponentHealth(
        name="ai_provider",
        status=HealthStatus.HEALTHY,
        latency_ms=0
    )


async def check_disk_space() -> ComponentHealth:
    """Check disk space usage."""
    try:
        total, used, free = shutil.disk_usage("/")
        pct_used = (used / total) * 100
        status = HealthStatus.HEALTHY
        if pct_used > 80:
            status = HealthStatus.DEGRADED
        if pct_used > 95:
            status = HealthStatus.UNHEALTHY
        return ComponentHealth(
            name="disk",
            status=status,
            latency_ms=0,
            message=f"{pct_used:.1f}% used"
        )
    except Exception as e:
        return ComponentHealth(
            name="disk",
            status=HealthStatus.UNHEALTHY,
            latency_ms=0,
            message=str(e)
        )
