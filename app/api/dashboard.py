"""Dashboard stats API — single endpoint replacing N+1 calls from the frontend."""

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.mitre.techniques import TECHNIQUES
from app.database import get_db
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.security.rbac import require_permission

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
async def get_dashboard_stats(
    _user: Annotated[dict, Depends(require_permission("dashboard:read"))],
    db: AsyncSession = Depends(get_db),
):
    """
    Return all dashboard KPIs in a single DB round-trip.
    Replaces the 11 parallel API calls previously made by the frontend.
    """
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)

    # --- Aggregate counts ---
    total_r = await db.execute(select(func.count()).select_from(Alert))
    total_alerts = total_r.scalar() or 0

    open_crit_r = await db.execute(
        select(func.count()).select_from(Alert).where(
            Alert.severity == AlertSeverity.CRITICAL,
            Alert.status == AlertStatus.OPEN,
        )
    )
    open_high_r = await db.execute(
        select(func.count()).select_from(Alert).where(
            Alert.severity == AlertSeverity.HIGH,
            Alert.status == AlertStatus.OPEN,
        )
    )
    open_critical = open_crit_r.scalar() or 0
    open_high = open_high_r.scalar() or 0

    inc_r = await db.execute(
        select(func.count(func.distinct(Alert.incident_group_id)))
        .select_from(Alert)
        .where(Alert.incident_group_id.is_not(None))
    )
    incidents_count = inc_r.scalar() or 0

    # --- Alerts by severity ---
    sev_r = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.severity.is_not(None))
        .group_by(Alert.severity)
    )
    alerts_by_severity = {
        (s.value if hasattr(s, "value") else str(s)): c
        for s, c in sev_r.all()
    }

    # --- 7-day volume timeline ---
    vol_r = await db.execute(
        select(func.date(Alert.created_at).label("day"), func.count(Alert.id))
        .where(Alert.created_at >= seven_days_ago)
        .group_by(func.date(Alert.created_at))
    )
    volume_by_day = {str(d): c for d, c in vol_r.all()}
    # Fill missing days with 0
    volume_timeline = []
    for i in range(6, -1, -1):
        day = (now - timedelta(days=i)).date().isoformat()
        volume_timeline.append({"date": day, "count": volume_by_day.get(day, 0)})

    # --- Recent alerts (10) ---
    recent_r = await db.execute(
        select(Alert).order_by(Alert.created_at.desc()).limit(10)
    )
    recent_rows = recent_r.scalars().all()
    recent_alerts = [
        {
            "id": a.id,
            "title": a.title,
            "source": a.source,
            "severity": a.severity.value if a.severity else "",
            "status": a.status.value if a.status else "",
            "category": a.category,
            "risk_score": a.risk_score,
            "risk_level": a.risk_level,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in recent_rows
    ]

    # --- Top 5 incidents by risk score ---
    inc_subq = (
        select(
            Alert.incident_group_id,
            func.count(Alert.id).label("cnt"),
            func.max(Alert.risk_score).label("max_score"),
            func.max(Alert.severity).label("max_sev"),
        )
        .where(Alert.incident_group_id.is_not(None))
        .group_by(Alert.incident_group_id)
        .order_by(func.max(Alert.risk_score).desc())
        .limit(5)
    )
    inc_rows = (await db.execute(inc_subq)).all()
    incidents = [
        {
            "incident_id": row.incident_group_id,
            "alert_count": row.cnt,
            "max_risk_score": row.max_score,
            "highest_severity": (
                row.max_sev.value if hasattr(row.max_sev, "value") else str(row.max_sev or "")
            ),
        }
        for row in inc_rows
    ]

    # --- MITRE coverage ---
    mitre_r = await db.execute(
        select(Alert.mitre_techniques).where(Alert.mitre_techniques.is_not(None))
    )
    seen_techniques: set[str] = set()
    for row in mitre_r.scalars().all():
        items = row if isinstance(row, list) else (row.get("items") or [] if isinstance(row, dict) else [])
        for t in items:
            if isinstance(t, dict) and t.get("technique_id"):
                seen_techniques.add(t["technique_id"])
    total_techniques = len(TECHNIQUES)
    techniques_detected = len(seen_techniques)
    coverage_pct = round(techniques_detected / total_techniques * 100, 1) if total_techniques else 0.0

    return {
        "total_alerts": total_alerts,
        "open_critical": open_critical,
        "open_high": open_high,
        "incidents_count": incidents_count,
        "alerts_by_severity": alerts_by_severity,
        "volume_timeline": volume_timeline,
        "recent_alerts": recent_alerts,
        "incidents": incidents,
        "coverage_pct": coverage_pct,
        "techniques_detected": techniques_detected,
        "total_techniques": total_techniques,
    }
