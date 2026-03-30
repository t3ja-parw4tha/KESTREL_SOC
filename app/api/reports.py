"""Reports API — executive summaries, detection coverage stats, and analyst activity."""

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.mitre.techniques import TECHNIQUES
from app.database import get_db
from app.models import AuditLog
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.security.rbac import require_permission

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/summary")
async def get_report_summary(
    _user: Annotated[dict, Depends(require_permission("dashboard:read"))],
    db: AsyncSession = Depends(get_db),
    days: int = Query(30, ge=1, le=365),
):
    """
    Executive summary KPIs, volume timeline, top sources, and top MITRE tactics
    for the given time window. Also returns the previous equal-length period for
    trend comparison.
    """
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    prev_since = since - timedelta(days=days)

    # --- Current-period totals ---
    total_r = await db.execute(
        select(func.count()).select_from(Alert).where(Alert.created_at >= since)
    )
    total_alerts = total_r.scalar() or 0

    prev_total_r = await db.execute(
        select(func.count()).select_from(Alert).where(
            Alert.created_at >= prev_since, Alert.created_at < since
        )
    )
    prev_total = prev_total_r.scalar() or 0

    open_crit_r = await db.execute(
        select(func.count()).select_from(Alert).where(
            Alert.severity == AlertSeverity.CRITICAL, Alert.status == AlertStatus.OPEN
        )
    )
    open_critical = open_crit_r.scalar() or 0

    resolved_r = await db.execute(
        select(func.count()).select_from(Alert).where(
            Alert.created_at >= since, Alert.status == AlertStatus.RESOLVED
        )
    )
    resolved = resolved_r.scalar() or 0
    resolved_pct = round(resolved / total_alerts * 100, 1) if total_alerts else 0.0

    fp_r = await db.execute(
        select(func.count()).select_from(Alert).where(
            Alert.created_at >= since, Alert.status == AlertStatus.FALSE_POSITIVE
        )
    )
    false_positives = fp_r.scalar() or 0

    inc_r = await db.execute(
        select(func.count(func.distinct(Alert.incident_group_id)))
        .select_from(Alert)
        .where(Alert.incident_group_id.is_not(None), Alert.created_at >= since)
    )
    incidents_count = inc_r.scalar() or 0

    # --- Severity breakdown ---
    sev_r = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.created_at >= since, Alert.severity.is_not(None))
        .group_by(Alert.severity)
    )
    alerts_by_severity = {
        (s.value if hasattr(s, "value") else str(s)): c for s, c in sev_r.all()
    }

    # --- Top 5 sources ---
    src_r = await db.execute(
        select(Alert.source, func.count(Alert.id).label("cnt"))
        .where(Alert.created_at >= since)
        .group_by(Alert.source)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
    )
    top_sources = [{"source": s, "count": c} for s, c in src_r.all()]

    # --- Daily volume timeline ---
    vol_r = await db.execute(
        select(func.date(Alert.created_at).label("day"), func.count(Alert.id))
        .where(Alert.created_at >= since)
        .group_by(func.date(Alert.created_at))
    )
    volume_by_day = {str(d): c for d, c in vol_r.all()}
    volume_timeline = [
        {"date": (now - timedelta(days=i)).date().isoformat(), "count": 0}
        for i in range(days - 1, -1, -1)
    ]
    for entry in volume_timeline:
        day_key = str(entry["date"])
        entry["count"] = volume_by_day.get(day_key, 0)

    # --- Top 5 MITRE tactics ---
    mitre_r = await db.execute(
        select(Alert.mitre_techniques).where(
            Alert.created_at >= since, Alert.mitre_techniques.is_not(None)
        )
    )
    tactic_counts: dict[str, int] = {}
    for row in mitre_r.scalars().all():
        items = (
            row if isinstance(row, list)
            else (row.get("items") or [] if isinstance(row, dict) else [])
        )
        for t in items:
            if isinstance(t, dict) and t.get("tactic"):
                tac = str(t["tactic"])
                tactic_counts[tac] = tactic_counts.get(tac, 0) + 1
    top_tactics = sorted(
        [{"tactic": k, "count": v} for k, v in tactic_counts.items()],
        key=lambda x: int(str(x.get("count", 0))),
        reverse=True,
    )[:5]

    # --- MITRE coverage (all-time) ---
    all_mitre_r = await db.execute(
        select(Alert.mitre_techniques).where(Alert.mitre_techniques.is_not(None))
    )
    seen: set[str] = set()
    for row in all_mitre_r.scalars().all():
        items = (
            row if isinstance(row, list)
            else (row.get("items") or [] if isinstance(row, dict) else [])
        )
        for t in items:
            if isinstance(t, dict) and t.get("technique_id"):
                seen.add(str(t["technique_id"]))
    total_techniques = len(TECHNIQUES)
    coverage_pct = round(len(seen) / total_techniques * 100, 1) if total_techniques else 0.0

    return {
        "period_days": days,
        "total_alerts": total_alerts,
        "prev_total_alerts": prev_total,
        "open_critical": open_critical,
        "resolved": resolved,
        "resolved_pct": resolved_pct,
        "false_positives": false_positives,
        "incidents_count": incidents_count,
        "alerts_by_severity": alerts_by_severity,
        "top_sources": top_sources,
        "volume_timeline": volume_timeline,
        "top_tactics": top_tactics,
        "coverage_pct": coverage_pct,
        "techniques_detected": len(seen),
        "total_techniques": total_techniques,
    }


@router.get("/analyst-activity")
async def get_analyst_activity(
    _user: Annotated[dict, Depends(require_permission("audit:read"))],
    db: AsyncSession = Depends(get_db),
    days: int = Query(30, ge=1, le=365),
):
    """Per-analyst triage and comment counts from the audit log."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    upd_r = await db.execute(
        select(AuditLog.analyst, func.count(AuditLog.id).label("updates"))
        .where(
            AuditLog.action == "alert_updated",
            AuditLog.timestamp >= since,
            AuditLog.analyst.is_not(None),
        )
        .group_by(AuditLog.analyst)
        .order_by(func.count(AuditLog.id).desc())
    )

    com_r = await db.execute(
        select(AuditLog.analyst, func.count(AuditLog.id).label("comments"))
        .where(
            AuditLog.action == "comment",
            AuditLog.timestamp >= since,
            AuditLog.analyst.is_not(None),
        )
        .group_by(AuditLog.analyst)
    )
    comment_counts = {row.analyst: row.comments for row in com_r.all()}

    activity: list[dict] = []
    for row in upd_r.all():
        activity.append({
            "analyst": row.analyst,
            "alerts_triaged": row.updates,
            "comments_added": comment_counts.get(row.analyst, 0),
        })
    for analyst, count in comment_counts.items():
        if not any(a["analyst"] == analyst for a in activity):
            activity.append({"analyst": analyst, "alerts_triaged": 0, "comments_added": count})

    activity.sort(key=lambda x: x["alerts_triaged"] + x["comments_added"], reverse=True)
    return {"period_days": days, "analysts": activity}
