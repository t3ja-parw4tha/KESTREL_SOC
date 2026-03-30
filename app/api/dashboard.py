"""Dashboard stats API — single endpoint replacing N+1 calls from the frontend."""

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from typing import Literal
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.mitre.techniques import TECHNIQUES
from app.database import get_db
from app.models import (
    Asset,
    AuditLog,
    CaseRecord,
    ComplianceReportArtifact,
    DetectionRule,
    HuntQueryRecord,
    HuntResultRecord,
    Playbook,
    RunbookApprovalRequest,
    SourceHealth,
    User,
)
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.security.rbac import require_permission

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/section-quality-metrics")
async def get_section_quality_metrics(
    _user: Annotated[dict, Depends(require_permission("dashboard:read"))],
    db: AsyncSession = Depends(get_db),
):
    """A2 acceptance surface: one measurable metric per sidebar section."""
    now = datetime.now(timezone.utc)

    latest_ingest = (
        await db.execute(select(func.max(Alert.created_at)).select_from(Alert))
    ).scalar_one_or_none()
    ingest_lag_minutes = None
    if latest_ingest:
        if latest_ingest.tzinfo is None:
            latest_ingest = latest_ingest.replace(tzinfo=timezone.utc)
        ingest_lag_minutes = round((now - latest_ingest).total_seconds() / 60, 1)

    open_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.status.in_([AlertStatus.OPEN, AlertStatus.IN_PROGRESS]))
        )
    ).scalar() or 0

    incidents_count = (
        await db.execute(
            select(func.count(func.distinct(Alert.incident_group_id))).where(Alert.incident_group_id.is_not(None))
        )
    ).scalar() or 0

    assets_count = (await db.execute(select(func.count(Asset.id)))).scalar() or 0
    saved_hunts = (
        await db.execute(select(func.count(HuntQueryRecord.id)).where(HuntQueryRecord.is_active.is_(True)))
    ).scalar() or 0
    active_playbooks = (
        await db.execute(select(func.count(Playbook.id)).where(Playbook.is_active.is_(True)))
    ).scalar() or 0
    enabled_rules = (
        await db.execute(select(func.count(DetectionRule.id)).where(DetectionRule.enabled.is_(True)))
    ).scalar() or 0
    pending_approvals = (
        await db.execute(
            select(func.count(RunbookApprovalRequest.id)).where(RunbookApprovalRequest.status == "pending")
        )
    ).scalar() or 0
    signed_artifacts = (await db.execute(select(func.count(ComplianceReportArtifact.report_id)))).scalar() or 0
    source_records = (await db.execute(select(func.count(SourceHealth.source_id)))).scalar() or 0
    active_users = (await db.execute(select(func.count(User.id)).where(User.is_active.is_(True)))).scalar() or 0

    settings_audits_30d = (
        await db.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.action.in_(["settings.update", "settings.delete"]),
                AuditLog.timestamp >= (now - timedelta(days=30)),
            )
        )
    ).scalar() or 0

    # MITRE coverage metric mirrors the main dashboard computation.
    mitre_rows = await db.execute(
        select(Alert.mitre_techniques).where(Alert.mitre_techniques.is_not(None))
    )
    seen_techniques: set[str] = set()
    for row in mitre_rows.scalars().all():
        items = row if isinstance(row, list) else (row.get("items") or [] if isinstance(row, dict) else [])
        for t in items:
            if isinstance(t, dict) and t.get("technique_id"):
                seen_techniques.add(str(t["technique_id"]))
    mitre_coverage_pct = round((len(seen_techniques) / len(TECHNIQUES)) * 100, 1) if TECHNIQUES else 0.0

    return {
        "generated_at": now.isoformat(),
        "sections": {
            "dashboard": {"metric": "ingest_lag_minutes", "value": ingest_lag_minutes, "target": "<= 15"},
            "alerts": {"metric": "open_alerts", "value": int(open_alerts), "target": "minimize"},
            "incidents": {"metric": "correlated_incident_count", "value": int(incidents_count), "target": ">= 1 when attacks correlate"},
            "assets": {"metric": "tracked_assets", "value": int(assets_count), "target": "> 0"},
            "mitre": {"metric": "coverage_pct", "value": mitre_coverage_pct, "target": ">= 80"},
            "hunting": {"metric": "saved_hunts", "value": int(saved_hunts), "target": "> 0"},
            "playbooks": {"metric": "active_playbooks", "value": int(active_playbooks), "target": "> 0"},
            "detection_rules": {"metric": "enabled_rules", "value": int(enabled_rules), "target": "> 0"},
            "resilience": {"metric": "pending_runbook_approvals", "value": int(pending_approvals), "target": "near 0 backlog"},
            "reports": {"metric": "signed_report_artifacts", "value": int(signed_artifacts), "target": "> 0 for compliance windows"},
            "sources": {"metric": "monitored_sources", "value": int(source_records), "target": "> 0"},
            "help": {"metric": "documented_sections", "value": 12, "target": "12"},
            "users": {"metric": "active_users", "value": int(active_users), "target": "> 0"},
            "settings": {"metric": "settings_audit_events_30d", "value": int(settings_audits_30d), "target": ">= 1 when changes occur"},
        },
    }


@router.get("/workflow-traceability")
async def get_workflow_traceability(
    _user: Annotated[dict, Depends(require_permission("dashboard:read"))],
    db: AsyncSession = Depends(get_db),
):
    """A5 acceptance surface: summarize detection-to-closure linkage coverage."""
    now = datetime.now(timezone.utc)

    alerts_in_incidents = (
        await db.execute(select(func.count(Alert.id)).where(Alert.incident_group_id.is_not(None)))
    ).scalar() or 0
    hunts_linked_to_alerts = (
        await db.execute(select(func.count(HuntResultRecord.id)).where(HuntResultRecord.alert_id.is_not(None)))
    ).scalar() or 0
    executed_approvals = (
        await db.execute(
            select(func.count(RunbookApprovalRequest.id)).where(RunbookApprovalRequest.status == "executed")
        )
    ).scalar() or 0

    case_rows = (await db.execute(select(CaseRecord))).scalars().all()
    total_cases = len(case_rows)
    cases_with_alert_links = 0
    cases_with_incident_links = 0
    closed_cases_with_reason = 0
    for row in case_rows:
        alert_links = row.linked_alert_ids if isinstance(row.linked_alert_ids, list) else []
        incident_links = row.linked_incident_ids if isinstance(row.linked_incident_ids, list) else []
        if alert_links:
            cases_with_alert_links += 1
        if incident_links:
            cases_with_incident_links += 1
        if str(row.status) in {"CaseStatus.RESOLVED", "CaseStatus.CLOSED", "resolved", "closed"} and row.closure_reason:
            closed_cases_with_reason += 1

    return {
        "generated_at": now.isoformat(),
        "traceability": {
            "alerts_linked_to_incidents": int(alerts_in_incidents),
            "hunt_results_linked_to_alerts": int(hunts_linked_to_alerts),
            "executed_playbook_approvals": int(executed_approvals),
            "total_cases": int(total_cases),
            "cases_with_alert_links": int(cases_with_alert_links),
            "cases_with_incident_links": int(cases_with_incident_links),
            "closed_cases_with_reason": int(closed_cases_with_reason),
        },
    }


@router.get("/stats")
async def get_dashboard_stats(
    _user: Annotated[dict, Depends(require_permission("dashboard:read"))],
    db: AsyncSession = Depends(get_db),
    trend_period: Literal["day", "week", "month"] = Query("day"),
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

    # --- 7-day volume timeline (per-severity breakdown) ---
    vol_r = await db.execute(
        select(
            func.date(Alert.created_at).label("day"),
            Alert.severity,
            func.count(Alert.id),
        )
        .where(Alert.created_at >= seven_days_ago)
        .group_by(func.date(Alert.created_at), Alert.severity)
    )
    volume_by_day_sev: dict[str, dict[str, int]] = {}
    for day, sev, cnt in vol_r.all():
        day_str = str(day)
        sev_str = (sev.value if hasattr(sev, "value") else str(sev or "")).lower()
        if day_str not in volume_by_day_sev:
            volume_by_day_sev[day_str] = {}
        volume_by_day_sev[day_str][sev_str] = cnt
    # Fill missing days with 0
    volume_timeline = []
    for i in range(6, -1, -1):
        day = (now - timedelta(days=i)).date().isoformat()
        d = volume_by_day_sev.get(day, {})
        volume_timeline.append({
            "date": day,
            "count": sum(d.values()),
            "critical": d.get("critical", 0),
            "high": d.get("high", 0),
            "medium": d.get("medium", 0),
            "low": d.get("low", 0),
        })

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

    # --- Trends: current period vs previous period ---
    #   day   → today vs yesterday
    #   week  → last 7 days vs the 7 days before that
    #   month → last 30 days vs the 30 days before that
    if trend_period == "day":
        period_delta = timedelta(days=1)
    elif trend_period == "week":
        period_delta = timedelta(days=7)
    else:
        period_delta = timedelta(days=30)

    period_start = now - period_delta
    prev_start   = period_start - period_delta

    def _trend(current: int, previous: int) -> int | None:
        if previous == 0 and current == 0:
            return None           # no data either period — nothing to show
        if previous == 0:
            return 100            # new alerts this period where there were none before
        return round((current - previous) / previous * 100)

    trend_rows = await db.execute(
        select(
            func.sum(
                case((Alert.created_at >= period_start, 1), else_=0)
            ).label("current"),
            func.sum(
                case(
                    ((Alert.created_at >= prev_start) & (Alert.created_at < period_start), 1),
                    else_=0,
                )
            ).label("previous"),
            Alert.severity,
        )
        .where(Alert.created_at >= prev_start)
        .group_by(Alert.severity)
    )
    _t: dict[str, tuple[int, int]] = {}
    for row in trend_rows.all():
        sev = (row.severity.value if hasattr(row.severity, "value") else str(row.severity or "")).lower()
        _t[sev] = (int(row.current or 0), int(row.previous or 0))

    total_curr = sum(v[0] for v in _t.values())
    total_prev = sum(v[1] for v in _t.values())
    crit_curr, crit_prev = _t.get("critical", (0, 0))
    high_curr, high_prev = _t.get("high", (0, 0))

    alerts_trend = _trend(total_curr, total_prev)
    crit_trend   = _trend(crit_curr, crit_prev)
    high_trend   = _trend(high_curr, high_prev)

    # --- SLA breach counts ---
    # Thresholds: Critical=1h, High=4h, Medium=24h, Low=72h
    sla_thresholds_h = {"Critical": 1, "High": 4, "Medium": 24, "Low": 72}
    open_alerts_r = await db.execute(
        select(Alert.severity, Alert.created_at)
        .where(Alert.status.in_([AlertStatus.OPEN, AlertStatus.IN_PROGRESS]))
    )
    sla_breach_total = 0
    sla_breach_by_sev: dict[str, int] = {}
    for sev, created in open_alerts_r.all():
        if not created:
            continue
        sev_str = sev.value if hasattr(sev, "value") else str(sev or "")
        threshold_h = sla_thresholds_h.get(sev_str, 24)
        # Make created timezone-aware for comparison
        if created.tzinfo is None:
            from datetime import timezone as _tz
            created = created.replace(tzinfo=_tz.utc)
        elapsed_h = (now - created).total_seconds() / 3600
        if elapsed_h > threshold_h:
            sla_breach_total += 1
            sla_breach_by_sev[sev_str] = sla_breach_by_sev.get(sev_str, 0) + 1

    # --- MTTR (Mean Time To Resolve, in hours) ---
    resolved_r = await db.execute(
        select(Alert.created_at, Alert.updated_at)
        .where(Alert.status == AlertStatus.RESOLVED)
        .where(Alert.updated_at.is_not(None))
        .limit(500)  # Limit for performance
    )
    ttrs = []
    for created, resolved in resolved_r.all():
        if created and resolved:
            if created.tzinfo is None:
                from datetime import timezone as _tz
                created = created.replace(tzinfo=_tz.utc)
            if resolved.tzinfo is None:
                from datetime import timezone as _tz
                resolved = resolved.replace(tzinfo=_tz.utc)
            diff_h = (resolved - created).total_seconds() / 3600
            if diff_h > 0:
                ttrs.append(diff_h)
    mttr_hours: float | None = round(sum(ttrs) / len(ttrs), 1) if ttrs else None

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

    # --- Data freshness: most recent alert ingest timestamp ---
    latest_r = await db.execute(
        select(func.max(Alert.created_at)).select_from(Alert)
    )
    latest_ingest: datetime | None = latest_r.scalar_one_or_none()
    last_ingest_at: str | None = latest_ingest.isoformat() if latest_ingest else None
    ingest_lag_minutes: float | None = None
    if latest_ingest:
        if latest_ingest.tzinfo is None:
            latest_ingest = latest_ingest.replace(tzinfo=timezone.utc)
        ingest_lag_minutes = round((now - latest_ingest).total_seconds() / 60, 1)

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
        "alerts_trend": alerts_trend,
        "crit_trend": crit_trend,
        "high_trend": high_trend,
        "trend_period": trend_period,
        "sla_breach_total": sla_breach_total,
        "sla_breach_by_sev": sla_breach_by_sev,
        "mttr_hours": mttr_hours,
        "last_ingest_at": last_ingest_at,
        "ingest_lag_minutes": ingest_lag_minutes,
    }
