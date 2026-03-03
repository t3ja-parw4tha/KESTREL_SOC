"""Serve Jinja2/HTMX dashboard pages."""

from datetime import datetime, timezone, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Alert, AlertDecision
from app.models.alert import AlertSeverity, AlertStatus
from app.core.mitre.techniques import TECHNIQUES
from app.api.mitre import TACTICS_LIST

try:
    from fastapi.templating import Jinja2Templates
except ImportError:
    from starlette.templating import Jinja2Templates

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES_DIR = ROOT / "frontend" / "templates"
if not TEMPLATES_DIR.exists():
    TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(tags=["pages"])


def _severity_color(severity: str) -> str:
    colors = {
        "Critical": "#ef4444",
        "High": "#f97316",
        "Medium": "#eab308",
        "Low": "#3b82f6",
    }
    return colors.get(severity, "#22c55e")


async def _dashboard_data(db: AsyncSession) -> dict:
    """Aggregate dashboard stats, recent alerts, incidents, and chart data."""
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)

    total_r = await db.execute(select(func.count()).select_from(Alert))
    total_alerts = total_r.scalar() or 0

    open_crit = await db.execute(
        select(func.count()).select_from(Alert).where(
            Alert.severity == AlertSeverity.CRITICAL, Alert.status == AlertStatus.OPEN
        )
    )
    open_high = await db.execute(
        select(func.count()).select_from(Alert).where(
            Alert.severity == AlertSeverity.HIGH, Alert.status == AlertStatus.OPEN
        )
    )
    open_critical = open_crit.scalar() or 0
    open_high_count = open_high.scalar() or 0

    inc_r = await db.execute(
        select(func.count(func.distinct(Alert.incident_group_id))).select_from(Alert).where(
            Alert.incident_group_id.is_not(None)
        )
    )
    incidents_count = inc_r.scalar() or 0

    sev_r = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.severity.is_not(None))
        .group_by(Alert.severity)
    )
    alerts_by_severity = {s.value if hasattr(s, "value") else str(s): c for s, c in sev_r.all()}

    vol_r = await db.execute(
        select(func.date(Alert.created_at).label("day"), func.count(Alert.id))
        .where(Alert.created_at >= seven_days_ago)
        .group_by(func.date(Alert.created_at))
    )
    volume_timeline = [{"date": str(d), "count": c} for d, c in vol_r.all()]

    src_r = await db.execute(
        select(Alert.source, func.count(Alert.id)).group_by(Alert.source)
    )
    alerts_by_source = [{"source": s, "count": c} for s, c in src_r.all()]

    recent_r = await db.execute(
        select(Alert).order_by(Alert.created_at.desc()).limit(10)
    )
    recent_alerts = recent_r.scalars().all()

    subq = (
        select(
            Alert.incident_group_id,
            func.count(Alert.id).label("cnt"),
            func.max(Alert.risk_score).label("max_score"),
        )
        .where(Alert.incident_group_id.is_not(None))
        .group_by(Alert.incident_group_id)
    )
    sub_r = await db.execute(subq)
    sub_rows = sub_r.all()
    incident_ids = [r.incident_group_id for r in sorted(sub_rows, key=lambda x: (x.max_score or 0), reverse=True)[:5]]
    active_incidents = []
    for gid in incident_ids:
        a_r = await db.execute(select(Alert).where(Alert.incident_group_id == gid).limit(1))
        first = a_r.scalar_one_or_none()
        if first:
            active_incidents.append({
                "incident_id": gid,
                "alert_count": next((r.cnt for r in sub_rows if r.incident_group_id == gid), 0),
                "max_risk_score": next((r.max_score for r in sub_rows if r.incident_group_id == gid), 0),
                "highest_severity": first.severity.value if first.severity else "",
            })

    tech_r = await db.execute(select(Alert.mitre_techniques).where(Alert.mitre_techniques.is_not(None)))
    tech_rows = tech_r.scalars().all()
    seen = set()
    for row in tech_rows:
        items = row if isinstance(row, list) else (row.get("items") or []) if isinstance(row, dict) else []
        for t in items:
            if isinstance(t, dict) and t.get("technique_id"):
                seen.add(t["technique_id"])
    coverage_pct = round(len(seen) / len(TECHNIQUES) * 100, 1) if TECHNIQUES else 0

    return {
        "total_alerts": total_alerts,
        "open_critical": open_critical,
        "open_high": open_high_count,
        "incidents_count": incidents_count,
        "coverage_pct": coverage_pct,
        "alerts_by_severity": alerts_by_severity,
        "volume_timeline": volume_timeline,
        "alerts_by_source": alerts_by_source,
        "recent_alerts": recent_alerts,
        "active_incidents": active_incidents,
        "severity_color": _severity_color,
    }


async def _header_stats(db: AsyncSession) -> dict:
    """Fetch open critical and high counts for base.html header."""
    crit_r = await db.execute(
        select(func.count()).select_from(Alert).where(
            Alert.severity == AlertSeverity.CRITICAL,
            Alert.status == AlertStatus.OPEN
        )
    )
    high_r = await db.execute(
        select(func.count()).select_from(Alert).where(
            Alert.severity == AlertSeverity.HIGH,
            Alert.status == AlertStatus.OPEN
        )
    )
    return {
        "open_critical": crit_r.scalar() or 0,
        "open_high": high_r.scalar() or 0,
    }


@router.get("/", response_class=HTMLResponse)
async def dashboard_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    data = await _dashboard_data(db)
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, **data},
    )


STATUS_MAP = {
    "open": AlertStatus.OPEN, "new": AlertStatus.OPEN, "in_progress": AlertStatus.IN_PROGRESS,
    "resolved": AlertStatus.RESOLVED, "false_positive": AlertStatus.FALSE_POSITIVE,
}


@router.get("/alerts", response_class=HTMLResponse)
async def alerts_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    stats = await _header_stats(db)
    return templates.TemplateResponse(
        "alerts.html",
        {"request": request, **stats},
    )


@router.get("/alerts/table", response_class=HTMLResponse)
async def alerts_table_fragment(
    request: Request,
    db: AsyncSession = Depends(get_db),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    source: str | None = Query(None),
    search: str | None = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    """HTMX: return table body HTML for alerts list."""
    q = select(Alert)
    count_q = select(func.count()).select_from(Alert)
    if severity:
        try:
            sev_enum = AlertSeverity(severity)
            q = q.where(Alert.severity == sev_enum)
            count_q = count_q.where(Alert.severity == sev_enum)
        except ValueError:
            pass
    if status:
        st = STATUS_MAP.get((status or "").lower(), AlertStatus.OPEN)
        q = q.where(Alert.status == st)
        count_q = count_q.where(Alert.status == st)
    if source:
        q = q.where(Alert.source == source)
        count_q = count_q.where(Alert.source == source)
    if search:
        q = q.where(Alert.title.ilike(f"%{search}%"))
        count_q = count_q.where(Alert.title.ilike(f"%{search}%"))
    total_r = await db.execute(count_q)
    total = total_r.scalar() or 0
    q = q.order_by(Alert.created_at.desc()).offset((page - 1) * limit).limit(limit)
    result = await db.execute(q)
    rows = result.scalars().all()
    return templates.TemplateResponse(
        "partials/alerts_table.html",
        {
            "request": request,
            "alerts": rows,
            "page": page,
            "limit": limit,
            "total": total,
            "severity_color": _severity_color,
        },
    )


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
async def alert_detail_page(
    request: Request,
    alert_id: str,
    db: AsyncSession = Depends(get_db),
):
    from fastapi import HTTPException
    r = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = r.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    dec_r = await db.execute(
        select(AlertDecision).where(AlertDecision.alert_id == alert_id).order_by(AlertDecision.generated_at.desc()).limit(1)
    )
    decision = dec_r.scalar_one_or_none()
    stats = await _header_stats(db)
    return templates.TemplateResponse(
        "alert_detail.html",
        {
            "request": request,
            "alert": alert,
            "decision": decision,
            "severity_color": _severity_color,
            **stats,
        },
    )


@router.get("/incidents", response_class=HTMLResponse)
async def incidents_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    subq = (
        select(
            Alert.incident_group_id,
            func.count(Alert.id).label("cnt"),
            func.max(Alert.risk_score).label("max_score"),
            func.max(Alert.severity).label("max_sev"),
        )
        .where(Alert.incident_group_id.is_not(None))
        .group_by(Alert.incident_group_id)
    )
    r = await db.execute(subq)
    rows = r.all()
    incidents = []
    for row in rows:
        a_r = await db.execute(select(Alert).where(Alert.incident_group_id == row.incident_group_id).limit(1))
        first = a_r.scalar_one_or_none()
        incidents.append({
            "incident_id": row.incident_group_id,
            "alert_count": row.cnt,
            "max_risk_score": row.max_score,
            "highest_severity": row.max_sev.value if hasattr(row.max_sev, "value") else str(row.max_sev or ""),
            "asset_id": first.asset_id if first else None,
        })
    incidents.sort(key=lambda x: (x["max_risk_score"] or 0), reverse=True)
    stats = await _header_stats(db)
    return templates.TemplateResponse(
        "incidents.html",
        {"request": request, "incidents": incidents, "severity_color": _severity_color, **stats},
    )


@router.get("/sources", response_class=HTMLResponse)
async def sources_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    stats = await _header_stats(db)
    return templates.TemplateResponse(
        "sources.html",
        {"request": request, **stats},
    )


@router.get("/incidents/{incident_id}", response_class=HTMLResponse)
async def incident_detail_page(
    request: Request,
    incident_id: str,
    db: AsyncSession = Depends(get_db),
):
    from fastapi import HTTPException
    r = await db.execute(select(Alert).where(Alert.incident_group_id == incident_id).order_by(Alert.created_at.asc()))
    alerts = r.scalars().all()
    if not alerts:
        raise HTTPException(status_code=404, detail="Incident not found")
    mitre_seen = {}
    for a in alerts:
        mt = a.mitre_techniques
        items = mt if isinstance(mt, list) else (mt.get("items") or []) if isinstance(mt, dict) else []
        for t in items:
            if isinstance(t, dict) and t.get("technique_id"):
                mitre_seen[t["technique_id"]] = t
    stats = await _header_stats(db)
    return templates.TemplateResponse(
        "incident_detail.html",
        {
            "request": request,
            "incident_id": incident_id,
            "alerts": alerts,
            "mitre_techniques": list(mitre_seen.values()),
            "severity_color": _severity_color,
            **stats,
        },
    )


@router.get("/mitre", response_class=HTMLResponse)
async def mitre_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    technique_counts = {}
    result = await db.execute(select(Alert.mitre_techniques).where(Alert.mitre_techniques.is_not(None)))
    for row in result.scalars().all():
        items = row if isinstance(row, list) else (row.get("items") or []) if isinstance(row, dict) else []
        for t in items:
            if isinstance(t, dict) and t.get("technique_id"):
                tid = t["technique_id"]
                technique_counts[tid] = technique_counts.get(tid, 0) + 1
    tactic_techniques = {}
    for t in TACTICS_LIST:
        tactic_techniques[t["id"]] = {"id": t["id"], "name": t["name"], "techniques": []}
    for tid, entry in TECHNIQUES.items():
        tactic_id = next((t["id"] for t in TACTICS_LIST if t["name"] == entry["tactic"]), "TA0000")
        if tactic_id in tactic_techniques:
            tactic_techniques[tactic_id]["techniques"].append({
                "id": tid, "name": entry["name"], "alert_count": technique_counts.get(tid, 0)
            })
    tactics_out = list(tactic_techniques.values())
    detected = sum(1 for c in technique_counts.values() if c > 0)
    coverage_pct = round(detected / len(TECHNIQUES) * 100, 1) if TECHNIQUES else 0
    stats = await _header_stats(db)
    return templates.TemplateResponse(
        "mitre.html",
        {
            "request": request,
            "tactics": tactics_out,
            "summary": {"techniques_detected": detected, "total_techniques": len(TECHNIQUES), "coverage_percentage": coverage_pct},
            "severity_color": _severity_color,
            **stats,
        },
    )
