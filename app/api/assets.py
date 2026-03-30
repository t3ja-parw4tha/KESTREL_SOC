"""Asset inventory (CMDB) API endpoints."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Alert, Asset, Incident
from app.models.alert import AlertStatus
from app.models.incident import IncidentStatus
from app.security.csrf import verify_csrf
from app.security.rbac import require_permission

router = APIRouter(prefix="/assets", tags=["assets"])

_CRITICALITY_VALUES = {"low", "medium", "high", "critical"}


class AssetListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    asset_id: str
    hostname: str | None
    ip_address: str | None
    asset_type: str | None
    owner: str | None
    department: str | None
    criticality: str
    risk_score: float | None
    open_alerts: int
    open_incidents: int
    last_alert_at: datetime | None
    updated_at: datetime | None
    confidence_score: float | None = None
    last_enriched_at: datetime | None = None


class AssetListResponse(BaseModel):
    items: list[AssetListItem]
    total: int
    page: int
    limit: int


class AssetDetailResponse(AssetListItem):
    id: int
    os: str | None
    tags: list[str]
    notes: str | None
    created_at: datetime | None
    created_by: str | None


class AssetCreateRequest(BaseModel):
    asset_id: str = Field(min_length=2, max_length=256)
    hostname: str | None = Field(default=None, max_length=256)
    ip_address: str | None = Field(default=None, max_length=64)
    asset_type: str | None = Field(default=None, max_length=64)
    os: str | None = Field(default=None, max_length=128)
    owner: str | None = Field(default=None, max_length=256)
    department: str | None = Field(default=None, max_length=256)
    criticality: str = Field(default="medium")
    risk_score: float | None = Field(default=None, ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    notes: str | None = Field(default=None, max_length=2048)


class AssetUpdateRequest(BaseModel):
    hostname: str | None = Field(default=None, max_length=256)
    ip_address: str | None = Field(default=None, max_length=64)
    asset_type: str | None = Field(default=None, max_length=64)
    os: str | None = Field(default=None, max_length=128)
    owner: str | None = Field(default=None, max_length=256)
    department: str | None = Field(default=None, max_length=256)
    criticality: str | None = None
    risk_score: float | None = Field(default=None, ge=0, le=100)
    tags: list[str] | None = None
    notes: str | None = Field(default=None, max_length=2048)


def _normalize_criticality(value: str) -> str:
    normalized = (value or "medium").strip().lower()
    if normalized not in _CRITICALITY_VALUES:
        raise HTTPException(
            status_code=400,
            detail="criticality must be one of: low, medium, high, critical",
        )
    return normalized


async def _build_alert_agg(db: AsyncSession) -> dict[str, dict]:
    stmt = (
        select(
            Alert.asset_id,
            func.count(Alert.id).label("open_alerts"),
            func.max(Alert.created_at).label("last_alert_at"),
            func.max(func.coalesce(Alert.risk_score, 0)).label("max_alert_risk"),
        )
        .where(
            Alert.asset_id.is_not(None),
            Alert.status.notin_([AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]),
        )
        .group_by(Alert.asset_id)
    )
    rows = (await db.execute(stmt)).all()
    out: dict[str, dict] = {}
    for row in rows:
        if not row.asset_id:
            continue
        out[row.asset_id] = {
            "open_alerts": int(row.open_alerts or 0),
            "last_alert_at": row.last_alert_at,
            "max_alert_risk": float(row.max_alert_risk or 0),
        }
    return out


async def _build_incident_agg(db: AsyncSession) -> dict[str, int]:
    stmt = (
        select(Incident.asset_id, func.count(Incident.id).label("open_incidents"))
        .where(
            Incident.asset_id.is_not(None),
            Incident.status != IncidentStatus.RESOLVED,
        )
        .group_by(Incident.asset_id)
    )
    rows = (await db.execute(stmt)).all()
    out: dict[str, int] = {}
    for row in rows:
        if row.asset_id:
            out[row.asset_id] = int(row.open_incidents or 0)
    return out


def _asset_to_detail(
    asset: Asset,
    alert_agg: dict[str, dict],
    incident_agg: dict[str, int],
) -> AssetDetailResponse:
    agg = alert_agg.get(asset.asset_id, {})
    max_alert_risk = float(agg.get("max_alert_risk", 0))
    effective_risk = asset.risk_score if asset.risk_score is not None else max_alert_risk
    tags = asset.tags if isinstance(asset.tags, list) else []
    return AssetDetailResponse(
        id=asset.id,
        asset_id=asset.asset_id,
        hostname=asset.hostname,
        ip_address=asset.ip_address,
        asset_type=asset.asset_type,
        os=asset.os,
        owner=asset.owner,
        department=asset.department,
        criticality=asset.criticality,
        risk_score=effective_risk,
        open_alerts=int(agg.get("open_alerts", 0)),
        open_incidents=int(incident_agg.get(asset.asset_id, 0)),
        last_alert_at=agg.get("last_alert_at"),
        updated_at=asset.updated_at,
        confidence_score=asset.confidence_score,
        last_enriched_at=asset.last_enriched_at,
        tags=[str(t) for t in tags if isinstance(t, str)],
        notes=asset.notes,
        created_at=asset.created_at,
        created_by=asset.created_by,
    )


@router.get("", response_model=AssetListResponse)
async def list_assets(
    _user: Annotated[dict, Depends(require_permission("assets:read"))],
    db: AsyncSession = Depends(get_db),
    search: str | None = Query(None),
    owner: str | None = Query(None),
    criticality: str | None = Query(None),
    min_risk: float | None = Query(None, ge=0, le=100),
    max_risk: float | None = Query(None, ge=0, le=100),
    sort_by: str = Query("updated_at"),
    sort_dir: str = Query("desc"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
) -> AssetListResponse:
    """List assets with optional search, risk filtering, and pagination."""
    q = select(Asset)

    if search:
        term = f"%{search}%"
        q = q.where(
            or_(
                Asset.asset_id.ilike(term),
                Asset.hostname.ilike(term),
                Asset.ip_address.ilike(term),
                Asset.owner.ilike(term),
            )
        )
    if owner:
        q = q.where(Asset.owner.ilike(f"%{owner}%"))
    if criticality:
        q = q.where(Asset.criticality == _normalize_criticality(criticality))

    sort_key = sort_by.strip().lower()
    is_desc = sort_dir.strip().lower() != "asc"
    if sort_key == "asset_id":
        q = q.order_by(Asset.asset_id.desc() if is_desc else Asset.asset_id.asc())
    elif sort_key == "hostname":
        q = q.order_by(Asset.hostname.desc() if is_desc else Asset.hostname.asc())
    else:
        q = q.order_by(Asset.updated_at.desc() if is_desc else Asset.updated_at.asc())

    assets = (await db.execute(q)).scalars().all()
    alert_agg = await _build_alert_agg(db)
    incident_agg = await _build_incident_agg(db)
    items = [_asset_to_detail(a, alert_agg, incident_agg) for a in assets]

    if min_risk is not None:
        items = [i for i in items if (i.risk_score or 0) >= min_risk]
    if max_risk is not None:
        items = [i for i in items if (i.risk_score or 0) <= max_risk]
    if sort_key == "risk_score":
        items.sort(key=lambda i: (i.risk_score or 0), reverse=is_desc)

    total = len(items)
    start = (page - 1) * limit
    end = start + limit

    return AssetListResponse(
        items=[AssetListItem.model_validate(i.model_dump()) for i in items[start:end]],
        total=total,
        page=page,
        limit=limit,
    )


@router.get("/{asset_id}", response_model=AssetDetailResponse)
async def get_asset(
    asset_id: str,
    _user: Annotated[dict, Depends(require_permission("assets:read"))],
    db: AsyncSession = Depends(get_db),
) -> AssetDetailResponse:
    """Get a single asset by asset_id."""
    asset = (
        await db.execute(select(Asset).where(Asset.asset_id == asset_id))
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    alert_agg = await _build_alert_agg(db)
    incident_agg = await _build_incident_agg(db)
    return _asset_to_detail(asset, alert_agg, incident_agg)


@router.post("", response_model=AssetDetailResponse, status_code=201)
async def create_asset(
    body: AssetCreateRequest,
    user: Annotated[dict, Depends(require_permission("assets:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> AssetDetailResponse:
    """Create a new CMDB asset entry."""
    existing = (
        await db.execute(select(Asset).where(Asset.asset_id == body.asset_id.strip()))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Asset already exists")

    asset = Asset(
        asset_id=body.asset_id.strip(),
        hostname=body.hostname,
        ip_address=body.ip_address,
        asset_type=body.asset_type,
        os=body.os,
        owner=body.owner,
        department=body.department,
        criticality=_normalize_criticality(body.criticality),
        risk_score=body.risk_score,
        tags=body.tags,
        notes=body.notes,
        created_by=str(user.get("sub")) if user.get("sub") else None,
    )
    db.add(asset)
    await db.flush()
    await db.refresh(asset)

    alert_agg = await _build_alert_agg(db)
    incident_agg = await _build_incident_agg(db)
    return _asset_to_detail(asset, alert_agg, incident_agg)


@router.patch("/{asset_id}", response_model=AssetDetailResponse)
async def update_asset(
    asset_id: str,
    body: AssetUpdateRequest,
    _user: Annotated[dict, Depends(require_permission("assets:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> AssetDetailResponse:
    """Update mutable asset metadata."""
    asset = (
        await db.execute(select(Asset).where(Asset.asset_id == asset_id))
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    update_data = body.model_dump(exclude_unset=True)
    if "criticality" in update_data and update_data["criticality"] is not None:
        update_data["criticality"] = _normalize_criticality(str(update_data["criticality"]))

    for k, v in update_data.items():
        setattr(asset, k, v)

    await db.flush()
    await db.refresh(asset)
    alert_agg = await _build_alert_agg(db)
    incident_agg = await _build_incident_agg(db)
    return _asset_to_detail(asset, alert_agg, incident_agg)


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(
    asset_id: str,
    _user: Annotated[dict, Depends(require_permission("assets:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete an asset from the CMDB."""
    asset = (
        await db.execute(select(Asset).where(Asset.asset_id == asset_id))
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    await db.delete(asset)
    await db.flush()


@router.post("/{asset_id}/enrich", response_model=AssetDetailResponse)
async def enrich_asset(
    asset_id: str,
    _user: Annotated[dict, Depends(require_permission("assets:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> AssetDetailResponse:
    """Recompute confidence score from recent alert telemetry and stamp last_enriched_at."""
    from datetime import timezone as _tz
    asset = (
        await db.execute(select(Asset).where(Asset.asset_id == asset_id))
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    alert_agg = await _build_alert_agg(db)
    agg = alert_agg.get(asset_id, {})
    open_alerts = int(agg.get("open_alerts", 0))
    max_risk = float(agg.get("max_alert_risk", 0))

    # Confidence: penalise assets with no alerts (unknown) or very high risk
    # Range: 0.0 (unknown/high-risk) to 1.0 (well-monitored, low-risk)
    if open_alerts == 0 and max_risk == 0:
        confidence = 0.5  # no telemetry — uncertain
    else:
        # More alerts = better monitored; risk reduces confidence in asset posture
        monitoring_score = min(1.0, open_alerts / 10)
        risk_penalty = max_risk / 100
        confidence = round(max(0.0, min(1.0, monitoring_score - risk_penalty * 0.5)), 2)

    asset.confidence_score = confidence
    asset.last_enriched_at = datetime.now(_tz.utc)
    await db.flush()
    await db.refresh(asset)

    incident_agg = await _build_incident_agg(db)
    return _asset_to_detail(asset, alert_agg, incident_agg)
