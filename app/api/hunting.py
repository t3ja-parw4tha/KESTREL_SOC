"""Threat hunting workspace API (P5-6)."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Alert, HuntQueryRecord, HuntResultRecord
from app.security.csrf import verify_csrf
from app.security.rbac import require_permission

router = APIRouter(prefix="/hunting", tags=["hunting"])


class HuntQueryCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=1024)
    query: str = Field(min_length=3)
    type: str = Field(default="kql")


class HuntQueryResponse(BaseModel):
    id: str
    name: str
    description: str
    query: str
    type: str
    created_by: str | None
    created_at: str | None
    last_run: str | None
    results_count: int
    status: str


class HuntResultResponse(BaseModel):
    id: str
    timestamp: str
    source: str
    host: str
    event_type: str
    details: str
    risk_score: int
    alert_id: str | None = None


def _scope_from_request(request: Request) -> tuple[str, str]:
    org_id = request.headers.get("x-org-id", "default")
    workspace_id = request.headers.get("x-workspace-id", "default")
    return org_id.strip() or "default", workspace_id.strip() or "default"


def _serialize_query(row: HuntQueryRecord) -> HuntQueryResponse:
    return HuntQueryResponse(
        id=row.id,
        name=row.name,
        description=row.description or "",
        query=row.query,
        type=row.query_type,
        created_by=row.created_by,
        created_at=row.created_at.isoformat() if row.created_at else None,
        last_run=row.last_run.isoformat() if row.last_run else None,
        results_count=int(row.results_count or 0),
        status=row.last_status or "saved",
    )


def _serialize_result(row: HuntResultRecord) -> HuntResultResponse:
    return HuntResultResponse(
        id=row.id,
        timestamp=row.timestamp.isoformat() if row.timestamp else datetime.now(timezone.utc).isoformat(),
        source=row.source or "unknown",
        host=row.host or "unknown",
        event_type=row.event_type or "match",
        details=row.details,
        risk_score=int(row.risk_score or 0),
        alert_id=row.alert_id,
    )


@router.get("/queries", response_model=list[HuntQueryResponse])
async def list_hunts(
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    org_id, workspace_id = _scope_from_request(request)
    rows = (
        await db.execute(
            select(HuntQueryRecord)
            .where(
                HuntQueryRecord.org_id == org_id,
                HuntQueryRecord.workspace_id == workspace_id,
                HuntQueryRecord.is_active.is_(True),
            )
            .order_by(HuntQueryRecord.updated_at.desc())
        )
    ).scalars().all()
    return [_serialize_query(r) for r in rows]


@router.get("/queries/{hunt_id}", response_model=HuntQueryResponse)
async def get_hunt(
    hunt_id: str,
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    org_id, workspace_id = _scope_from_request(request)
    row = (
        await db.execute(
            select(HuntQueryRecord).where(
                HuntQueryRecord.id == hunt_id,
                HuntQueryRecord.org_id == org_id,
                HuntQueryRecord.workspace_id == workspace_id,
                HuntQueryRecord.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return _serialize_query(row)


@router.post("/queries", response_model=HuntQueryResponse, status_code=201)
async def create_hunt(
    body: HuntQueryCreate,
    user: Annotated[dict, Depends(require_permission("alerts:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    org_id, workspace_id = _scope_from_request(request)
    row = HuntQueryRecord(
        id=f"HUNT-{uuid.uuid4().hex[:8].upper()}",
        name=body.name.strip(),
        description=body.description.strip() or None,
        query=body.query,
        query_type=body.type,
        created_by=str(user.get("sub")) if user.get("sub") else None,
        org_id=org_id,
        workspace_id=workspace_id,
        last_status="saved",
    )
    db.add(row)
    await db.flush()
    await db.refresh(row)
    return _serialize_query(row)


def _tokenize_query(query: str) -> list[str]:
    tokens = re.findall(r"[a-zA-Z0-9_\.-]+", query.lower())
    return [t for t in tokens if len(t) >= 4 and t not in {"where", "project", "select", "from", "and", "or"}][:30]


@router.post("/queries/{hunt_id}/run")
async def run_hunt(
    hunt_id: str,
    _user: Annotated[dict, Depends(require_permission("alerts:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    org_id, workspace_id = _scope_from_request(request)
    row = (
        await db.execute(
            select(HuntQueryRecord).where(
                HuntQueryRecord.id == hunt_id,
                HuntQueryRecord.org_id == org_id,
                HuntQueryRecord.workspace_id == workspace_id,
                HuntQueryRecord.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Hunt not found")

    row.last_status = "running"
    row.last_run = datetime.now(timezone.utc)
    await db.flush()

    terms = _tokenize_query(row.query)
    alerts = (
        await db.execute(select(Alert).order_by(Alert.created_at.desc()).limit(300))
    ).scalars().all()

    await db.execute(delete(HuntResultRecord).where(HuntResultRecord.hunt_id == row.id))

    matches: list[HuntResultRecord] = []
    for alert in alerts:
        blob = " ".join(
            [
                (alert.title or ""),
                (alert.category or ""),
                (alert.source or ""),
                json.dumps(alert.raw or {}, default=str),
            ]
        ).lower()
        score = sum(1 for t in terms if t in blob)
        if score <= 0:
            continue
        result = HuntResultRecord(
            id=f"R-{uuid.uuid4().hex[:8].upper()}",
            hunt_id=row.id,
            alert_id=alert.id,
            source=alert.source,
            host=alert.asset_id or alert.user_id or "unknown",
            event_type=alert.category,
            details=f"Matched {score} query term(s) on alert {alert.id}: {alert.title[:120]}",
            risk_score=min(100, max(5, int((alert.risk_score or 20) + score * 5))),
            org_id=org_id,
            workspace_id=workspace_id,
        )
        matches.append(result)

    for item in matches[:200]:
        db.add(item)

    row.results_count = len(matches)
    row.last_status = "completed"
    timeline = row.notebook_timeline if isinstance(row.notebook_timeline, list) else []
    timeline.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": "run",
            "results_count": len(matches),
        }
    )
    row.notebook_timeline = timeline[-50:]
    await db.flush()

    return {"results": [_serialize_result(r).model_dump() for r in matches[:200]]}


@router.get("/queries/{hunt_id}/results", response_model=list[HuntResultResponse])
async def get_hunt_results(
    hunt_id: str,
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    org_id, workspace_id = _scope_from_request(request)
    rows = (
        await db.execute(
            select(HuntResultRecord)
            .where(
                HuntResultRecord.hunt_id == hunt_id,
                HuntResultRecord.org_id == org_id,
                HuntResultRecord.workspace_id == workspace_id,
            )
            .order_by(HuntResultRecord.timestamp.desc())
        )
    ).scalars().all()
    return [_serialize_result(r) for r in rows]


@router.delete("/queries/{hunt_id}", status_code=204)
async def delete_hunt(
    hunt_id: str,
    _user: Annotated[dict, Depends(require_permission("alerts:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Soft-delete a saved hunt query."""
    org_id, workspace_id = _scope_from_request(request)
    row = (
        await db.execute(
            select(HuntQueryRecord).where(
                HuntQueryRecord.id == hunt_id,
                HuntQueryRecord.org_id == org_id,
                HuntQueryRecord.workspace_id == workspace_id,
                HuntQueryRecord.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Hunt not found")
    row.is_active = False
    await db.commit()


@router.get("/queries/{hunt_id}/pivot-alerts")
async def pivot_hunt_to_alerts(
    hunt_id: str,
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    org_id, workspace_id = _scope_from_request(request)
    rows = (
        await db.execute(
            select(HuntResultRecord)
            .where(
                HuntResultRecord.hunt_id == hunt_id,
                HuntResultRecord.org_id == org_id,
                HuntResultRecord.workspace_id == workspace_id,
                HuntResultRecord.alert_id.is_not(None),
            )
            .order_by(HuntResultRecord.risk_score.desc())
            .limit(100)
        )
    ).scalars().all()
    return {"alert_ids": [r.alert_id for r in rows if r.alert_id], "count": len(rows)}
