"""Compliance report endpoints (P4-3)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import ComplianceReportArtifact
from app.security.rbac import require_permission
from app.services.compliance import ALLOWED_FRAMEWORKS, build_compliance_artifact_bundle, build_compliance_report

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/reports/artifacts")
async def list_report_artifacts(
    _user: Annotated[dict, Depends(require_permission("audit:read"))],
    db: AsyncSession = Depends(get_db),
    limit: int = Query(25, ge=1, le=200),
):
    """List immutable signed export artifacts for reproducibility verification."""
    rows = (
        await db.execute(
            select(ComplianceReportArtifact)
            .order_by(ComplianceReportArtifact.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()

    return {
        "total": len(rows),
        "items": [
            {
                "report_id": r.report_id,
                "framework": r.framework,
                "period_days": r.period_days,
                "artifact_name": r.artifact_name,
                "report_checksum": r.report_checksum,
                "signature": r.signature,
                "created_by": r.created_by,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


@router.get("/reports/generate")
async def generate_report(
    _user: Annotated[dict, Depends(require_permission("audit:read"))],
    db: AsyncSession = Depends(get_db),
    framework: str = Query(..., description="soc2 | iso27001 | pci-dss"),
    days: int = Query(30, ge=1, le=365),
):
    fw = framework.lower()
    if fw not in ALLOWED_FRAMEWORKS:
        raise HTTPException(status_code=400, detail="Unsupported framework")
    return await build_compliance_report(db, fw, days)


@router.get("/reports/export")
async def export_report(
    user: Annotated[dict, Depends(require_permission("audit:read"))],
    db: AsyncSession = Depends(get_db),
    framework: str = Query(..., description="soc2 | iso27001 | pci-dss"),
    days: int = Query(30, ge=1, le=365),
):
    fw = framework.lower()
    if fw not in ALLOWED_FRAMEWORKS:
        raise HTTPException(status_code=400, detail="Unsupported framework")

    artifact = await build_compliance_artifact_bundle(
        db=db,
        framework=fw,
        days=days,
        created_by=str(user.get("sub")) if user.get("sub") else None,
    )
    return Response(
        content=artifact["bundle_bytes"],
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{artifact["bundle_name"]}"',
            "X-Report-Id": artifact["report_id"],
            "X-Report-Checksum": artifact["report_checksum"],
            "X-Report-Signature": artifact["signature"],
        },
    )
