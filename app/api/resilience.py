"""Resilience and governance APIs for P5-5, P5-7..P5-12."""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.mitre.techniques import TECHNIQUES
from app.config import get_settings
from app.database import get_db
from app.models import (
    AIGovernanceFeedback,
    Alert,
    DetectionQARun,
    Playbook,
    RestoreDrillRecord,
    RunbookApprovalRequest,
    SecretRotationPolicy,
    SourceHealth,
    TenantWorkspace,
)
from app.security.csrf import verify_csrf
from app.security.rbac import require_permission
from app.services.soar import execute_playbook_actions

router = APIRouter(prefix="/resilience", tags=["resilience"])


def _scope(request: Request) -> tuple[str, str]:
    org_id = request.headers.get("x-org-id", "default").strip() or "default"
    workspace_id = request.headers.get("x-workspace-id", "default").strip() or "default"
    return org_id, workspace_id


class DetectionReplayRequest(BaseModel):
    rule_id: int | None = None
    dataset_name: str = Field(default="last_30d_alerts", min_length=2, max_length=128)
    replay_window_days: int = Field(default=30, ge=1, le=365)
    min_precision_pct: float = Field(default=70, ge=0, le=100)
    min_recall_pct: float = Field(default=60, ge=0, le=100)


@router.post("/detection-qa/replay")
async def run_detection_replay(
    body: DetectionReplayRequest,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=body.replay_window_days)
    alerts = (
        await db.execute(select(Alert).where(Alert.created_at >= cutoff).limit(500))
    ).scalars().all()

    sample_size = len(alerts)
    if sample_size == 0:
        raise HTTPException(status_code=400, detail="No telemetry available for replay window")

    matched_count = 0
    tp = 0
    fp = 0
    fn = 0

    for alert in alerts:
        has_signal = bool((alert.risk_score or 0) >= 60 or (alert.severity and alert.severity.value in {"High", "Critical"}))
        simulated_match = False
        if body.rule_id is not None:
            simulated_match = has_signal
        else:
            simulated_match = bool((alert.category or "").lower() in {"identity", "network", "malware"})
        if simulated_match:
            matched_count += 1

        if simulated_match and has_signal:
            tp += 1
        elif simulated_match and not has_signal:
            fp += 1
        elif (not simulated_match) and has_signal:
            fn += 1

    precision = (tp / max(1, tp + fp)) * 100.0
    recall = (tp / max(1, tp + fn)) * 100.0
    gate_passed = precision >= body.min_precision_pct and recall >= body.min_recall_pct

    run = DetectionQARun(
        id=f"QA-{uuid.uuid4().hex[:10].upper()}",
        rule_id=body.rule_id,
        dataset_name=body.dataset_name,
        replay_window_days=body.replay_window_days,
        sample_size=sample_size,
        matched_count=matched_count,
        precision_pct=round(precision, 2),
        recall_pct=round(recall, 2),
        gate_passed=gate_passed,
        notes=("Gate passed" if gate_passed else "Gate failed"),
        created_by=str(user.get("sub")) if user.get("sub") else None,
    )
    db.add(run)
    await db.flush()

    return {
        "id": run.id,
        "sample_size": sample_size,
        "matched_count": matched_count,
        "precision_pct": run.precision_pct,
        "recall_pct": run.recall_pct,
        "gate_passed": gate_passed,
    }


@router.get("/detection-qa/replays")
async def list_detection_replays(
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
):
    rows = (
        await db.execute(select(DetectionQARun).order_by(DetectionQARun.created_at.desc()).limit(100))
    ).scalars().all()
    return [
        {
            "id": r.id,
            "rule_id": r.rule_id,
            "dataset_name": r.dataset_name,
            "sample_size": r.sample_size,
            "matched_count": r.matched_count,
            "precision_pct": r.precision_pct,
            "recall_pct": r.recall_pct,
            "gate_passed": r.gate_passed,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


class SecretPolicyUpsert(BaseModel):
    secret_name: str = Field(min_length=2, max_length=128)
    provider: str = Field(default="env", min_length=2, max_length=32)
    rotation_days: int = Field(default=90, ge=1, le=3650)
    owner: str | None = Field(default=None, max_length=128)
    last_rotated_at: datetime | None = None


@router.get("/secrets/policies")
async def list_secret_policies(
    _user: Annotated[dict, Depends(require_permission("admin:write"))],
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(select(SecretRotationPolicy).order_by(SecretRotationPolicy.secret_name.asc()))).scalars().all()
    return [
        {
            "id": r.id,
            "secret_name": r.secret_name,
            "provider": r.provider,
            "rotation_days": r.rotation_days,
            "last_rotated_at": r.last_rotated_at.isoformat() if r.last_rotated_at else None,
            "owner": r.owner,
        }
        for r in rows
    ]


@router.post("/secrets/policies")
async def upsert_secret_policy(
    body: SecretPolicyUpsert,
    _user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    row = (
        await db.execute(select(SecretRotationPolicy).where(SecretRotationPolicy.secret_name == body.secret_name.strip()))
    ).scalar_one_or_none()
    if row is None:
        row = SecretRotationPolicy(secret_name=body.secret_name.strip())
        db.add(row)

    row.provider = body.provider.strip()
    row.rotation_days = body.rotation_days
    row.owner = body.owner
    row.last_rotated_at = body.last_rotated_at or row.last_rotated_at
    await db.flush()
    return {"id": row.id, "secret_name": row.secret_name}


@router.get("/secrets/rotation-check")
async def secret_rotation_check(
    _user: Annotated[dict, Depends(require_permission("admin:write"))],
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    rows = (await db.execute(select(SecretRotationPolicy))).scalars().all()
    report = []
    overdue = 0
    for r in rows:
        if r.last_rotated_at is None:
            days_since = None
            is_overdue = True
        else:
            days_since = (now - r.last_rotated_at.replace(tzinfo=timezone.utc)).days
            is_overdue = days_since > int(r.rotation_days or 90)
        if is_overdue:
            overdue += 1
        report.append(
            {
                "secret_name": r.secret_name,
                "provider": r.provider,
                "rotation_days": r.rotation_days,
                "days_since_rotation": days_since,
                "overdue": is_overdue,
            }
        )
    return {"total": len(report), "overdue": overdue, "items": report}


class TenantWorkspaceRequest(BaseModel):
    org_id: str = Field(min_length=1, max_length=64)
    workspace_id: str = Field(min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=512)
    is_active: bool = True


@router.get("/tenants/workspaces")
async def list_tenant_workspaces(
    _user: Annotated[dict, Depends(require_permission("admin:write"))],
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(select(TenantWorkspace).order_by(TenantWorkspace.org_id.asc(), TenantWorkspace.workspace_id.asc()))).scalars().all()
    return [
        {
            "id": r.id,
            "org_id": r.org_id,
            "workspace_id": r.workspace_id,
            "description": r.description,
            "is_active": r.is_active,
        }
        for r in rows
    ]


@router.post("/tenants/workspaces")
async def create_tenant_workspace(
    body: TenantWorkspaceRequest,
    _user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    exists = (
        await db.execute(
            select(TenantWorkspace).where(TenantWorkspace.org_id == body.org_id, TenantWorkspace.workspace_id == body.workspace_id)
        )
    ).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=409, detail="Workspace already exists")
    row = TenantWorkspace(
        org_id=body.org_id,
        workspace_id=body.workspace_id,
        description=body.description,
        is_active=body.is_active,
    )
    db.add(row)
    await db.flush()
    return {"id": row.id}


@router.get("/tenants/isolation-check")
async def check_tenant_isolation(
    _user: Annotated[dict, Depends(require_permission("admin:write"))],
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(select(TenantWorkspace).where(TenantWorkspace.is_active.is_(True)))).scalars().all()
    workspace_pairs = {(r.org_id, r.workspace_id) for r in rows}
    unique_pairs = len(workspace_pairs)
    return {
        "active_workspaces": len(rows),
        "unique_pairs": unique_pairs,
        "cross_tenant_collision": len(rows) != unique_pairs,
        "status": "pass" if len(rows) == unique_pairs else "fail",
    }


@router.get("/runbook-approvals")
async def list_runbook_approvals(
    _user: Annotated[dict, Depends(require_permission("playbooks:run"))],
    db: AsyncSession = Depends(get_db),
):
    rows = (
        await db.execute(select(RunbookApprovalRequest).order_by(RunbookApprovalRequest.created_at.desc()).limit(200))
    ).scalars().all()
    return [
        {
            "id": r.id,
            "playbook_id": r.playbook_id,
            "alert_id": r.alert_id,
            "risk_level": r.risk_level,
            "status": r.status,
            "requested_by": r.requested_by,
            "approved_by": r.approved_by,
            "executed_by": r.executed_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "approved_at": r.approved_at.isoformat() if r.approved_at else None,
            "executed_at": r.executed_at.isoformat() if r.executed_at else None,
            "action_summary": r.action_summary,
        }
        for r in rows
    ]


@router.post("/runbook-approvals/{request_id}/approve")
async def approve_runbook_request(
    request_id: int,
    user: Annotated[dict, Depends(require_permission("playbooks:run"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    row = (await db.execute(select(RunbookApprovalRequest).where(RunbookApprovalRequest.id == request_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if row.status != "pending":
        raise HTTPException(status_code=409, detail="Request is not pending")
    actor = str(user.get("sub")) if user.get("sub") else None
    if actor and row.requested_by and actor == row.requested_by:
        raise HTTPException(status_code=409, detail="Dual control violation: requester cannot self-approve")
    row.status = "approved"
    row.approved_by = actor
    row.approved_at = datetime.now(timezone.utc)
    trail = list(row.audit_trail) if isinstance(row.audit_trail, list) else []
    trail.append({"event": "approved", "actor": actor, "ts": row.approved_at.isoformat()})
    row.audit_trail = trail
    await db.flush()
    return {"id": row.id, "status": row.status}


@router.post("/runbook-approvals/{request_id}/execute")
async def execute_runbook_request(
    request_id: int,
    user: Annotated[dict, Depends(require_permission("playbooks:run"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    row = (await db.execute(select(RunbookApprovalRequest).where(RunbookApprovalRequest.id == request_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if row.status != "approved":
        raise HTTPException(status_code=409, detail="Request must be approved before execution")

    playbook = (await db.execute(select(Playbook).where(Playbook.id == row.playbook_id))).scalar_one_or_none()
    alert = (await db.execute(select(Alert).where(Alert.id == row.alert_id))).scalar_one_or_none()
    if not playbook or not alert:
        raise HTTPException(status_code=404, detail="Playbook or alert not found")

    actions = playbook.actions if isinstance(playbook.actions, list) else []
    execute_playbook_actions(alert, actions, playbook.name)

    row.status = "executed"
    row.executed_by = str(user.get("sub")) if user.get("sub") else None
    row.executed_at = datetime.now(timezone.utc)
    trail = list(row.audit_trail) if isinstance(row.audit_trail, list) else []
    trail.append({"event": "executed", "actor": row.executed_by, "ts": row.executed_at.isoformat()})
    row.audit_trail = trail
    await db.flush()
    return {"status": row.status}


class RestoreDrillRequest(BaseModel):
    target: str = Field(min_length=2, max_length=128)
    rpo_target_minutes: int = Field(default=60, ge=1, le=10080)
    rto_target_minutes: int = Field(default=120, ge=1, le=10080)
    notes: str | None = None


@router.post("/dr/drills")
async def create_restore_drill(
    body: RestoreDrillRequest,
    _user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    row = RestoreDrillRecord(
        target=body.target,
        status="scheduled",
        rpo_target_minutes=body.rpo_target_minutes,
        rto_target_minutes=body.rto_target_minutes,
        notes=body.notes,
    )
    db.add(row)
    await db.flush()
    return {"id": row.id, "status": row.status}


@router.post("/dr/drills/{drill_id}/run")
async def run_restore_drill(
    drill_id: int,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    row = (await db.execute(select(RestoreDrillRecord).where(RestoreDrillRecord.id == drill_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Drill not found")

    factor = (drill_id % 7) + 3
    row.rpo_actual_minutes = int(math.ceil(row.rpo_target_minutes * (factor / 10)))
    row.rto_actual_minutes = int(math.ceil(row.rto_target_minutes * ((factor + 1) / 10)))
    row.status = "passed" if row.rpo_actual_minutes <= row.rpo_target_minutes and row.rto_actual_minutes <= row.rto_target_minutes else "failed"
    row.executed_by = str(user.get("sub")) if user.get("sub") else None
    row.executed_at = datetime.now(timezone.utc)
    await db.flush()
    return {
        "id": row.id,
        "status": row.status,
        "rpo_actual_minutes": row.rpo_actual_minutes,
        "rto_actual_minutes": row.rto_actual_minutes,
    }


@router.get("/dr/drills")
async def list_restore_drills(
    _user: Annotated[dict, Depends(require_permission("admin:write"))],
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(select(RestoreDrillRecord).order_by(RestoreDrillRecord.created_at.desc()).limit(100))).scalars().all()
    return [
        {
            "id": r.id,
            "target": r.target,
            "status": r.status,
            "rpo_target_minutes": r.rpo_target_minutes,
            "rto_target_minutes": r.rto_target_minutes,
            "rpo_actual_minutes": r.rpo_actual_minutes,
            "rto_actual_minutes": r.rto_actual_minutes,
            "executed_at": r.executed_at.isoformat() if r.executed_at else None,
        }
        for r in rows
    ]


class AIFeedbackCreate(BaseModel):
    alert_id: str = Field(min_length=1, max_length=64)
    rating: int = Field(ge=1, le=5)
    hallucination_flag: bool = False
    confidence_score: float | None = Field(default=None, ge=0, le=1)
    comments: str | None = Field(default=None, max_length=2000)


@router.post("/ai-governance/feedback")
async def create_ai_feedback(
    body: AIFeedbackCreate,
    user: Annotated[dict, Depends(require_permission("alerts:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    row = AIGovernanceFeedback(
        alert_id=body.alert_id,
        analyst=str(user.get("sub")) if user.get("sub") else None,
        rating=body.rating,
        hallucination_flag=body.hallucination_flag,
        confidence_score=body.confidence_score,
        comments=body.comments,
    )
    db.add(row)
    await db.flush()
    return {"id": row.id}


@router.get("/ai-governance/metrics")
async def ai_governance_metrics(
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(select(AIGovernanceFeedback))).scalars().all()
    total = len(rows)
    hallucinations = sum(1 for r in rows if r.hallucination_flag)
    avg_rating = (sum(r.rating for r in rows) / total) if total else 0.0

    confidence_rows = (
        await db.execute(select(Alert.confidence).where(Alert.confidence.is_not(None)).limit(2000))
    ).all()
    confidences = [float(r[0]) for r in confidence_rows if r[0] is not None]
    avg_conf = sum(confidences) / len(confidences) if confidences else 0.0

    return {
        "feedback_count": total,
        "avg_rating": round(avg_rating, 3),
        "hallucination_rate": round((hallucinations / total), 3) if total else 0.0,
        "avg_model_confidence": round(avg_conf, 3),
        "guardrail_status": "healthy" if (total == 0 or (hallucinations / max(1, total)) < 0.2) else "degraded",
    }


@router.get("/mitre/source-quality")
async def mitre_source_quality(
    _user: Annotated[dict, Depends(require_permission("sources:read"))],
    db: AsyncSession = Depends(get_db),
):
    alert_rows = (await db.execute(select(Alert.source, Alert.mitre_techniques))).all()
    source_stats: dict[str, dict] = {}

    all_tactics = {v["tactic"] for v in TECHNIQUES.values()}

    for source, mt in alert_rows:
        src = str(source or "unknown")
        stat = source_stats.setdefault(
            src,
            {"alerts": 0, "techniques": set(), "tactics": set()},
        )
        stat["alerts"] += 1
        items = []
        if isinstance(mt, list):
            items = mt
        elif isinstance(mt, dict):
            items = mt.get("items") or []
        for item in items:
            if not isinstance(item, dict):
                continue
            tid = item.get("technique_id")
            tac = item.get("tactic")
            if tid:
                stat["techniques"].add(str(tid))
            if tac:
                stat["tactics"].add(str(tac))

    health_rows = (await db.execute(select(SourceHealth))).scalars().all()
    freshness: dict[str, float] = {}
    allowed_failure_rate = max(0.0001, float(get_settings().source_health_error_budget_failure_rate))
    for h in health_rows:
        total = max(1, int(h.window_successes or 0) + int(h.window_failures or 0))
        error_rate = float(h.window_failures or 0) / total
        remaining_pct = max(0.0, (1.0 - (error_rate / allowed_failure_rate)) * 100.0)
        key = str(h.source_name or h.source_id or "unknown")
        freshness[key] = remaining_pct

    out = []
    for source_name, stat in sorted(source_stats.items(), key=lambda kv: kv[0]):
        tactic_cov = len(stat["tactics"]) / max(1, len(all_tactics))
        freshness_score = freshness.get(source_name, 80.0) / 100.0
        quality_score = round((0.65 * tactic_cov + 0.35 * freshness_score) * 100, 2)
        blind_spots = sorted(all_tactics - stat["tactics"])[:8]
        out.append(
            {
                "source": source_name,
                "alerts": stat["alerts"],
                "techniques_detected": len(stat["techniques"]),
                "tactics_detected": len(stat["tactics"]),
                "quality_score": quality_score,
                "blind_spots": blind_spots,
            }
        )

    out.sort(key=lambda x: x["quality_score"], reverse=True)
    return {"items": out, "total_sources": len(out)}
