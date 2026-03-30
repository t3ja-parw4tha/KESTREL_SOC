"""Detection rules API (P4-1)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Literal, cast

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.detection_rules.engine import evaluate_custom_rule, evaluate_sigma_rule
from app.database import get_db
from app.models import AuditLog, DetectionRule, DetectionRuleHistory
from app.security.csrf import verify_csrf
from app.security.rbac import require_permission

router = APIRouter(prefix="/detection-rules", tags=["detection-rules"])

_RULE_FIELDS = (
    "name",
    "rule_type",
    "description",
    "severity",
    "enabled",
    "sigma_yaml",
    "conditions",
)


def _snapshot_rule(rule: DetectionRule) -> dict[str, Any]:
    return {
        "name": rule.name,
        "rule_type": rule.rule_type,
        "description": rule.description,
        "severity": rule.severity,
        "enabled": bool(rule.enabled),
        "sigma_yaml": rule.sigma_yaml,
        "conditions": rule.conditions,
    }


def _diff_snapshots(previous: dict[str, Any], proposed: dict[str, Any]) -> dict[str, dict[str, Any]]:
    diff: dict[str, dict[str, Any]] = {}
    for key in _RULE_FIELDS:
        old = previous.get(key)
        new = proposed.get(key)
        if old != new:
            diff[key] = {"old": old, "new": new}
    return diff


def _apply_snapshot(rule: DetectionRule, snapshot: dict[str, Any]) -> None:
    for key in _RULE_FIELDS:
        if key in snapshot:
            setattr(rule, key, snapshot[key])


def _validate_rule_snapshot(snapshot: dict[str, Any]) -> None:
    rule_type = str(snapshot.get("rule_type") or "").lower()
    if rule_type not in {"sigma", "custom"}:
        raise HTTPException(status_code=400, detail="rule_type must be sigma or custom")
    if rule_type == "sigma" and not snapshot.get("sigma_yaml"):
        raise HTTPException(status_code=400, detail="sigma_yaml is required for sigma rules")
    if rule_type == "custom" and not snapshot.get("conditions"):
        raise HTTPException(status_code=400, detail="conditions are required for custom rules")


async def _current_version(db: AsyncSession, rule_id: int) -> int:
    current = (
        await db.execute(
            select(func.max(DetectionRuleHistory.version)).where(
                DetectionRuleHistory.rule_id == rule_id,
                DetectionRuleHistory.status == "approved",
                DetectionRuleHistory.version.is_not(None),
            )
        )
    ).scalar_one_or_none()
    return int(current or 1)


async def _latest_pending_request(db: AsyncSession, rule_id: int) -> DetectionRuleHistory | None:
    return (
        await db.execute(
            select(DetectionRuleHistory)
            .where(
                DetectionRuleHistory.rule_id == rule_id,
                DetectionRuleHistory.status == "pending",
                DetectionRuleHistory.action == "update_request",
            )
            .order_by(DetectionRuleHistory.created_at.desc(), DetectionRuleHistory.id.desc())
        )
    ).scalar_one_or_none()


async def _rule_approval_status(db: AsyncSession, rule_id: int) -> tuple[str, bool]:
    pending = await _latest_pending_request(db, rule_id)
    return ("pending" if pending else "approved", pending is not None)


def _conditions_as_list(raw: Any) -> list[dict[str, Any]] | None:
    if raw is None:
        return None
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    if isinstance(raw, dict):
        return [raw]
    return None


class DetectionRuleBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=160)
    rule_type: Literal["sigma", "custom"]
    description: str | None = Field(default=None, max_length=1024)
    severity: Literal["Low", "Medium", "High", "Critical"] = "Medium"
    enabled: bool = True
    sigma_yaml: str | None = None
    conditions: list[dict[str, Any]] | None = None


class DetectionRuleCreate(DetectionRuleBase):
    pass


class DetectionRuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=1024)
    severity: Literal["Low", "Medium", "High", "Critical"] | None = None
    enabled: bool | None = None
    sigma_yaml: str | None = None
    conditions: list[dict[str, Any]] | None = None


class DetectionRuleResponse(DetectionRuleBase):
    id: int
    created_by: str | None
    version: int
    approval_status: Literal["pending", "approved"]
    has_pending_change: bool


class DetectionRuleChangeRequest(DetectionRuleUpdate):
    reason: str | None = Field(default=None, max_length=512)


class ApproveRuleChangeRequest(BaseModel):
    request_id: int | None = None


class RollbackRuleRequest(BaseModel):
    target_version: int = Field(..., ge=1)
    reason: str | None = Field(default=None, max_length=512)


class DetectionRuleHistoryItem(BaseModel):
    id: int
    rule_id: int
    version: int | None
    action: str
    status: str
    requested_by: str | None
    approved_by: str | None
    reason: str | None
    base_version: int | None
    change_set: dict | list | None
    created_at: datetime | None
    approved_at: datetime | None


class RuleTestRequest(BaseModel):
    event: dict[str, Any]


async def _serialize_rule(db: AsyncSession, rule: DetectionRule) -> DetectionRuleResponse:
    version = await _current_version(db, rule.id)
    approval_status, has_pending_change = await _rule_approval_status(db, rule.id)
    rt = str(rule.rule_type or "custom").lower()
    sev = str(rule.severity or "Medium")
    st = str(approval_status)
    return DetectionRuleResponse(
        id=rule.id,
        name=rule.name,
        rule_type=cast(Literal["sigma", "custom"], rt if rt in ("sigma", "custom") else "custom"),
        description=rule.description,
        severity=cast(
            Literal["Low", "Medium", "High", "Critical"],
            sev if sev in ("Low", "Medium", "High", "Critical") else "Medium",
        ),
        enabled=rule.enabled,
        sigma_yaml=rule.sigma_yaml,
        conditions=_conditions_as_list(rule.conditions),
        created_by=rule.created_by,
        version=version,
        approval_status=cast(Literal["pending", "approved"], st if st in ("pending", "approved") else "approved"),
        has_pending_change=has_pending_change,
    )


@router.get("")
async def list_rules(
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
    enabled: bool | None = Query(default=None),
):
    stmt = select(DetectionRule).order_by(DetectionRule.updated_at.desc())
    if enabled is not None:
        stmt = stmt.where(DetectionRule.enabled.is_(enabled))
    rows = (await db.execute(stmt)).scalars().all()
    return [await _serialize_rule(db, r) for r in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: DetectionRuleCreate,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    if body.rule_type == "sigma" and not body.sigma_yaml:
        raise HTTPException(status_code=400, detail="sigma_yaml is required for sigma rules")
    if body.rule_type == "custom" and not body.conditions:
        raise HTTPException(status_code=400, detail="conditions are required for custom rules")

    existing = await db.execute(select(DetectionRule).where(DetectionRule.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Rule name already exists")

    actor = str(user.get("sub")) if user.get("sub") else None

    obj = DetectionRule(
        name=body.name,
        rule_type=body.rule_type,
        description=body.description,
        severity=body.severity,
        enabled=body.enabled,
        sigma_yaml=body.sigma_yaml,
        conditions=body.conditions,
        created_by=actor,
    )
    db.add(obj)
    await db.flush()
    db.add(
        DetectionRuleHistory(
            rule_id=obj.id,
            version=1,
            action="create",
            status="approved",
            requested_by=actor,
            approved_by=actor,
            approved_at=datetime.now(timezone.utc),
            snapshot=_snapshot_rule(obj),
            change_set={"created": True},
        )
    )
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="detection_rule.create",
        analyst=actor,
        ip_address=None,
        details={"rule_id": obj.id, "rule_name": obj.name, "rule_type": obj.rule_type, "severity": obj.severity},
    ))
    await db.commit()
    await db.refresh(obj)
    return await _serialize_rule(db, obj)


@router.patch("/{rule_id}")
async def update_rule(
    rule_id: int,
    body: DetectionRuleChangeRequest,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    row = (await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")

    pending = await _latest_pending_request(db, rule_id)
    if pending:
        raise HTTPException(status_code=409, detail="Rule already has a pending change request")

    patch = body.model_dump(exclude_unset=True, exclude={"reason"})
    if not patch:
        raise HTTPException(status_code=400, detail="No fields supplied for update")

    current_snapshot = _snapshot_rule(row)
    proposed_snapshot = dict(current_snapshot)
    proposed_snapshot.update(patch)
    _validate_rule_snapshot(proposed_snapshot)

    diff = _diff_snapshots(current_snapshot, proposed_snapshot)
    if not diff:
        return {"rule_id": row.id, "status": "noop", "detail": "No effective changes"}

    if "name" in diff:
        duplicate = (
            await db.execute(
                select(DetectionRule)
                .where(and_(DetectionRule.name == proposed_snapshot["name"], DetectionRule.id != row.id))
            )
        ).scalar_one_or_none()
        if duplicate:
            raise HTTPException(status_code=409, detail="Rule name already exists")

    actor = str(user.get("sub")) if user.get("sub") else None
    base_version = await _current_version(db, rule_id)
    request_row = DetectionRuleHistory(
        rule_id=rule_id,
        version=None,
        action="update_request",
        status="pending",
        requested_by=actor,
        approved_by=None,
        approved_at=None,
        reason=body.reason,
        base_version=base_version,
        change_set=diff,
        snapshot=proposed_snapshot,
    )
    db.add(request_row)
    await db.commit()
    await db.refresh(request_row)
    return {
        "rule_id": row.id,
        "request_id": request_row.id,
        "status": "pending_approval",
        "base_version": base_version,
        "changed_fields": sorted(diff.keys()),
    }


@router.post("/{rule_id}/approve-change")
async def approve_rule_change(
    rule_id: int,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
    body: ApproveRuleChangeRequest | None = None,
):
    row = (await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")

    if body and body.request_id is not None:
        pending = (
            await db.execute(
                select(DetectionRuleHistory).where(
                    DetectionRuleHistory.id == body.request_id,
                    DetectionRuleHistory.rule_id == rule_id,
                    DetectionRuleHistory.status == "pending",
                    DetectionRuleHistory.action == "update_request",
                )
            )
        ).scalar_one_or_none()
    else:
        pending = await _latest_pending_request(db, rule_id)

    if not pending:
        raise HTTPException(status_code=404, detail="Pending change request not found")

    approver = str(user.get("sub")) if user.get("sub") else None
    if approver and pending.requested_by and approver == pending.requested_by:
        raise HTTPException(status_code=409, detail="Peer approval required: requester cannot self-approve")

    target_snapshot = pending.snapshot if isinstance(pending.snapshot, dict) else None
    if not target_snapshot:
        raise HTTPException(status_code=400, detail="Pending change has no snapshot")

    _validate_rule_snapshot(target_snapshot)
    current_snapshot = _snapshot_rule(row)

    if "name" in target_snapshot and target_snapshot["name"] != row.name:
        duplicate = (
            await db.execute(
                select(DetectionRule)
                .where(and_(DetectionRule.name == target_snapshot["name"], DetectionRule.id != row.id))
            )
        ).scalar_one_or_none()
        if duplicate:
            raise HTTPException(status_code=409, detail="Rule name already exists")

    _apply_snapshot(row, target_snapshot)
    new_version = (await _current_version(db, rule_id)) + 1
    applied_diff = _diff_snapshots(current_snapshot, target_snapshot)

    pending.status = "approved"
    pending.action = "update"
    pending.version = new_version
    pending.approved_by = approver
    pending.approved_at = datetime.now(timezone.utc)
    pending.change_set = applied_diff
    pending.snapshot = target_snapshot

    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="detection_rule.approve_change",
        analyst=approver,
        ip_address=None,
        details={
            "rule_id": rule_id,
            "rule_name": row.name,
            "new_version": new_version,
            "request_id": pending.id,
            "changed_fields": sorted(applied_diff.keys()),
        },
    ))
    await db.commit()
    await db.refresh(row)
    return await _serialize_rule(db, row)


@router.post("/{rule_id}/rollback")
async def rollback_rule(
    rule_id: int,
    body: RollbackRuleRequest,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    row = (await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")

    target_revision = (
        await db.execute(
            select(DetectionRuleHistory).where(
                DetectionRuleHistory.rule_id == rule_id,
                DetectionRuleHistory.version == body.target_version,
                DetectionRuleHistory.status == "approved",
                DetectionRuleHistory.snapshot.is_not(None),
            ).order_by(DetectionRuleHistory.id.desc())
        )
    ).scalars().first()
    if not target_revision or not isinstance(target_revision.snapshot, dict):
        raise HTTPException(status_code=404, detail="Target version not found")

    target_snapshot = target_revision.snapshot
    _validate_rule_snapshot(target_snapshot)

    if "name" in target_snapshot and target_snapshot["name"] != row.name:
        duplicate = (
            await db.execute(
                select(DetectionRule)
                .where(and_(DetectionRule.name == target_snapshot["name"], DetectionRule.id != row.id))
            )
        ).scalar_one_or_none()
        if duplicate:
            raise HTTPException(status_code=409, detail="Cannot rollback due to name conflict")

    before = _snapshot_rule(row)
    diff = _diff_snapshots(before, target_snapshot)
    if not diff:
        return {"rule_id": row.id, "status": "noop", "detail": "Rule already matches target version"}

    _apply_snapshot(row, target_snapshot)
    actor = str(user.get("sub")) if user.get("sub") else None
    new_version = (await _current_version(db, rule_id)) + 1

    db.add(
        DetectionRuleHistory(
            rule_id=rule_id,
            version=new_version,
            action="rollback",
            status="approved",
            requested_by=actor,
            approved_by=actor,
            approved_at=datetime.now(timezone.utc),
            reason=body.reason or f"rollback_to_v{body.target_version}",
            base_version=body.target_version,
            change_set=diff,
            snapshot=target_snapshot,
        )
    )
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="detection_rule.rollback",
        analyst=actor,
        ip_address=None,
        details={
            "rule_id": rule_id,
            "rule_name": row.name,
            "target_version": body.target_version,
            "new_version": new_version,
            "reason": body.reason,
        },
    ))
    await db.commit()
    await db.refresh(row)
    return await _serialize_rule(db, row)


@router.get("/{rule_id}/history", response_model=list[DetectionRuleHistoryItem])
async def get_rule_history(
    rule_id: int,
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
):
    row = (await db.execute(select(DetectionRule.id).where(DetectionRule.id == rule_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    entries = (
        await db.execute(
            select(DetectionRuleHistory)
            .where(DetectionRuleHistory.rule_id == rule_id)
            .order_by(DetectionRuleHistory.created_at.desc(), DetectionRuleHistory.id.desc())
        )
    ).scalars().all()
    return [
        DetectionRuleHistoryItem(
            id=e.id,
            rule_id=e.rule_id,
            version=e.version,
            action=e.action,
            status=e.status,
            requested_by=e.requested_by,
            approved_by=e.approved_by,
            reason=e.reason,
            base_version=e.base_version,
            change_set=e.change_set,
            created_at=e.created_at,
            approved_at=e.approved_at,
        )
        for e in entries
    ]


@router.get("/{rule_id}/diff")
async def get_rule_diff(
    rule_id: int,
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
    from_version: int = Query(..., ge=1),
    to_version: int = Query(..., ge=1),
):
    row = (await db.execute(select(DetectionRule.id).where(DetectionRule.id == rule_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    from_entry = (
        await db.execute(
            select(DetectionRuleHistory).where(
                DetectionRuleHistory.rule_id == rule_id,
                DetectionRuleHistory.version == from_version,
                DetectionRuleHistory.status == "approved",
                DetectionRuleHistory.snapshot.is_not(None),
            ).order_by(DetectionRuleHistory.id.desc())
        )
    ).scalars().first()
    to_entry = (
        await db.execute(
            select(DetectionRuleHistory).where(
                DetectionRuleHistory.rule_id == rule_id,
                DetectionRuleHistory.version == to_version,
                DetectionRuleHistory.status == "approved",
                DetectionRuleHistory.snapshot.is_not(None),
            ).order_by(DetectionRuleHistory.id.desc())
        )
    ).scalars().first()
    if not from_entry or not isinstance(from_entry.snapshot, dict):
        raise HTTPException(status_code=404, detail="from_version not found")
    if not to_entry or not isinstance(to_entry.snapshot, dict):
        raise HTTPException(status_code=404, detail="to_version not found")

    diff = _diff_snapshots(from_entry.snapshot, to_entry.snapshot)
    return {
        "rule_id": rule_id,
        "from_version": from_version,
        "to_version": to_version,
        "changed_fields": sorted(diff.keys()),
        "diff": diff,
    }


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: int,
    _user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    row = (await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")
    actor = str(_user.get("sub")) if _user.get("sub") else None
    db.add(
        DetectionRuleHistory(
            rule_id=row.id,
            version=None,
            action="delete",
            status="approved",
            requested_by=actor,
            approved_by=actor,
            approved_at=datetime.now(timezone.utc),
            snapshot=_snapshot_rule(row),
            change_set={"deleted": True},
        )
    )
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="detection_rule.delete",
        analyst=actor,
        ip_address=None,
        details={"rule_id": row.id, "rule_name": row.name, "rule_type": row.rule_type},
    ))
    await db.delete(row)
    await db.commit()


@router.post("/{rule_id}/test")
async def test_rule(
    rule_id: int,
    body: RuleTestRequest,
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
):
    rule = (await db.execute(select(DetectionRule).where(DetectionRule.id == rule_id))).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    matched = False
    reason = "no-match"
    if rule.rule_type == "custom":
        conds = _conditions_as_list(rule.conditions) or []
        matched = evaluate_custom_rule(body.event, conds)
        reason = "custom-condition-match" if matched else "custom-condition-miss"
    else:
        if not rule.sigma_yaml:
            raise HTTPException(status_code=400, detail="Rule missing sigma_yaml")
        try:
            sigma_doc = yaml.safe_load(rule.sigma_yaml) or {}
        except yaml.YAMLError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid SIGMA yaml: {exc}")
        matched = evaluate_sigma_rule(body.event, sigma_doc)
        reason = "sigma-selection-match" if matched else "sigma-selection-miss"

    return {"rule_id": rule.id, "matched": matched, "reason": reason}
