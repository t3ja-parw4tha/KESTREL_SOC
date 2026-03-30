"""Evidence attachment API for alerts and incidents."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Alert, AuditLog, EvidenceAttachment, EvidenceCustodyEvent, EvidenceLegalHold
from app.security.csrf import verify_csrf
from app.security.rbac import require_permission

router = APIRouter(prefix="/evidence", tags=["evidence"])

_ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".txt", ".log", ".csv", ".json", ".pcap"}
_MAX_FILE_BYTES = 15 * 1024 * 1024
_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_NOTES_LENGTH = 2048


class EvidenceItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_id: str | None
    incident_id: str | None
    attachment_type: str
    name: str
    content_type: str | None
    size_bytes: int | None
    external_url: str | None
    sha256: str | None
    notes: str | None
    uploaded_by: str | None
    created_at: str | None


class EvidenceUrlRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    name: str | None = Field(default=None, max_length=512)
    notes: str | None = Field(default=None, max_length=2048)


class LegalHoldRequest(BaseModel):
    enabled: bool
    reason: str | None = Field(default=None, max_length=512)
    retain_until: datetime | None = None


class LegalHoldResponse(BaseModel):
    evidence_id: str
    enabled: bool
    reason: str | None
    retain_until: str | None
    set_by: str | None
    set_at: str | None
    released_by: str | None
    released_at: str | None


class EvidenceHashVerificationResponse(BaseModel):
    evidence_id: str
    expected_sha256: str | None
    computed_sha256: str | None
    valid: bool
    detail: str


class CustodyEventItem(BaseModel):
    id: str
    evidence_id: str
    action: str
    actor: str | None
    details: dict | None
    prev_hash: str
    event_hash: str
    created_at: str | None


class CustodyVerifyResponse(BaseModel):
    evidence_id: str
    valid: bool
    event_count: int
    broken_event_id: str | None
    detail: str


def _get_evidence_base() -> Path:
    base = Path("data") / "evidence"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _sanitize_filename(name: str) -> str:
    clean = _FILENAME_SAFE.sub("_", name.strip())
    return clean[:180] or "evidence"


def _validate_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Only http/https URLs are allowed")
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL")
    return raw_url


async def _ensure_alert_exists(db: AsyncSession, alert_id: str) -> None:
    alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")


async def _ensure_incident_exists(db: AsyncSession, incident_id: str) -> None:
    alert = (
        await db.execute(
            select(Alert.id).where(Alert.incident_group_id == incident_id).limit(1)
        )
    ).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Incident not found")


def _to_item(e: EvidenceAttachment) -> EvidenceItem:
    return EvidenceItem(
        id=e.id,
        alert_id=e.alert_id,
        incident_id=e.incident_id,
        attachment_type=e.attachment_type,
        name=e.name,
        content_type=e.content_type,
        size_bytes=e.size_bytes,
        external_url=e.external_url,
        sha256=e.sha256,
        notes=e.notes,
        uploaded_by=e.uploaded_by,
        created_at=e.created_at.isoformat() if e.created_at else None,
    )


def _canonical_details(details: dict | None) -> str:
    return json.dumps(details or {}, sort_keys=True, separators=(",", ":"))


def _compute_custody_hash(*, prev_hash: str, evidence_id: str, action: str, actor: str | None, details: dict | None) -> str:
    payload = "|".join([
        prev_hash,
        evidence_id,
        action,
        actor or "",
        _canonical_details(details),
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def _append_custody_event(
    db: AsyncSession,
    *,
    evidence_id: str,
    action: str,
    actor: str | None,
    details: dict | None = None,
) -> EvidenceCustodyEvent:
    last_event = (
        await db.execute(
            select(EvidenceCustodyEvent)
            .where(EvidenceCustodyEvent.evidence_id == evidence_id)
            .order_by(EvidenceCustodyEvent.created_at.desc(), EvidenceCustodyEvent.id.desc())
        )
    ).scalars().first()
    prev_hash = last_event.event_hash if last_event else "GENESIS"
    event_hash = _compute_custody_hash(
        prev_hash=prev_hash,
        evidence_id=evidence_id,
        action=action,
        actor=actor,
        details=details,
    )
    event = EvidenceCustodyEvent(
        id=str(uuid.uuid4()),
        evidence_id=evidence_id,
        action=action,
        actor=actor,
        details=details,
        prev_hash=prev_hash,
        event_hash=event_hash,
    )
    db.add(event)
    return event


def _to_legal_hold_response(row: EvidenceLegalHold) -> LegalHoldResponse:
    return LegalHoldResponse(
        evidence_id=row.evidence_id,
        enabled=bool(row.enabled),
        reason=row.reason,
        retain_until=row.retain_until.isoformat() if row.retain_until else None,
        set_by=row.set_by,
        set_at=row.set_at.isoformat() if row.set_at else None,
        released_by=row.released_by,
        released_at=row.released_at.isoformat() if row.released_at else None,
    )


def _hold_is_active(hold: EvidenceLegalHold | None) -> bool:
    if not hold or not hold.enabled:
        return False
    if hold.retain_until and hold.retain_until.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        return False
    return True


@router.get("/alerts/{alert_id}", response_model=list[EvidenceItem])
async def list_alert_evidence(
    alert_id: str,
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
) -> list[EvidenceItem]:
    await _ensure_alert_exists(db, alert_id)
    rows = (
        await db.execute(
            select(EvidenceAttachment)
            .where(EvidenceAttachment.alert_id == alert_id)
            .order_by(EvidenceAttachment.created_at.desc())
        )
    ).scalars().all()
    return [_to_item(r) for r in rows]


@router.get("/incidents/{incident_id}", response_model=list[EvidenceItem])
async def list_incident_evidence(
    incident_id: str,
    _user: Annotated[dict, Depends(require_permission("incidents:read"))],
    db: AsyncSession = Depends(get_db),
) -> list[EvidenceItem]:
    await _ensure_incident_exists(db, incident_id)
    rows = (
        await db.execute(
            select(EvidenceAttachment)
            .where(EvidenceAttachment.incident_id == incident_id)
            .order_by(EvidenceAttachment.created_at.desc())
        )
    ).scalars().all()
    return [_to_item(r) for r in rows]


@router.post("/alerts/{alert_id}/url", response_model=EvidenceItem, status_code=201)
async def add_alert_url_evidence(
    alert_id: str,
    body: EvidenceUrlRequest,
    user: Annotated[dict, Depends(require_permission("evidence:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> EvidenceItem:
    await _ensure_alert_exists(db, alert_id)
    validated_url = _validate_url(body.url)
    ev = EvidenceAttachment(
        id=str(uuid.uuid4()),
        alert_id=alert_id,
        incident_id=None,
        attachment_type="url",
        name=(body.name or validated_url)[:512],
        content_type=None,
        size_bytes=None,
        storage_path=None,
        external_url=validated_url,
        sha256=None,
        notes=body.notes,
        uploaded_by=str(user.get("sub")) if user.get("sub") else None,
    )
    db.add(ev)
    actor = str(user.get("sub")) if user.get("sub") else None
    await _append_custody_event(
        db,
        evidence_id=ev.id,
        action="created_url_evidence",
        actor=actor,
        details={"alert_id": alert_id, "external_url": validated_url},
    )
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="evidence.create",
        analyst=actor,
        ip_address=None,
        details={"evidence_id": ev.id, "attachment_type": "url", "alert_id": alert_id},
    ))
    await db.flush()
    await db.refresh(ev)
    return _to_item(ev)


@router.post("/incidents/{incident_id}/url", response_model=EvidenceItem, status_code=201)
async def add_incident_url_evidence(
    incident_id: str,
    body: EvidenceUrlRequest,
    user: Annotated[dict, Depends(require_permission("evidence:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
) -> EvidenceItem:
    await _ensure_incident_exists(db, incident_id)
    validated_url = _validate_url(body.url)
    ev = EvidenceAttachment(
        id=str(uuid.uuid4()),
        alert_id=None,
        incident_id=incident_id,
        attachment_type="url",
        name=(body.name or validated_url)[:512],
        content_type=None,
        size_bytes=None,
        storage_path=None,
        external_url=validated_url,
        sha256=None,
        notes=body.notes,
        uploaded_by=str(user.get("sub")) if user.get("sub") else None,
    )
    db.add(ev)
    actor = str(user.get("sub")) if user.get("sub") else None
    await _append_custody_event(
        db,
        evidence_id=ev.id,
        action="created_url_evidence",
        actor=actor,
        details={"incident_id": incident_id, "external_url": validated_url},
    )
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="evidence.create",
        analyst=actor,
        ip_address=None,
        details={"evidence_id": ev.id, "attachment_type": "url", "incident_id": incident_id},
    ))
    await db.flush()
    await db.refresh(ev)
    return _to_item(ev)


async def _store_upload(file: UploadFile) -> tuple[str, int, str]:
    original_name = file.filename or "evidence"
    ext = Path(original_name).suffix.lower()
    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported file extension: {ext}")

    base = _get_evidence_base()
    safe_name = _sanitize_filename(Path(original_name).name)
    final_name = f"{uuid.uuid4()}_{safe_name}"
    path = base / final_name

    sha = hashlib.sha256()
    total = 0
    with path.open("wb") as fh:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_FILE_BYTES:
                fh.close()
                path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="File exceeds 15 MB limit")
            sha.update(chunk)
            fh.write(chunk)

    return str(path), total, sha.hexdigest()


@router.post("/alerts/{alert_id}/file", response_model=EvidenceItem, status_code=201)
async def add_alert_file_evidence(
    alert_id: str,
    user: Annotated[dict, Depends(require_permission("evidence:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
    file: UploadFile = File(...),
    notes: str | None = Form(default=None, max_length=_MAX_NOTES_LENGTH),
) -> EvidenceItem:
    await _ensure_alert_exists(db, alert_id)
    storage_path, size_bytes, digest = await _store_upload(file)
    ev = EvidenceAttachment(
        id=str(uuid.uuid4()),
        alert_id=alert_id,
        incident_id=None,
        attachment_type="file",
        name=(file.filename or "evidence")[:512],
        content_type=file.content_type,
        size_bytes=size_bytes,
        storage_path=storage_path,
        external_url=None,
        sha256=digest,
        notes=(notes or None),
        uploaded_by=str(user.get("sub")) if user.get("sub") else None,
    )
    db.add(ev)
    actor = str(user.get("sub")) if user.get("sub") else None
    await _append_custody_event(
        db,
        evidence_id=ev.id,
        action="created_file_evidence",
        actor=actor,
        details={"alert_id": alert_id, "sha256": digest, "size_bytes": size_bytes},
    )
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="evidence.create",
        analyst=actor,
        ip_address=None,
        details={"evidence_id": ev.id, "attachment_type": "file", "alert_id": alert_id, "sha256": digest},
    ))
    await db.flush()
    await db.refresh(ev)
    return _to_item(ev)


@router.post("/incidents/{incident_id}/file", response_model=EvidenceItem, status_code=201)
async def add_incident_file_evidence(
    incident_id: str,
    user: Annotated[dict, Depends(require_permission("evidence:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
    file: UploadFile = File(...),
    notes: str | None = Form(default=None, max_length=_MAX_NOTES_LENGTH),
) -> EvidenceItem:
    await _ensure_incident_exists(db, incident_id)
    storage_path, size_bytes, digest = await _store_upload(file)
    ev = EvidenceAttachment(
        id=str(uuid.uuid4()),
        alert_id=None,
        incident_id=incident_id,
        attachment_type="file",
        name=(file.filename or "evidence")[:512],
        content_type=file.content_type,
        size_bytes=size_bytes,
        storage_path=storage_path,
        external_url=None,
        sha256=digest,
        notes=(notes or None),
        uploaded_by=str(user.get("sub")) if user.get("sub") else None,
    )
    db.add(ev)
    actor = str(user.get("sub")) if user.get("sub") else None
    await _append_custody_event(
        db,
        evidence_id=ev.id,
        action="created_file_evidence",
        actor=actor,
        details={"incident_id": incident_id, "sha256": digest, "size_bytes": size_bytes},
    )
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="evidence.create",
        analyst=actor,
        ip_address=None,
        details={"evidence_id": ev.id, "attachment_type": "file", "incident_id": incident_id, "sha256": digest},
    ))
    await db.flush()
    await db.refresh(ev)
    return _to_item(ev)


@router.get("/{evidence_id}/download")
async def download_evidence(
    evidence_id: str,
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
):
    ev = (
        await db.execute(select(EvidenceAttachment).where(EvidenceAttachment.id == evidence_id))
    ).scalar_one_or_none()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if ev.attachment_type != "file" or not ev.storage_path:
        raise HTTPException(status_code=400, detail="Evidence item is not a downloadable file")

    path = Path(ev.storage_path)
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file missing from storage")

    await _append_custody_event(
        db,
        evidence_id=ev.id,
        action="downloaded",
        actor=str(_user.get("sub")) if _user.get("sub") else None,
        details={"filename": ev.name},
    )

    return FileResponse(path=str(path), filename=ev.name, media_type=ev.content_type or "application/octet-stream")


@router.get("/{evidence_id}/verify-hash", response_model=EvidenceHashVerificationResponse)
async def verify_evidence_hash(
    evidence_id: str,
    user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
):
    ev = (await db.execute(select(EvidenceAttachment).where(EvidenceAttachment.id == evidence_id))).scalar_one_or_none()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if ev.attachment_type != "file" or not ev.storage_path:
        raise HTTPException(status_code=400, detail="Hash verification is only available for file evidence")

    path = Path(ev.storage_path)
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file missing from storage")

    sha = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            sha.update(chunk)
    computed = sha.hexdigest()
    expected = ev.sha256
    valid = bool(expected and computed == expected)
    detail = "hash_match" if valid else "hash_mismatch"

    await _append_custody_event(
        db,
        evidence_id=ev.id,
        action="hash_verified",
        actor=str(user.get("sub")) if user.get("sub") else None,
        details={"expected_sha256": expected, "computed_sha256": computed, "valid": valid},
    )

    return EvidenceHashVerificationResponse(
        evidence_id=ev.id,
        expected_sha256=expected,
        computed_sha256=computed,
        valid=valid,
        detail=detail,
    )


@router.get("/{evidence_id}/custody-events", response_model=list[CustodyEventItem])
async def list_custody_events(
    evidence_id: str,
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
):
    ev = (await db.execute(select(EvidenceAttachment.id).where(EvidenceAttachment.id == evidence_id))).scalar_one_or_none()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    rows = (
        await db.execute(
            select(EvidenceCustodyEvent)
            .where(EvidenceCustodyEvent.evidence_id == evidence_id)
            .order_by(EvidenceCustodyEvent.created_at.asc(), EvidenceCustodyEvent.id.asc())
        )
    ).scalars().all()
    return [
        CustodyEventItem(
            id=r.id,
            evidence_id=r.evidence_id,
            action=r.action,
            actor=r.actor,
            details=r.details if isinstance(r.details, dict) else None,
            prev_hash=r.prev_hash,
            event_hash=r.event_hash,
            created_at=r.created_at.isoformat() if r.created_at else None,
        )
        for r in rows
    ]


@router.get("/{evidence_id}/verify-chain", response_model=CustodyVerifyResponse)
async def verify_custody_chain(
    evidence_id: str,
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
):
    ev = (await db.execute(select(EvidenceAttachment.id).where(EvidenceAttachment.id == evidence_id))).scalar_one_or_none()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    rows = (
        await db.execute(
            select(EvidenceCustodyEvent)
            .where(EvidenceCustodyEvent.evidence_id == evidence_id)
            .order_by(EvidenceCustodyEvent.created_at.asc(), EvidenceCustodyEvent.id.asc())
        )
    ).scalars().all()

    hash_index = {row.event_hash: row.id for row in rows}
    genesis_count = 0
    for row in rows:
        expected = _compute_custody_hash(
            prev_hash=row.prev_hash,
            evidence_id=row.evidence_id,
            action=row.action,
            actor=row.actor,
            details=row.details if isinstance(row.details, dict) else None,
        )
        if row.event_hash != expected:
            return CustodyVerifyResponse(
                evidence_id=evidence_id,
                valid=False,
                event_count=len(rows),
                broken_event_id=row.id,
                detail="chain_integrity_failure",
            )
        if row.prev_hash == "GENESIS":
            genesis_count += 1
        elif row.prev_hash not in hash_index:
            return CustodyVerifyResponse(
                evidence_id=evidence_id,
                valid=False,
                event_count=len(rows),
                broken_event_id=row.id,
                detail="chain_link_missing",
            )

    if rows and genesis_count != 1:
        return CustodyVerifyResponse(
            evidence_id=evidence_id,
            valid=False,
            event_count=len(rows),
            broken_event_id=None,
            detail="chain_genesis_invalid",
        )

    return CustodyVerifyResponse(
        evidence_id=evidence_id,
        valid=True,
        event_count=len(rows),
        broken_event_id=None,
        detail="chain_valid",
    )


@router.get("/{evidence_id}/legal-hold", response_model=LegalHoldResponse)
async def get_legal_hold(
    evidence_id: str,
    _user: Annotated[dict, Depends(require_permission("alerts:read"))],
    db: AsyncSession = Depends(get_db),
):
    ev = (await db.execute(select(EvidenceAttachment.id).where(EvidenceAttachment.id == evidence_id))).scalar_one_or_none()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    hold = await db.get(EvidenceLegalHold, evidence_id)
    if not hold:
        hold = EvidenceLegalHold(evidence_id=evidence_id, enabled=False)
        db.add(hold)
        await db.flush()
    return _to_legal_hold_response(hold)


@router.post("/{evidence_id}/legal-hold", response_model=LegalHoldResponse)
async def set_legal_hold(
    evidence_id: str,
    body: LegalHoldRequest,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    ev = (await db.execute(select(EvidenceAttachment.id).where(EvidenceAttachment.id == evidence_id))).scalar_one_or_none()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    actor = str(user.get("sub")) if user.get("sub") else None
    hold = await db.get(EvidenceLegalHold, evidence_id)
    if not hold:
        hold = EvidenceLegalHold(evidence_id=evidence_id)
        db.add(hold)

    if body.enabled and not (body.reason or "").strip():
        raise HTTPException(status_code=400, detail="reason is required when enabling legal hold")

    hold.enabled = bool(body.enabled)
    hold.reason = body.reason
    hold.retain_until = body.retain_until
    if body.enabled:
        hold.set_by = actor
        hold.set_at = datetime.now(timezone.utc)
        hold.released_by = None
        hold.released_at = None
        action = "legal_hold_enabled"
    else:
        hold.released_by = actor
        hold.released_at = datetime.now(timezone.utc)
        action = "legal_hold_released"

    await _append_custody_event(
        db,
        evidence_id=evidence_id,
        action=action,
        actor=actor,
        details={
            "reason": hold.reason,
            "retain_until": hold.retain_until.isoformat() if hold.retain_until else None,
        },
    )
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="evidence.legal_hold",
        analyst=actor,
        ip_address=None,
        details={
            "evidence_id": evidence_id,
            "legal_hold_action": action,
            "reason": hold.reason,
            "retain_until": hold.retain_until.isoformat() if hold.retain_until else None,
        },
    ))
    await db.flush()
    return _to_legal_hold_response(hold)


@router.delete("/{evidence_id}", status_code=204)
async def delete_evidence(
    evidence_id: str,
    user: Annotated[dict, Depends(require_permission("admin:write"))],
    _csrf: Annotated[None, Depends(verify_csrf)],
    db: AsyncSession = Depends(get_db),
):
    ev = (await db.execute(select(EvidenceAttachment).where(EvidenceAttachment.id == evidence_id))).scalar_one_or_none()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    hold = await db.get(EvidenceLegalHold, evidence_id)
    if _hold_is_active(hold):
        raise HTTPException(status_code=409, detail="Evidence is under legal hold and cannot be deleted")

    actor = str(user.get("sub")) if user.get("sub") else None
    await _append_custody_event(
        db,
        evidence_id=evidence_id,
        action="deleted",
        actor=actor,
        details={"attachment_type": ev.attachment_type, "name": ev.name},
    )
    db.add(AuditLog(
        id=str(uuid.uuid4()),
        action="evidence.delete",
        analyst=actor,
        ip_address=None,
        details={"evidence_id": evidence_id, "attachment_type": ev.attachment_type, "name": ev.name},
    ))

    if ev.attachment_type == "file" and ev.storage_path:
        Path(ev.storage_path).unlink(missing_ok=True)

    await db.delete(ev)
