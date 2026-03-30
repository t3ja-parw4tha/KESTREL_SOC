"""Integration tests for case management workflow (P5-1)."""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import SessionLocal
from app.main import app
from app.models import Alert, AuditLog, CaseRecord
from app.models.alert import AlertSeverity, AlertStatus
from app.security.auth import create_access_token


def _token(role: str = "analyst", user_id: int = 1) -> str:
    token, _ = create_access_token(user_id=user_id, role=role)
    return token


async def _seed_alert_with_incident() -> tuple[str, str]:
    alert_id = str(uuid.uuid4())
    incident_id = f"inc-{uuid.uuid4().hex[:10]}"
    async with SessionLocal() as db:
        db.add(
            Alert(
                id=alert_id,
                title="Suspicious privilege escalation",
                source="unit-test",
                severity=AlertSeverity.HIGH,
                category="endpoint",
                status=AlertStatus.OPEN,
                incident_group_id=incident_id,
                source_ip="203.0.113.20",
            )
        )
        await db.commit()
    return alert_id, incident_id


@pytest.mark.asyncio
async def test_cases_requires_authentication():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/api/v1/cases")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_cases_viewer_read_only():
    headers = {"Authorization": f"Bearer {_token('viewer')}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        read_r = await client.get("/api/v1/cases")
        write_r = await client.post(
            "/api/v1/cases",
            json={
                "title": "Viewer should not create",
                "owner": "tier1@example.com",
                "severity": "low",
            },
        )

    assert read_r.status_code == 200
    assert write_r.status_code == 403


@pytest.mark.asyncio
async def test_cases_create_track_and_close_with_taxonomy():
    alert_id, incident_id = await _seed_alert_with_incident()
    headers = {"Authorization": f"Bearer {_token('analyst', user_id=11)}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        create_r = await client.post(
            "/api/v1/cases",
            json={
                "title": "Credential abuse investigation",
                "description": "Track coordinated auth attack and triage ownership",
                "owner": "tier2@corp.local",
                "severity": "high",
                "sla_hours": 8,
                "linked_alert_ids": [alert_id],
                "linked_incident_ids": [incident_id],
            },
        )
        assert create_r.status_code == 201
        created = create_r.json()
        case_id = created["id"]

        assert created["status"] == "open"
        assert created["owner"] == "tier2@corp.local"
        assert created["linked_alert_ids"] == [alert_id]
        assert created["linked_incident_ids"] == [incident_id]
        assert created["sla_due_at"] is not None
        assert created["sla_breached"] is False

        patch_no_reason = await client.patch(
            f"/api/v1/cases/{case_id}",
            json={"status": "resolved"},
        )
        assert patch_no_reason.status_code == 400

        patch_reason = await client.patch(
            f"/api/v1/cases/{case_id}",
            json={
                "status": "resolved",
                "closure_reason": "mitigated",
                "closure_notes": "Reset credentials and blocked abusive source network",
            },
        )
        assert patch_reason.status_code == 200
        resolved = patch_reason.json()

        assert resolved["status"] == "resolved"
        assert resolved["closure_reason"] == "mitigated"
        assert resolved["closed_at"] is not None

        detail_r = await client.get(f"/api/v1/cases/{case_id}")
        assert detail_r.status_code == 200
        detail = detail_r.json()
        assert detail["id"] == case_id

        taxonomy_r = await client.get("/api/v1/cases/taxonomy/closure-reasons")
        assert taxonomy_r.status_code == 200
        assert "mitigated" in taxonomy_r.json()["items"]

        metrics_r = await client.get("/api/v1/cases/metrics/summary")
        assert metrics_r.status_code == 200
        metrics = metrics_r.json()
        assert metrics["total_cases"] >= 1

    async with SessionLocal() as db:
        case_row = (await db.execute(select(CaseRecord).where(CaseRecord.id == case_id))).scalar_one_or_none()
        assert case_row is not None
        assert case_row.closure_reason == "mitigated"

        audits = (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.action.in_(["case_created", "case_updated"]))
                .order_by(AuditLog.timestamp.desc())
            )
        ).scalars().all()
        assert any((a.details or {}).get("case_id") == case_id for a in audits)


@pytest.mark.asyncio
async def test_cases_reject_unknown_linked_entities():
    headers = {"Authorization": f"Bearer {_token('analyst')}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        bad_alert = await client.post(
            "/api/v1/cases",
            json={
                "title": "Bad alert link",
                "owner": "tier1@corp.local",
                "severity": "medium",
                "linked_alert_ids": ["missing-alert-id"],
            },
        )
        assert bad_alert.status_code == 400

        bad_incident = await client.post(
            "/api/v1/cases",
            json={
                "title": "Bad incident link",
                "owner": "tier1@corp.local",
                "severity": "medium",
                "linked_incident_ids": ["missing-incident-id"],
            },
        )
        assert bad_incident.status_code == 400
