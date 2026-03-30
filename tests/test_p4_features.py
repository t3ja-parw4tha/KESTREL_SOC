"""Integration tests for P4 features (P4-1 to P4-6)."""

from __future__ import annotations

from datetime import datetime, timezone
import io
import json
import uuid
import zipfile

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import SessionLocal
from app.main import app
from app.models import Alert, AuditLog, ComplianceReportArtifact, ScheduledReport, SSOProvider, User
from app.models.alert import AlertSeverity, AlertStatus
from app.api.sso import _emit_sso_drift_alert, _resolve_role_from_groups
from app.security.auth import create_access_token
from app.services.scheduled_reports import run_due_scheduled_reports_once


def _token(role: str, user_id: int = 1) -> str:
    token, _ = create_access_token(user_id=user_id, role=role)
    return token


@pytest.mark.asyncio
async def test_p4_1_detection_rules_crud_and_test_endpoint():
    headers = {"Authorization": f"Bearer {_token('admin')}"}
    unique = uuid.uuid4().hex[:8]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        create_r = await client.post(
            "/api/v1/detection-rules",
            json={
                "name": f"failed-login-rule-{unique}",
                "rule_type": "custom",
                "severity": "High",
                "conditions": [
                    {"field": "event_type", "operator": "equals", "value": "failed_login"},
                    {"field": "username", "operator": "contains", "value": "admin"},
                ],
            },
        )
        assert create_r.status_code == 201
        created = create_r.json()
        rule_id = created["id"]

        list_r = await client.get("/api/v1/detection-rules")
        assert list_r.status_code == 200
        assert any(r["id"] == rule_id for r in list_r.json())

        test_r = await client.post(
            f"/api/v1/detection-rules/{rule_id}/test",
            json={"event": {"event_type": "failed_login", "username": "svc-admin"}},
        )
        assert test_r.status_code == 200
        assert test_r.json()["matched"] is True

        delete_r = await client.delete(f"/api/v1/detection-rules/{rule_id}")
        assert delete_r.status_code == 204


@pytest.mark.asyncio
async def test_p4_f3_detection_rule_lifecycle_controls():
    creator_headers = {"Authorization": f"Bearer {_token('admin', user_id=101)}"}
    approver_headers = {"Authorization": f"Bearer {_token('admin', user_id=202)}"}
    unique = uuid.uuid4().hex[:8]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=creator_headers) as client:
        create_r = await client.post(
            "/api/v1/detection-rules",
            json={
                "name": f"lifecycle-rule-{unique}",
                "rule_type": "custom",
                "severity": "Medium",
                "enabled": True,
                "conditions": [{"field": "event_type", "operator": "equals", "value": "failed_login"}],
            },
        )
        assert create_r.status_code == 201
        created = create_r.json()
        rule_id = created["id"]
        assert created["version"] == 1
        assert created["approval_status"] == "approved"

        submit_r = await client.patch(
            f"/api/v1/detection-rules/{rule_id}",
            json={"severity": "High", "enabled": False, "reason": "Tune noisy detections"},
        )
        assert submit_r.status_code == 200
        pending = submit_r.json()
        assert pending["status"] == "pending_approval"

        self_approve_r = await client.post(f"/api/v1/detection-rules/{rule_id}/approve-change")
        assert self_approve_r.status_code == 409

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=approver_headers) as approver_client:
        approve_r = await approver_client.post(f"/api/v1/detection-rules/{rule_id}/approve-change")
        assert approve_r.status_code == 200
        approved = approve_r.json()
        assert approved["version"] == 2
        assert approved["approval_status"] == "approved"
        assert approved["severity"] == "High"
        assert approved["enabled"] is False

        history_r = await approver_client.get(f"/api/v1/detection-rules/{rule_id}/history")
        assert history_r.status_code == 200
        history = history_r.json()
        assert any(entry["action"] == "create" and entry["version"] == 1 for entry in history)
        assert any(entry["action"] == "update" and entry["version"] == 2 for entry in history)

        diff_r = await approver_client.get(
            f"/api/v1/detection-rules/{rule_id}/diff",
            params={"from_version": 1, "to_version": 2},
        )
        assert diff_r.status_code == 200
        diff = diff_r.json()["diff"]
        assert "severity" in diff
        assert diff["severity"]["old"] == "Medium"
        assert diff["severity"]["new"] == "High"

        rollback_r = await approver_client.post(
            f"/api/v1/detection-rules/{rule_id}/rollback",
            json={"target_version": 1, "reason": "Rollback for validation"},
        )
        assert rollback_r.status_code == 200
        rolled_back = rollback_r.json()
        assert rolled_back["version"] == 3
        assert rolled_back["severity"] == "Medium"
        assert rolled_back["enabled"] is True


@pytest.mark.asyncio
async def test_p4_f4_sso_group_mapping_default_deny_and_drift_alerts():
    async with SessionLocal() as db:
        provider = SSOProvider(
            domain=f"p4f4-{uuid.uuid4().hex[:8]}.example.com",
            name="Test IdP",
            client_id="cid",
            client_secret="secret",
            issuer_url="https://idp.example.com",
            is_active=True,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(provider)
        await db.flush()
        provider_id = provider.id
        await db.commit()

    admin_headers = {"Authorization": f"Bearer {_token('admin')}"}
    viewer_headers = {"Authorization": f"Bearer {_token('viewer')}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=viewer_headers) as viewer_client:
        denied = await viewer_client.get(f"/api/v1/auth/sso/providers/{provider_id}/group-mappings")
        assert denied.status_code == 403

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=admin_headers) as admin_client:
        create_map = await admin_client.post(
            f"/api/v1/auth/sso/providers/{provider_id}/group-mappings",
            json={"group_name": "SOC_Analysts", "role": "analyst", "is_active": True},
        )
        assert create_map.status_code == 201

        listed = await admin_client.get(f"/api/v1/auth/sso/providers/{provider_id}/group-mappings")
        assert listed.status_code == 200
        assert any(r["group_name"] == "SOC_Analysts" for r in listed.json())

    async with SessionLocal() as db:
        role = await _resolve_role_from_groups(db, provider_id=provider_id, idp_groups=["SOC_Analysts"])
        assert role == "analyst"
        denied_role = await _resolve_role_from_groups(db, provider_id=provider_id, idp_groups=["Unknown_Group"])
        assert denied_role is None

        provider = (await db.execute(select(SSOProvider).where(SSOProvider.id == provider_id))).scalar_one()
        await _emit_sso_drift_alert(
            db=db,
            provider=provider,
            email="user@example.com",
            reason="unmapped_group_default_deny",
            idp_groups=["Unknown_Group"],
            mapped_role=None,
            existing_role="analyst",
        )
        await db.commit()

        drift_audit = (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.action == "sso_group_sync_drift")
                .order_by(AuditLog.timestamp.desc())
            )
        ).scalars().first()
        assert drift_audit is not None

        drift_alert = (
            await db.execute(
                select(Alert)
                .where(Alert.source == "sso-governance", Alert.user_id == "user@example.com")
                .order_by(Alert.created_at.desc())
            )
        ).scalars().first()
        assert drift_alert is not None
        assert drift_alert.severity == AlertSeverity.HIGH


@pytest.mark.asyncio
async def test_p4_2_ldap_sync_creates_users(monkeypatch):
    headers = {"Authorization": f"Bearer {_token('admin')}"}
    unique = uuid.uuid4().hex[:8]

    def _fake_fetch():
        return [
            {
                "username": f"ldap_{unique}",
                "email": f"ldap_{unique}@example.com",
                "display_name": "LDAP Test User",
            }
        ]

    monkeypatch.setattr("app.api.sso.fetch_ldap_users", _fake_fetch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        sync_r = await client.post("/api/v1/auth/sso/ldap/sync")

    assert sync_r.status_code == 200
    assert sync_r.json()["created"] >= 1

    async with SessionLocal() as db:
        row = (
            await db.execute(select(User).where(User.username == f"ldap_{unique}"))
        ).scalar_one_or_none()
        assert row is not None
        assert row.email == f"ldap_{unique}@example.com"


@pytest.mark.asyncio
async def test_p4_3_compliance_generate_and_export():
    headers = {"Authorization": f"Bearer {_token('admin')}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        generate_r = await client.get("/api/v1/compliance/reports/generate", params={"framework": "soc2", "days": 30})
        assert generate_r.status_code == 200
        payload = generate_r.json()
        assert payload["framework"] == "soc2"
        assert "kpis" in payload

        export_r = await client.get("/api/v1/compliance/reports/export", params={"framework": "soc2", "days": 30})
        assert export_r.status_code == 200
        disposition = export_r.headers.get("content-disposition", "")
        assert "attachment;" in disposition
        assert export_r.headers.get("x-report-id")
        assert export_r.headers.get("x-report-checksum")
        assert export_r.headers.get("x-report-signature")

        with zipfile.ZipFile(io.BytesIO(export_r.content)) as zf:
            names = set(zf.namelist())
            assert "manifest.json" in names
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
            assert manifest["report_id"] == export_r.headers.get("x-report-id")
            assert manifest["checksum_algorithm"] == "sha256"
            assert manifest["signature_algorithm"] == "hmac-sha256"
            assert len(manifest["report_checksum"]) == 64
            assert len(manifest["signature"]) == 64
            assert manifest["artifacts"]["report_pdf"] in names
            assert manifest["artifacts"]["report_csv"] in names
            assert manifest["artifacts"]["report_json"] in names

    async with SessionLocal() as db:
        artifact = (
            await db.execute(
                select(ComplianceReportArtifact)
                .where(ComplianceReportArtifact.report_id == export_r.headers.get("x-report-id"))
            )
        ).scalar_one_or_none()
        assert artifact is not None
        assert artifact.framework == "soc2"
        assert artifact.report_checksum == export_r.headers.get("x-report-checksum")


@pytest.mark.asyncio
async def test_p4_4_threat_actor_attribution_by_alert_and_incident():
    alert_id = str(uuid.uuid4())
    incident_id = f"incident-{uuid.uuid4().hex[:10]}"
    headers = {"Authorization": f"Bearer {_token('analyst')}"}

    async with SessionLocal() as db:
        db.add(
            Alert(
                id=alert_id,
                title="Suspicious credential access and execution",
                source="Splunk",
                severity=AlertSeverity.HIGH,
                category="identity",
                status=AlertStatus.OPEN,
                incident_group_id=incident_id,
                mitre_techniques={
                    "items": [
                        {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Credential Access", "subtechniques": []},
                        {"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access", "subtechniques": []},
                        {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution", "subtechniques": []},
                    ]
                },
                created_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        by_alert = await client.get(f"/api/v1/threat-attribution/alerts/{alert_id}")
        assert by_alert.status_code == 200
        alert_payload = by_alert.json()
        assert alert_payload["candidates"]

        by_incident = await client.get(f"/api/v1/threat-attribution/incidents/{incident_id}")
        assert by_incident.status_code == 200
        incident_payload = by_incident.json()
        assert incident_payload["alert_count"] >= 1
        assert incident_payload["candidates"]


@pytest.mark.asyncio
async def test_p4_5_custom_dashboards_crud():
    headers = {"Authorization": f"Bearer {_token('analyst')}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        create_r = await client.post(
            "/api/v1/custom-dashboards",
            json={
                "name": "My Tier-1 Dashboard",
                "description": "Queue + investigations",
                "is_default": True,
                "widgets": [
                    {"type": "alerts_by_severity", "x": 0, "y": 0, "w": 6, "h": 4},
                    {"type": "top_sources", "x": 6, "y": 0, "w": 6, "h": 4},
                ],
            },
        )
        assert create_r.status_code == 201
        created = create_r.json()

        list_r = await client.get("/api/v1/custom-dashboards")
        assert list_r.status_code == 200
        assert any(row["id"] == created["id"] for row in list_r.json())

        patch_r = await client.patch(
            f"/api/v1/custom-dashboards/{created['id']}",
            json={"name": "My Updated Dashboard", "is_default": True},
        )
        assert patch_r.status_code == 200
        assert patch_r.json()["name"] == "My Updated Dashboard"

        del_r = await client.delete(f"/api/v1/custom-dashboards/{created['id']}")
        assert del_r.status_code == 204


@pytest.mark.asyncio
async def test_p4_6_scheduled_reports_run_now():
    headers = {"Authorization": f"Bearer {_token('analyst')}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        create_r = await client.post(
            "/api/v1/scheduled-reports",
            json={
                "name": "Weekly SOC2 executive",
                "framework": "soc2",
                "cadence": "weekly",
                "recipients": ["secops@example.com", "ciso@example.com"],
                "delivery_format": "pdf",
            },
        )
        assert create_r.status_code == 201
        created = create_r.json()

        run_r = await client.post(f"/api/v1/scheduled-reports/{created['id']}/run-now")
        assert run_r.status_code == 200
        run_payload = run_r.json()
        assert run_payload["report_framework"] == "soc2"
        assert run_payload["delivered_to"] == ["secops@example.com", "ciso@example.com"]
        assert run_payload["next_run_at"]

        del_r = await client.delete(f"/api/v1/scheduled-reports/{created['id']}")
        assert del_r.status_code == 204


@pytest.mark.asyncio
async def test_p4_f1_scheduled_delivery_engine_processes_due_reports(monkeypatch):
    sent_to: list[str] = []

    async def _fake_send_alert_email(to_email: str, subject: str, body_plain: str, body_html: str | None = None) -> bool:
        assert "Scheduled" in subject
        assert "KESTREL Scheduled Compliance Report" in body_plain
        sent_to.append(to_email)
        return True

    monkeypatch.setattr("app.services.scheduled_reports.send_alert_email", _fake_send_alert_email)

    now = datetime.now(timezone.utc)

    async with SessionLocal() as db:
        row = ScheduledReport(
            owner="1",
            name="Daily SOC2 Ops",
            framework="soc2",
            cadence="daily",
            recipients=["secops@example.com", "ciso@example.com"],
            delivery_format="pdf",
            is_active=True,
            next_run_at=now,
        )
        db.add(row)
        await db.commit()
        await db.refresh(row)
        schedule_id = row.id

    summary = await run_due_scheduled_reports_once(now=now)
    assert summary["due"] >= 1
    assert summary["processed"] >= 1
    assert summary["delivered"] >= 2
    assert summary["failed"] == 0

    async with SessionLocal() as db:
        updated = (await db.execute(select(ScheduledReport).where(ScheduledReport.id == schedule_id))).scalar_one()
        assert updated.last_run_at is not None
        assert updated.next_run_at is not None
        expected_floor = now.replace(tzinfo=None)
        assert updated.next_run_at > expected_floor

        audits = (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.action == "scheduled_report_delivery")
                .order_by(AuditLog.timestamp.desc())
            )
        ).scalars().all()
        assert any((a.details or {}).get("schedule_id") == schedule_id for a in audits)

    assert sent_to == ["secops@example.com", "ciso@example.com"]
