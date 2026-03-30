"""Integration tests for P5 features."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import SessionLocal
from app.main import app
from app.models import Alert, BackgroundJob, EvidenceCustodyEvent, Playbook
from app.models.alert import AlertSeverity, AlertStatus
from app.security.auth import create_access_token
from app.services.job_queue import enqueue_job, process_due_jobs_once
from app.models.source_health import SourceHealth
from app.services.source_health import evaluate_stale_feeds, record_source_ingestion
from app.services.soar import run_playbooks_for_alert


def _token(role: str = "analyst", user_id: int = 1) -> str:
    token, _ = create_access_token(user_id=user_id, role=role)
    return token


async def _seed_alert() -> str:
    alert_id = str(uuid.uuid4())
    async with SessionLocal() as db:
        db.add(
            Alert(
                id=alert_id,
                title="Potential data exfiltration",
                source="unit-test",
                severity=AlertSeverity.HIGH,
                category="network",
                status=AlertStatus.OPEN,
                source_ip="198.51.100.10",
            )
        )
        await db.commit()
    return alert_id


@pytest.mark.asyncio
async def test_p5_2_chain_of_custody_hash_verify_and_legal_hold_enforcement():
    alert_id = await _seed_alert()
    analyst_headers = {"Authorization": f"Bearer {_token('analyst', user_id=101)}"}
    admin_headers = {"Authorization": f"Bearer {_token('admin', user_id=202)}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=analyst_headers) as analyst_client:
        file_r = await analyst_client.post(
            f"/api/v1/evidence/alerts/{alert_id}/file",
            files={"file": ("custody.txt", b"hello-custody-chain\n", "text/plain")},
            data={"notes": "forensics artifact"},
        )
        assert file_r.status_code == 201
        evidence = file_r.json()
        evidence_id = evidence["id"]

        verify_hash = await analyst_client.get(f"/api/v1/evidence/{evidence_id}/verify-hash")
        assert verify_hash.status_code == 200
        verify_payload = verify_hash.json()
        assert verify_payload["valid"] is True
        assert verify_payload["expected_sha256"] == verify_payload["computed_sha256"]

        chain_ok = await analyst_client.get(f"/api/v1/evidence/{evidence_id}/verify-chain")
        assert chain_ok.status_code == 200
        assert chain_ok.json()["valid"] is True

    # Tamper one custody event hash directly and verify chain detects breakage.
    async with SessionLocal() as db:
        first_event = (
            await db.execute(
                select(EvidenceCustodyEvent)
                .where(EvidenceCustodyEvent.evidence_id == evidence_id)
                .order_by(EvidenceCustodyEvent.created_at.asc(), EvidenceCustodyEvent.id.asc())
            )
        ).scalars().first()
        assert first_event is not None
        first_event.event_hash = "0" * 64
        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=analyst_headers) as analyst_client:
        chain_bad = await analyst_client.get(f"/api/v1/evidence/{evidence_id}/verify-chain")
        assert chain_bad.status_code == 200
        chain_bad_payload = chain_bad.json()
        assert chain_bad_payload["valid"] is False
        assert chain_bad_payload["broken_event_id"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=admin_headers) as admin_client:
        hold_enable = await admin_client.post(
            f"/api/v1/evidence/{evidence_id}/legal-hold",
            json={"enabled": True, "reason": "litigation-hold"},
        )
        assert hold_enable.status_code == 200
        assert hold_enable.json()["enabled"] is True

        blocked_delete = await admin_client.delete(f"/api/v1/evidence/{evidence_id}")
        assert blocked_delete.status_code == 409

        hold_disable = await admin_client.post(
            f"/api/v1/evidence/{evidence_id}/legal-hold",
            json={"enabled": False, "reason": "released"},
        )
        assert hold_disable.status_code == 200
        assert hold_disable.json()["enabled"] is False

        delete_ok = await admin_client.delete(f"/api/v1/evidence/{evidence_id}")
        assert delete_ok.status_code == 204


@pytest.mark.asyncio
async def test_p5_3_durable_queue_idempotency_and_dead_letter(monkeypatch):
    idem_key = f"p5-3-idempotency-{uuid.uuid4().hex[:10]}"
    async with SessionLocal() as db:
        first = await enqueue_job(
            db,
            job_type="alerts_enrichment",
            payload={"alert_ids": ["a-1"]},
            idempotency_key=idem_key,
            max_attempts=2,
        )
        second = await enqueue_job(
            db,
            job_type="alerts_enrichment",
            payload={"alert_ids": ["a-1"]},
            idempotency_key=idem_key,
            max_attempts=2,
        )
        await db.commit()

    assert first.id == second.id

    async with SessionLocal() as db:
        rows = (
            await db.execute(
                select(BackgroundJob).where(BackgroundJob.idempotency_key == idem_key)
            )
        ).scalars().all()
        assert len(rows) == 1

    async def _always_fail(alert_ids: list[str]) -> None:  # noqa: ARG001
        raise RuntimeError("forced-enrichment-failure")

    monkeypatch.setattr("app.services.alert_tasks.run_enrichment_for_alerts", _always_fail)

    first_run = await process_due_jobs_once(limit=10, job_types=["alerts_enrichment"])
    assert first_run["picked"] >= 1
    assert first_run["failed"] >= 1

    # Force immediate second attempt by resetting next_run_at in DB.
    async with SessionLocal() as db:
        job = (
            await db.execute(
                select(BackgroundJob).where(BackgroundJob.idempotency_key == idem_key)
            )
        ).scalar_one()
        job.next_run_at = job.created_at
        await db.commit()

    second_run = await process_due_jobs_once(limit=10, job_types=["alerts_enrichment"])
    assert second_run["dead_letter"] >= 1

    async with SessionLocal() as db:
        job = (
            await db.execute(
                select(BackgroundJob).where(BackgroundJob.idempotency_key == idem_key)
            )
        ).scalar_one()
        assert job.status == "dead_letter"
        assert job.attempts == 2
        assert "forced-enrichment-failure" in (job.last_error or "")


@pytest.mark.asyncio
async def test_p5_4_source_health_dashboard_and_error_budget():
    async with SessionLocal() as db:
        await record_source_ingestion(
            db,
            source_id="splunk",
            source_name="Splunk Enterprise",
            source_type="SIEM",
            events_received=20,
            alerts_ingested=12,
            processing_errors=0,
            success=True,
            ingest_lag_seconds=1.2,
        )
        await record_source_ingestion(
            db,
            source_id="splunk",
            source_name="Splunk Enterprise",
            source_type="SIEM",
            events_received=10,
            alerts_ingested=0,
            processing_errors=10,
            success=False,
            last_error="unit-test-ingest-failure",
            ingest_lag_seconds=2.8,
        )
        await db.commit()

    headers = {"Authorization": f"Bearer {_token('admin', user_id=909)}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        r = await client.get("/api/v1/sources/health")
        assert r.status_code == 200
        data = r.json()
        assert data["summary"]["tracked_sources"] >= 1

        splunk = next((item for item in data["items"] if item["source_id"] == "splunk"), None)
        assert splunk is not None
        assert splunk["window_successes"] >= 1
        assert splunk["window_failures"] >= 1
        assert splunk["error_budget_remaining_pct"] <= 1.0
        assert splunk["last_error_message"] == "unit-test-ingest-failure"


@pytest.mark.asyncio
async def test_p5_4_stale_source_auto_alert_and_recovery_resolution():
    source_id = f"splunk-p5-4-{uuid.uuid4().hex[:8]}"
    stale_title = f"Stale source feed: {source_id}"

    async with SessionLocal() as db:
        await record_source_ingestion(
            db,
            source_id=source_id,
            source_name="Splunk Enterprise",
            source_type="SIEM",
            events_received=5,
            alerts_ingested=5,
            processing_errors=0,
            success=True,
            ingest_lag_seconds=1.0,
        )
        row = await db.get(SourceHealth, source_id)
        assert row is not None
        row.last_success_at = datetime.now(timezone.utc) - timedelta(hours=3)
        row.stale_alert_active = False
        await db.commit()

    async with SessionLocal() as db:
        result = await evaluate_stale_feeds(db)
        await db.commit()
        assert result["opened"] >= 1

    async with SessionLocal() as db:
        stale_alert = (
            await db.execute(select(Alert).where(Alert.title == stale_title))
        ).scalar_one_or_none()
        assert stale_alert is not None
        assert stale_alert.status == AlertStatus.OPEN

        row = await db.get(SourceHealth, source_id)
        assert row is not None
        row.last_success_at = datetime.now(timezone.utc)
        await db.commit()

    async with SessionLocal() as db:
        result = await evaluate_stale_feeds(db)
        await db.commit()
        assert result["resolved"] >= 1

    async with SessionLocal() as db:
        stale_alert = (
            await db.execute(select(Alert).where(Alert.title == stale_title))
        ).scalar_one_or_none()
        assert stale_alert is not None
        assert stale_alert.status == AlertStatus.RESOLVED


@pytest.mark.asyncio
async def test_p5_5_detection_qa_replay_gate_endpoint():
    headers = {"Authorization": f"Bearer {_token('admin', user_id=1001)}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        replay = await client.post(
            "/api/v1/resilience/detection-qa/replay",
            json={
                "dataset_name": "last_30d_alerts",
                "replay_window_days": 30,
                "min_precision_pct": 0,
                "min_recall_pct": 0,
            },
        )
        assert replay.status_code == 200
        payload = replay.json()
        assert payload["id"].startswith("QA-")
        assert payload["sample_size"] >= 1

        history = await client.get("/api/v1/resilience/detection-qa/replays")
        assert history.status_code == 200
        assert any(item["id"] == payload["id"] for item in history.json())


@pytest.mark.asyncio
async def test_p5_6_hunting_workspace_saved_query_run_results_and_pivot():
    headers = {
        "Authorization": f"Bearer {_token('analyst', user_id=1002)}",
        "X-Org-Id": "acme",
        "X-Workspace-Id": "soc-a",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        created = await client.post(
            "/api/v1/hunting/queries",
            json={
                "name": "Network Hunt",
                "description": "Find network alerts",
                "query": "where category contains network",
                "type": "kql",
            },
        )
        assert created.status_code == 201
        hunt_id = created.json()["id"]

        listed = await client.get("/api/v1/hunting/queries")
        assert listed.status_code == 200
        assert any(item["id"] == hunt_id for item in listed.json())

        run = await client.post(f"/api/v1/hunting/queries/{hunt_id}/run")
        assert run.status_code == 200
        assert "results" in run.json()

        results = await client.get(f"/api/v1/hunting/queries/{hunt_id}/results")
        assert results.status_code == 200

        pivot = await client.get(f"/api/v1/hunting/queries/{hunt_id}/pivot-alerts")
        assert pivot.status_code == 200
        assert "alert_ids" in pivot.json()


@pytest.mark.asyncio
async def test_p5_7_secret_rotation_policy_and_overdue_check():
    headers = {"Authorization": f"Bearer {_token('admin', user_id=1003)}"}
    old_date = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        upsert = await client.post(
            "/api/v1/resilience/secrets/policies",
            json={
                "secret_name": "OPENAI_API_KEY",
                "provider": "vault",
                "rotation_days": 90,
                "owner": "secops",
                "last_rotated_at": old_date,
            },
        )
        assert upsert.status_code == 200

        check = await client.get("/api/v1/resilience/secrets/rotation-check")
        assert check.status_code == 200
        payload = check.json()
        assert payload["total"] >= 1
        assert payload["overdue"] >= 1


@pytest.mark.asyncio
async def test_p5_8_tenant_workspace_boundaries_and_isolation_check():
    headers = {"Authorization": f"Bearer {_token('admin', user_id=1004)}"}
    ws_a = f"ws-{uuid.uuid4().hex[:6]}"
    ws_b = f"ws-{uuid.uuid4().hex[:6]}"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        r1 = await client.post("/api/v1/resilience/tenants/workspaces", json={"org_id": "org-a", "workspace_id": ws_a})
        r2 = await client.post("/api/v1/resilience/tenants/workspaces", json={"org_id": "org-b", "workspace_id": ws_b})
        assert r1.status_code == 200
        assert r2.status_code == 200

        listed = await client.get("/api/v1/resilience/tenants/workspaces")
        assert listed.status_code == 200
        assert any(item["workspace_id"] == ws_a for item in listed.json())
        assert any(item["workspace_id"] == ws_b for item in listed.json())

        isolation = await client.get("/api/v1/resilience/tenants/isolation-check")
        assert isolation.status_code == 200
        assert isolation.json()["status"] == "pass"


@pytest.mark.asyncio
async def test_p5_9_high_risk_runbook_requires_approval_then_executes():
    alert_id = await _seed_alert()

    async with SessionLocal() as db:
        pb = Playbook(
            name=f"High Risk PB {uuid.uuid4().hex[:6]}",
            description="Requires approval",
            is_active=True,
            trigger_type="alert_created",
            conditions=[{"field": "category", "operator": "equals", "value": "network"}],
            actions=[{"type": "set_status", "value": "resolved"}],
        )
        db.add(pb)
        await db.flush()
        alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one()
        await run_playbooks_for_alert(db, alert)
        await db.commit()

    headers = {"Authorization": f"Bearer {_token('admin', user_id=1005)}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        pending = await client.get("/api/v1/resilience/runbook-approvals")
        assert pending.status_code == 200
        req = next((x for x in pending.json() if x["alert_id"] == alert_id and x["status"] == "pending"), None)
        assert req is not None

        approve = await client.post(f"/api/v1/resilience/runbook-approvals/{req['id']}/approve")
        assert approve.status_code == 200

        execute = await client.post(f"/api/v1/resilience/runbook-approvals/{req['id']}/execute")
        assert execute.status_code == 200

    async with SessionLocal() as db:
        alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one()
        assert alert.status == AlertStatus.RESOLVED


@pytest.mark.asyncio
async def test_p5_10_backup_restore_drill_lifecycle():
    headers = {"Authorization": f"Bearer {_token('admin', user_id=1006)}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        created = await client.post(
            "/api/v1/resilience/dr/drills",
            json={"target": "primary-db", "rpo_target_minutes": 60, "rto_target_minutes": 120},
        )
        assert created.status_code == 200
        drill_id = created.json()["id"]

        ran = await client.post(f"/api/v1/resilience/dr/drills/{drill_id}/run")
        assert ran.status_code == 200
        assert ran.json()["status"] in {"passed", "failed"}

        listed = await client.get("/api/v1/resilience/dr/drills")
        assert listed.status_code == 200
        assert any(item["id"] == drill_id for item in listed.json())


@pytest.mark.asyncio
async def test_p5_11_ai_governance_feedback_and_metrics():
    alert_id = await _seed_alert()
    analyst_headers = {"Authorization": f"Bearer {_token('analyst', user_id=1007)}"}
    reader_headers = {"Authorization": f"Bearer {_token('senior_analyst', user_id=1008)}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=analyst_headers) as client:
        created = await client.post(
            "/api/v1/resilience/ai-governance/feedback",
            json={
                "alert_id": alert_id,
                "rating": 2,
                "hallucination_flag": True,
                "confidence_score": 0.42,
                "comments": "model over-attributed",
            },
        )
        assert created.status_code == 200

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=reader_headers) as client:
        metrics = await client.get("/api/v1/resilience/ai-governance/metrics")
        assert metrics.status_code == 200
        payload = metrics.json()
        assert payload["feedback_count"] >= 1
        assert payload["hallucination_rate"] >= 0


@pytest.mark.asyncio
async def test_p5_12_attack_coverage_by_source_quality_endpoint():
    headers = {"Authorization": f"Bearer {_token('admin', user_id=1009)}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        res = await client.get("/api/v1/resilience/mitre/source-quality")
        assert res.status_code == 200
        payload = res.json()
        assert "items" in payload
        assert "total_sources" in payload
