"""Tests for P2 evidence handling, AI chat, and shift handover endpoints."""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import SessionLocal
from app.main import app
from app.models import Alert
from app.models.alert import AlertSeverity, AlertStatus
from app.security.auth import create_access_token


def _token(role: str = "analyst") -> str:
    token, _ = create_access_token(user_id=1, role=role)
    return token


async def _seed_alert() -> str:
    alert_id = str(uuid.uuid4())
    async with SessionLocal() as db:
        alert = Alert(
            id=alert_id,
            title="Suspicious authentication burst",
            source="unit-test",
            severity=AlertSeverity.HIGH,
            category="identity",
            status=AlertStatus.OPEN,
            source_ip="192.0.2.10",
            asset_id="srv-auth-01",
        )
        db.add(alert)
        await db.commit()
    return alert_id


@pytest.mark.asyncio
async def test_evidence_write_requires_permission():
    alert_id = await _seed_alert()
    headers = {"Authorization": f"Bearer {_token('viewer')}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        r = await client.post(
            f"/api/v1/evidence/alerts/{alert_id}/url",
            json={"url": "https://example.com/report"},
        )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_alert_evidence_url_file_and_download_roundtrip():
    alert_id = await _seed_alert()
    headers = {"Authorization": f"Bearer {_token('analyst')}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        add_url = await client.post(
            f"/api/v1/evidence/alerts/{alert_id}/url",
            json={"url": "https://example.com/intel", "notes": "Primary intel reference"},
        )
        assert add_url.status_code == 201

        add_file = await client.post(
            f"/api/v1/evidence/alerts/{alert_id}/file",
            files={"file": ("ioc.txt", b"ioc,confidence\n1.2.3.4,high\n", "text/plain")},
            data={"notes": "IOC export"},
        )
        assert add_file.status_code == 201
        file_item = add_file.json()

        listed = await client.get(f"/api/v1/evidence/alerts/{alert_id}")
        assert listed.status_code == 200
        items = listed.json()
        assert len(items) >= 2

        download = await client.get(f"/api/v1/evidence/{file_item['id']}/download")
        assert download.status_code == 200
        assert download.content.startswith(b"ioc,confidence")


@pytest.mark.asyncio
async def test_alert_ai_chat_persists_history(monkeypatch):
    alert_id = await _seed_alert()

    async def _fake_completion(system: str, prompt: str) -> str:  # noqa: ARG001
        return "Likely credential attack. Prioritize account containment."

    monkeypatch.setattr("app.api.ai_assistant.run_ai_completion", _fake_completion)

    headers = {"Authorization": f"Bearer {_token('analyst')}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        sent = await client.post(
            "/api/v1/ai-assistant/chat",
            json={
                "context_type": "alert",
                "context_id": alert_id,
                "message": "What is the most likely threat path?",
            },
        )
        assert sent.status_code == 200
        reply = sent.json()["reply"]
        assert "Likely credential attack" in reply["message"]

        history = await client.get(
            "/api/v1/ai-assistant/history",
            params={"context_type": "alert", "context_id": alert_id},
        )
        assert history.status_code == 200
        rows = history.json()
        assert len(rows) == 2
        assert rows[0]["role"] == "user"
        assert rows[1]["role"] == "assistant"


@pytest.mark.asyncio
async def test_shift_handover_generation(monkeypatch):
    async def _fake_completion(system: str, prompt: str) -> str:  # noqa: ARG001
        return "Executive Summary\n- All critical investigations are actively tracked."

    monkeypatch.setattr("app.api.ai_assistant.run_ai_completion", _fake_completion)

    headers = {"Authorization": f"Bearer {_token('senior_analyst')}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        r = await client.post("/api/v1/ai-assistant/shift-handover")
    assert r.status_code == 200
    body = r.json()
    assert "Executive Summary" in body["handover"]
    assert isinstance(body["open_incidents"], int)
