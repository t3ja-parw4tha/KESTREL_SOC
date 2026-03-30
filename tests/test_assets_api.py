"""Assets API tests for CMDB inventory workflows."""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.security.auth import create_access_token


def _token(role: str = "analyst") -> str:
    token, _ = create_access_token(user_id=1, role=role)
    return token


@pytest.mark.asyncio
async def test_assets_requires_auth():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/api/v1/assets")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_assets_viewer_can_read_but_not_write():
    headers = {"Authorization": f"Bearer {_token('viewer')}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        list_r = await client.get("/api/v1/assets")
        create_r = await client.post(
            "/api/v1/assets",
            json={
                "asset_id": f"asset-{uuid.uuid4().hex[:8]}",
                "criticality": "high",
            },
        )
    assert list_r.status_code == 200
    assert create_r.status_code == 403


@pytest.mark.asyncio
async def test_assets_create_list_update_roundtrip():
    headers = {"Authorization": f"Bearer {_token('analyst')}"}
    asset_id = f"asset-{uuid.uuid4().hex[:10]}"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        create_r = await client.post(
            "/api/v1/assets",
            json={
                "asset_id": asset_id,
                "hostname": "srv-app-01",
                "ip_address": "10.1.5.20",
                "owner": "secops@corp.local",
                "department": "Security Operations",
                "criticality": "critical",
                "risk_score": 92,
                "tags": ["production", "internet-facing"],
            },
        )
        assert create_r.status_code == 201
        created = create_r.json()
        assert created["asset_id"] == asset_id
        assert created["criticality"] == "critical"
        assert created["owner"] == "secops@corp.local"

        list_r = await client.get(f"/api/v1/assets?search={asset_id}")
        assert list_r.status_code == 200
        data = list_r.json()
        assert data["total"] >= 1
        assert any(item["asset_id"] == asset_id for item in data["items"])

        update_r = await client.patch(
            f"/api/v1/assets/{asset_id}",
            json={"owner": "soc-lead@corp.local", "criticality": "high", "risk_score": 85},
        )
        assert update_r.status_code == 200
        updated = update_r.json()
        assert updated["owner"] == "soc-lead@corp.local"
        assert updated["criticality"] == "high"
        assert updated["risk_score"] == 85


@pytest.mark.asyncio
async def test_assets_invalid_criticality_rejected():
    headers = {"Authorization": f"Bearer {_token('analyst')}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        r = await client.post(
            "/api/v1/assets",
            json={
                "asset_id": f"asset-{uuid.uuid4().hex[:8]}",
                "criticality": "urgent",
            },
        )
    assert r.status_code == 400
