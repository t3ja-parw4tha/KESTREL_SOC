"""API tests for IOC watchlist CRUD (P3-2)."""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.security.auth import create_access_token


def _token(role: str) -> str:
    token, _ = create_access_token(user_id=1, role=role)
    return token


@pytest.mark.asyncio
async def test_watchlist_requires_auth():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/api/v1/watchlist")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_watchlist_viewer_read_only():
    headers = {"Authorization": f"Bearer {_token('viewer')}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        read_r = await client.get("/api/v1/watchlist")
        write_r = await client.post(
            "/api/v1/watchlist",
            json={"indicator": f"mal-{uuid.uuid4().hex[:8]}.evil", "indicator_type": "domain"},
        )

    assert read_r.status_code == 200
    assert write_r.status_code == 403


@pytest.mark.asyncio
async def test_watchlist_create_update_delete_roundtrip():
    headers = {"Authorization": f"Bearer {_token('analyst')}"}
    domain = f"bad-{uuid.uuid4().hex[:8]}.example"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        create_r = await client.post(
            "/api/v1/watchlist",
            json={
                "indicator": domain,
                "indicator_type": "domain",
                "confidence": 88,
                "notes": "Known C2 domain",
            },
        )
        assert create_r.status_code == 201
        created = create_r.json()
        assert created["indicator"] == domain
        assert created["indicator_type"] == "domain"

        list_r = await client.get("/api/v1/watchlist")
        assert list_r.status_code == 200
        assert any(row["id"] == created["id"] for row in list_r.json())

        update_r = await client.patch(
            f"/api/v1/watchlist/{created['id']}",
            json={"confidence": 95, "is_active": False},
        )
        assert update_r.status_code == 200
        updated = update_r.json()
        assert updated["confidence"] == 95
        assert updated["is_active"] is False

        del_r = await client.delete(f"/api/v1/watchlist/{created['id']}")
        assert del_r.status_code == 204
