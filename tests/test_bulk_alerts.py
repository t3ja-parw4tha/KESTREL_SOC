"""Tests for bulk alerts API: auth, validation, and permission."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.security.auth import create_access_token


def _token(role: str = "analyst") -> str:
    t, _ = create_access_token(user_id=1, role=role)
    return t


@pytest.mark.asyncio
async def test_bulk_alerts_requires_auth():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        r = await client.patch(
            "/api/v1/alerts/bulk",
            json={"alert_ids": ["a"], "status": "open"},
        )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_bulk_alerts_viewer_forbidden():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token('viewer')}"},
    ) as client:
        r = await client.patch(
            "/api/v1/alerts/bulk",
            json={"alert_ids": ["some-id"], "status": "resolved"},
        )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_bulk_alerts_validation_empty_ids():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token()}"},
    ) as client:
        r = await client.patch(
            "/api/v1/alerts/bulk",
            json={"alert_ids": [], "status": "resolved"},
        )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_bulk_alerts_validation_no_action():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token()}"},
    ) as client:
        r = await client.patch(
            "/api/v1/alerts/bulk",
            json={"alert_ids": ["valid-uuid-here"]},
        )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_bulk_alerts_validation_invalid_status():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token()}"},
    ) as client:
        r = await client.patch(
            "/api/v1/alerts/bulk",
            json={"alert_ids": ["550e8400-e29b-41d4-a716-446655440000"], "status": "invalid_status"},
        )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_bulk_alerts_accepts_valid_body_analyst():
    """With analyst token, valid body returns 200 (may update 0 if no matching alerts)."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token()}"},
    ) as client:
        r = await client.patch(
            "/api/v1/alerts/bulk",
            json={
                "alert_ids": ["550e8400-e29b-41d4-a716-446655440000"],
                "status": "resolved",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert "updated" in data
    assert "failed" in data
    assert "error_ids" in data
    assert isinstance(data["updated"], int)
    assert isinstance(data["failed"], int)
