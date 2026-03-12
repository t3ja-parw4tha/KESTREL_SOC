"""Extended alerts API tests: pagination, filters, date range, and RBAC."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.security.auth import create_access_token


def _token(role: str = "analyst") -> str:
    t, _ = create_access_token(user_id=1, role=role)
    return t


# ── Authentication ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_alerts_list_requires_auth():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/api/v1/alerts")
    assert r.status_code == 401


# ── RBAC ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_alerts_list_viewer_allowed():
    """viewer has alerts:read → should get 200."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token('viewer')}"},
    ) as client:
        r = await client.get("/api/v1/alerts")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_alerts_patch_viewer_forbidden():
    """viewer lacks alerts:update_status → should get 403."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token('viewer')}"},
    ) as client:
        r = await client.patch(
            "/api/v1/alerts/nonexistent-id",
            json={"status": "resolved"},
        )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_alerts_patch_analyst_not_forbidden():
    """analyst has alerts:update_status → should get 404 (not 403) for missing alert."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token('analyst')}"},
    ) as client:
        r = await client.patch(
            "/api/v1/alerts/nonexistent-id",
            json={"status": "resolved"},
        )
    assert r.status_code == 404


# ── Pagination ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_alerts_list_default_pagination_shape():
    """Response must include items, total, page, limit."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token()}"},
    ) as client:
        r = await client.get("/api/v1/alerts")
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "limit" in data
    assert data["page"] == 1
    assert isinstance(data["items"], list)


@pytest.mark.asyncio
async def test_alerts_list_page2():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token()}"},
    ) as client:
        r = await client.get("/api/v1/alerts?page=2&limit=5")
    assert r.status_code == 200
    data = r.json()
    assert data["page"] == 2
    assert data["limit"] == 5


@pytest.mark.asyncio
async def test_alerts_list_limit_over_max_rejected():
    """limit > 100 must be rejected with 422."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token()}"},
    ) as client:
        r = await client.get("/api/v1/alerts?limit=101")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_alerts_list_page_zero_rejected():
    """page < 1 must be rejected with 422."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token()}"},
    ) as client:
        r = await client.get("/api/v1/alerts?page=0")
    assert r.status_code == 422


# ── Filters ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_alerts_filter_severity_returns_200():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token()}"},
    ) as client:
        r = await client.get("/api/v1/alerts?severity=Critical")
    assert r.status_code == 200
    data = r.json()
    # All returned items must have severity == Critical
    for item in data["items"]:
        assert item["severity"] == "Critical"


@pytest.mark.asyncio
async def test_alerts_filter_status_returns_200():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token()}"},
    ) as client:
        r = await client.get("/api/v1/alerts?status=open")
    assert r.status_code == 200
    data = r.json()
    for item in data["items"]:
        assert item["status"] == "open"


@pytest.mark.asyncio
async def test_alerts_filter_source_returns_200():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token()}"},
    ) as client:
        r = await client.get("/api/v1/alerts?source=suricata")
    assert r.status_code == 200
    data = r.json()
    for item in data["items"]:
        assert item["source"] == "suricata"


@pytest.mark.asyncio
async def test_alerts_filter_date_range_returns_200():
    """date_from/date_to accepted and return valid response."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token()}"},
    ) as client:
        r = await client.get("/api/v1/alerts?date_from=2025-01-01&date_to=2026-12-31")
    assert r.status_code == 200
    data = r.json()
    assert "items" in data


@pytest.mark.asyncio
async def test_alerts_filter_malformed_date_ignored():
    """Malformed date_from is silently ignored (does not cause 422)."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token()}"},
    ) as client:
        r = await client.get("/api/v1/alerts?date_from=not-a-date")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_alerts_invalid_unknown_filter_ignored():
    """Unknown query params are ignored (FastAPI does not reject them)."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_token()}"},
    ) as client:
        r = await client.get("/api/v1/alerts?totally_unknown_param=xyz")
    assert r.status_code == 200
