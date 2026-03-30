"""API tests for built-in playbook library installation (P3-1)."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.security.auth import create_access_token


def _token(role: str) -> str:
    token, _ = create_access_token(user_id=1, role=role)
    return token


@pytest.mark.asyncio
async def test_playbook_library_list_requires_auth():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/api/v1/playbooks/library")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_playbook_library_list_contains_required_templates():
    headers = {"Authorization": f"Bearer {_token('analyst')}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        r = await client.get("/api/v1/playbooks/library")

    assert r.status_code == 200
    keys = {item["key"] for item in r.json()}
    assert {"phishing_triage", "ransomware_triage", "bruteforce_triage"}.issubset(keys)


@pytest.mark.asyncio
async def test_playbook_library_install_requires_admin():
    headers = {"Authorization": f"Bearer {_token('senior_analyst')}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        r = await client.post(
            "/api/v1/playbooks/library/install",
            json={"template_keys": ["phishing_triage"]},
        )

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_playbook_library_install_and_idempotent_skip():
    headers = {"Authorization": f"Bearer {_token('admin')}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers) as client:
        first = await client.post(
            "/api/v1/playbooks/library/install",
            json={
                "template_keys": ["phishing_triage", "ransomware_triage"],
                "overwrite_existing": True,
            },
        )
        assert first.status_code == 200
        body = first.json()
        assert set(body["installed"]) == {"phishing_triage", "ransomware_triage"}

        second = await client.post(
            "/api/v1/playbooks/library/install",
            json={"template_keys": ["phishing_triage", "ransomware_triage"]},
        )
        assert second.status_code == 200
        second_body = second.json()
        assert second_body["installed"] == []
        assert set(second_body["skipped"]) == {"phishing_triage", "ransomware_triage"}
