"""Lightweight high-risk input fuzz tests for admin/authz paths (SN-5)."""

from __future__ import annotations

import json

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.security.auth import create_access_token

pytestmark = pytest.mark.anyio


MALFORMED_PAYLOADS = [
    "",
    "{",
    "[]",
    "{\"name\":\"x\",\"rule_type\":\"custom\",\"conditions\":\"not-array\"}",
    "{\"name\":\"x\",\"rule_type\":\"sigma\",\"sigma_yaml\":123}",
]


def _token(role: str = "admin", user_id: int = 999) -> str:
    token, _ = create_access_token(user_id=user_id, role=role)
    return token


async def test_high_risk_admin_endpoints_do_not_500_on_malformed_json() -> None:
    token = _token("admin")
    endpoints = [
        "/api/v1/detection-rules",
        "/api/v1/scheduled-reports",
        "/api/v1/resilience/secrets/policies",
        "/api/v1/resilience/dr/drills",
    ]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for ep in endpoints:
            for raw in MALFORMED_PAYLOADS:
                r = await client.post(
                    ep,
                    content=raw,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                )
                # 4xx expected; never 5xx.
                assert r.status_code < 500, f"{ep} returned {r.status_code} for payload={raw!r}"


async def test_detection_rule_test_endpoint_handles_injection_like_strings() -> None:
    token = _token("admin")
    payload = {
        "event": {
            "source": "'; DROP TABLE detection_rules;--",
            "nested": {"k": "<script>alert(1)</script>"},
            "blob": "A" * 5000,
        }
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Rule id may not exist in clean test db, so 404 is valid; must not 5xx.
        r = await client.post(
            "/api/v1/detection-rules/1/test",
            data=json.dumps(payload),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
    assert r.status_code < 500
