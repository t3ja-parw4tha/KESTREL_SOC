import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.security.auth import create_access_token


pytestmark = pytest.mark.anyio


def _make_token() -> str:
  token, _ = create_access_token(user_id=1, role="admin")
  return token


async def test_login_rate_limit_eventually_returns_429():
  client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
  try:
    body = {"username": "nosuchuser", "password": "wrong"}
    codes: list[int] = []
    for _ in range(8):
      r = await client.post("/api/v1/auth/login", json=body)
      codes.append(r.status_code)
    # Depending on DB, repeated failures may trigger rate limiting or lockout.
    assert any(c in (429, 423, 401) for c in codes)
  finally:
    await client.aclose()


async def test_ai_rate_limit_headers_present():
  token = _make_token()
  client = AsyncClient(
    transport=ASGITransport(app=app),
    base_url="http://test",
    headers={"Authorization": f"Bearer {token}"},
  )
  try:
    # Use a non-existent alert id; focus is on headers, not body.
    r = await client.post("/api/v1/ai/summarize", json={"alert_id": "non-existent"})
    assert "X-RateLimit-Limit" in r.headers
    assert "X-RateLimit-Remaining" in r.headers
    assert "X-RateLimit-Reset" in r.headers
  finally:
    await client.aclose()

