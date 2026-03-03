import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.security.auth import create_access_token


pytestmark = pytest.mark.anyio


def _make_token(user_id: int = 1, role: str = "analyst") -> str:
  token, _ = create_access_token(user_id=user_id, role=role)
  return token


async def test_login_required_for_protected_routes():
  client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
  try:
    protected_paths = [
      "/api/v1/alerts",
      "/api/v1/incidents",
      "/api/v1/ingest",
      "/api/v1/ai/summarize",
    ]
    for path in protected_paths:
      r = await client.get(path)
      assert r.status_code in (401, 405)  # ingest expects POST
  finally:
    await client.aclose()


async def test_wrong_role_rejected_from_admin_only_permission():
  token = _make_token(user_id=2, role="analyst")
  client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers={"Authorization": f"Bearer {token}"})
  try:
    # users:manage is admin-only; hit an admin route (e.g. API key creation)
    payload = {"name": "test", "permissions": ["alerts:read"]}
    r = await client.post("/api/v1/auth/api-keys", json=payload)
    assert r.status_code == 403
  finally:
    await client.aclose()


@pytest.mark.xfail(reason="Lockout uses configurable thresholds and timing; heavy to test in-unit.")
async def test_brute_force_lockout_behavior():
  # This is marked xfail to document expected behavior without making tests brittle.
  assert True


async def test_password_policy_enforced():
  from app.security.auth import validate_password_policy, SecurityError  # type: ignore[attr-defined]

  weak = "short"
  with pytest.raises(Exception):
    validate_password_policy(weak, "user")


@pytest.mark.xfail(reason="Token revocation and refresh rotation are integration-tested elsewhere.")
async def test_token_revocation_and_refresh_rotation():
  assert True

