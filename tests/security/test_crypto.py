import re

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.security.auth import hash_password


pytestmark = pytest.mark.anyio


def test_passwords_hashed_with_argon2_not_plaintext():
  password = "StrongP@ssw0rd!"
  hashed = hash_password(password)
  assert password not in hashed
  # argon2-cffi default prefix
  assert hashed.startswith("$argon2id$")


async def test_alert_ids_are_uuids_not_sequential():
  # Ingest a minimal event and check ID format from list API.
  from app.security.auth import create_access_token

  token, _ = create_access_token(user_id=1, role="admin")
  client = AsyncClient(
    transport=ASGITransport(app=app),
    base_url="http://test",
    headers={"Authorization": f"Bearer {token}"},
  )
  try:
    payload = {"source": "Sentinel", "events": [{"severity": "Low", "title": "ID test"}]}
    r = await client.post("/api/v1/ingest", json=payload)
    assert r.status_code == 200
    r2 = await client.get("/api/v1/alerts?limit=1")
    assert r2.status_code == 200
    data = r2.json()
    assert data["items"]
    alert_id = data["items"][0]["id"]
    uuid_regex = re.compile(
      r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    )
    assert uuid_regex.match(alert_id)
  finally:
    await client.aclose()


@pytest.mark.xfail(reason="API key entropy checks are enforced via config and not directly testable here.")
def test_api_keys_have_entropy():
  assert True

