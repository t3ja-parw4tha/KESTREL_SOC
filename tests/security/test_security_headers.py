import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


pytestmark = pytest.mark.anyio


async def test_security_headers_present_on_health():
  client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
  try:
    r = await client.get("/health")
    assert "Content-Security-Policy" in r.headers
    assert "Strict-Transport-Security" in r.headers
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    # Server header should be removed or not reveal implementation.
    server = r.headers.get("Server", "")
    assert "uvicorn" not in server.lower()
  finally:
    await client.aclose()

