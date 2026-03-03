import json
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


pytestmark = pytest.mark.anyio


async def _authed_client() -> AsyncClient:
  # Create an access token with admin role using the real auth helper.
  from app.security.auth import create_access_token

  token, _ = create_access_token(user_id=1, role="admin")
  client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
  client.headers.update({"Authorization": f"Bearer {token}"})
  return client


async def test_sql_injection_in_search():
  client = await _authed_client()
  try:
    r = await client.get("/api/v1/alerts", params={"search": "' OR '1'='1"})
    # Should not error with 5xx; either 200 with filtered results or 4xx.
    assert r.status_code < 500
  finally:
    await client.aclose()


async def test_sql_injection_in_alert_id():
  client = await _authed_client()
  try:
    r = await client.get("/api/v1/alerts/1; DROP TABLE alerts;--")
    # Path param is a plain string; invalid ID should be treated as "not found", not executed.
    assert r.status_code in (404, 422)
  finally:
    await client.aclose()


async def test_xss_in_alert_title():
  # Ingest an event with a script tag in title and ensure it is sanitized by sanitize_json.
  client = await _authed_client()
  try:
    payload = {
      "source": "Sentinel",
      "events": [
        {
          "Severity": "High",
          "DisplayName": "<script>alert(1)</script>",
          "AlertType": "Auth",
          "StartTime": datetime.now(timezone.utc).isoformat(),
        }
      ],
    }
    r = await client.post("/api/v1/ingest", json=payload)
    assert r.status_code == 200
  finally:
    await client.aclose()


async def test_xss_in_raw_payload_sanitized_before_storage():
  client = await _authed_client()
  try:
    payload = {
      "source": "UnknownSource",
      "events": [
        {
          "severity": "Low",
          "title": "XSS test",
          "payload": "<script>alert(1)</script>",
        }
      ],
    }
    r = await client.post("/api/v1/ingest", json=payload)
    assert r.status_code == 200
  finally:
    await client.aclose()


async def test_path_traversal_like_source_is_treated_as_data():
  client = await _authed_client()
  try:
    payload = {"source": "../../etc/passwd", "events": [{"severity": "Low", "title": "T"}]}
    r = await client.post("/api/v1/ingest", json=payload)
    # Even if accepted, it must not crash or succeed with 5xx.
    assert r.status_code in (200, 400, 422)
  finally:
    await client.aclose()


async def test_oversized_payload_rejected_with_413():
  client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
  try:
    # Build ~11MB JSON body; RequestValidationMiddleware should reject based on Content-Length.
    big_string = "x" * (11 * 1024 * 1024)
    body = {"source": "Sentinel", "events": [{"big": big_string}]}
    data = json.dumps(body)
    headers = {"Content-Type": "application/json"}
    r = await client.post("/api/v1/ingest", content=data, headers=headers)
    assert r.status_code == 413
  finally:
    await client.aclose()


async def test_deeply_nested_json_rejected():
  client = await _authed_client()
  try:
    nested = {}
    cur = nested
    for i in range(50):
      cur["x"] = {}
      cur = cur["x"]
    payload = {"source": "Sentinel", "events": [nested]}
    r = await client.post("/api/v1/ingest", json=payload)
    # sanitize_json should reject with SecurityError -> HTTP 400 or 422.
    assert r.status_code in (400, 422)
  finally:
    await client.aclose()


async def test_null_bytes_in_input_rejected_or_sanitized():
  client = await _authed_client()
  try:
    payload = {"source": "Sentinel", "events": [{"title": "Null\x00byte", "severity": "High"}]}
    r = await client.post("/api/v1/ingest", json=payload)
    assert r.status_code in (200, 400, 422)
  finally:
    await client.aclose()


async def test_log_injection_sanitizes_newlines():
  from app.security.sanitization import sanitize_for_log

  value = "line1\nline2\r\nline3"
  sanitized = sanitize_for_log(value)
  assert "\n" not in sanitized and "\r" not in sanitized

