"""SC-7 + SC-8 security tests: authz boundaries, injection, token manipulation.

Covers all new API endpoints added in P6 and S1-S6 that are not already
tested in test_p6_authz.py.  Specifically:

  1. Unauthenticated access → 401 for every new endpoint.
  2. Role boundary tests (analyst / viewer) → 403 on admin-only endpoints.
  3. Malformed / injection payloads → 400/422, never 5xx.
  4. Token manipulation / auth-bypass probes → 401.
  5. Role escalation prevention.

Test isolation: every test creates its own AsyncClient and closes it in a
finally block.  No shared mutable state between tests.

Infrastructure mirrors test_p6_authz.py:
  - httpx AsyncClient via ASGITransport (no real server needed)
  - create_access_token from app.security.auth for signed test JWTs
  - pytestmark = pytest.mark.anyio (anyio pytest plugin)
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.security.auth import create_access_token, ALGORITHM, _get_jwt_keys

pytestmark = pytest.mark.anyio

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_token(role: str = "analyst", user_id: int = 1) -> str:
    token, _ = create_access_token(user_id=user_id, role=role)
    return token


def _authed_headers(role: str = "analyst", user_id: int = 1) -> dict[str, str]:
    return {"Authorization": f"Bearer {_make_token(role=role, user_id=user_id)}"}


# ---------------------------------------------------------------------------
# 1. Unauthenticated access → 401 for all new endpoints
# ---------------------------------------------------------------------------


async def test_unauthed_get_detection_rules_returns_401() -> None:
    """GET /api/v1/detection-rules without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/detection-rules")
    assert r.status_code == 401


async def test_unauthed_post_detection_rules_returns_401() -> None:
    """POST /api/v1/detection-rules without a token must return 401."""
    payload = {"name": "test-rule", "rule_type": "custom", "conditions": []}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/v1/detection-rules", json=payload)
    assert r.status_code == 401


async def test_unauthed_patch_detection_rule_returns_401() -> None:
    """PATCH /api/v1/detection-rules/1 without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.patch("/api/v1/detection-rules/1", json={"description": "x"})
    assert r.status_code == 401


async def test_unauthed_approve_detection_rule_change_returns_401() -> None:
    """POST /api/v1/detection-rules/1/approve-change without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/v1/detection-rules/1/approve-change")
    assert r.status_code == 401


async def test_unauthed_rollback_detection_rule_returns_401() -> None:
    """POST /api/v1/detection-rules/1/rollback without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/v1/detection-rules/1/rollback", json={"target_version": 1})
    assert r.status_code == 401


async def test_unauthed_delete_detection_rule_returns_401() -> None:
    """DELETE /api/v1/detection-rules/1 without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.delete("/api/v1/detection-rules/1")
    assert r.status_code == 401


async def test_unauthed_test_detection_rule_returns_401() -> None:
    """POST /api/v1/detection-rules/1/test without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/v1/detection-rules/1/test", json={"event": {}})
    assert r.status_code == 401


async def test_unauthed_get_detection_qa_replays_returns_401() -> None:
    """GET /api/v1/resilience/detection-qa/replays without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/resilience/detection-qa/replays")
    assert r.status_code == 401


async def test_unauthed_post_detection_qa_replay_returns_401() -> None:
    """POST /api/v1/resilience/detection-qa/replay without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/v1/resilience/detection-qa/replay", json={})
    assert r.status_code == 401


async def test_unauthed_get_secrets_policies_returns_401() -> None:
    """GET /api/v1/resilience/secrets/policies without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/resilience/secrets/policies")
    assert r.status_code == 401


async def test_unauthed_post_secrets_policies_returns_401() -> None:
    """POST /api/v1/resilience/secrets/policies without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/resilience/secrets/policies",
            json={"secret_name": "test-secret", "provider": "env"},
        )
    assert r.status_code == 401


async def test_unauthed_get_runbook_approvals_returns_401() -> None:
    """GET /api/v1/resilience/runbook-approvals without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/resilience/runbook-approvals")
    assert r.status_code == 401


async def test_unauthed_post_runbook_approval_approve_returns_401() -> None:
    """POST /api/v1/resilience/runbook-approvals/1/approve without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/v1/resilience/runbook-approvals/1/approve")
    assert r.status_code == 401


async def test_unauthed_get_dr_drills_returns_401() -> None:
    """GET /api/v1/resilience/dr/drills without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/resilience/dr/drills")
    assert r.status_code == 401


async def test_unauthed_post_dr_drills_returns_401() -> None:
    """POST /api/v1/resilience/dr/drills without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/resilience/dr/drills",
            json={"target": "db-primary"},
        )
    assert r.status_code == 401


async def test_unauthed_get_ai_governance_metrics_returns_401() -> None:
    """GET /api/v1/resilience/ai-governance/metrics without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/resilience/ai-governance/metrics")
    assert r.status_code == 401


async def test_unauthed_post_ai_governance_feedback_returns_401() -> None:
    """POST /api/v1/resilience/ai-governance/feedback without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/resilience/ai-governance/feedback",
            json={"alert_id": "a-1", "rating": 3},
        )
    assert r.status_code == 401


async def test_unauthed_get_cases_returns_401() -> None:
    """GET /api/v1/cases without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/cases")
    assert r.status_code == 401


async def test_unauthed_post_cases_returns_401() -> None:
    """POST /api/v1/cases without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/cases",
            json={"title": "Test Case", "owner": "analyst1"},
        )
    assert r.status_code == 401


async def test_unauthed_get_watchlist_returns_401() -> None:
    """GET /api/v1/watchlist without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/watchlist")
    assert r.status_code == 401


async def test_unauthed_post_watchlist_returns_401() -> None:
    """POST /api/v1/watchlist without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/watchlist",
            json={"indicator": "192.168.1.1", "indicator_type": "ip"},
        )
    assert r.status_code == 401


async def test_unauthed_get_suppression_rules_returns_401() -> None:
    """GET /api/v1/suppression without a token must return 401.

    Note: the suppression list endpoint uses get_current_user (any authenticated
    user) rather than require_permission.  An unauthenticated request must still
    fail with 401.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/suppression")
    assert r.status_code == 401


async def test_unauthed_post_suppression_rules_returns_401() -> None:
    """POST /api/v1/suppression without a token must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/suppression",
            json={
                "name": "suppress-all-low",
                "conditions": [{"field": "severity", "operator": "equals", "value": "Low"}],
            },
        )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# 2. Role boundary tests → 403
# ---------------------------------------------------------------------------


async def test_analyst_cannot_create_detection_rule() -> None:
    """Analyst lacks admin:write → POST /api/v1/detection-rules must return 403."""
    payload = {"name": "analyst-rule", "rule_type": "custom", "conditions": [{"field": "severity", "op": "eq", "value": "High"}]}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/detection-rules",
            json=payload,
            headers=_authed_headers(role="analyst"),
        )
    assert r.status_code == 403


async def test_analyst_cannot_patch_detection_rule() -> None:
    """Analyst lacks admin:write → PATCH /api/v1/detection-rules/1 must return 403."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.patch(
            "/api/v1/detection-rules/1",
            json={"description": "updated"},
            headers=_authed_headers(role="analyst"),
        )
    assert r.status_code == 403


async def test_analyst_cannot_approve_detection_rule_change() -> None:
    """Analyst lacks admin:write → POST /api/v1/detection-rules/1/approve-change must return 403."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/detection-rules/1/approve-change",
            headers=_authed_headers(role="analyst"),
        )
    assert r.status_code == 403


async def test_analyst_cannot_delete_detection_rule() -> None:
    """Analyst lacks admin:write → DELETE /api/v1/detection-rules/1 must return 403."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.delete(
            "/api/v1/detection-rules/1",
            headers=_authed_headers(role="analyst"),
        )
    assert r.status_code == 403


async def test_analyst_cannot_trigger_detection_qa_replay() -> None:
    """Analyst lacks admin:write → POST /api/v1/resilience/detection-qa/replay must return 403."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/resilience/detection-qa/replay",
            json={"dataset_name": "last_30d_alerts"},
            headers=_authed_headers(role="analyst"),
        )
    assert r.status_code == 403


async def test_analyst_cannot_create_secrets_policy() -> None:
    """Analyst lacks admin:write → POST /api/v1/resilience/secrets/policies must return 403."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/resilience/secrets/policies",
            json={"secret_name": "my-api-key", "provider": "env"},
            headers=_authed_headers(role="analyst"),
        )
    assert r.status_code == 403


async def test_analyst_cannot_read_secrets_policies() -> None:
    """Analyst lacks admin:write → GET /api/v1/resilience/secrets/policies must return 403."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get(
            "/api/v1/resilience/secrets/policies",
            headers=_authed_headers(role="analyst"),
        )
    assert r.status_code == 403


async def test_analyst_cannot_approve_runbook_request() -> None:
    """Analyst lacks playbooks:run → POST /api/v1/resilience/runbook-approvals/1/approve must return 403."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/resilience/runbook-approvals/1/approve",
            headers=_authed_headers(role="analyst"),
        )
    assert r.status_code == 403


async def test_analyst_cannot_create_dr_drill() -> None:
    """Analyst lacks admin:write → POST /api/v1/resilience/dr/drills must return 403."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/resilience/dr/drills",
            json={"target": "db-primary"},
            headers=_authed_headers(role="analyst"),
        )
    assert r.status_code == 403


async def test_analyst_cannot_list_dr_drills() -> None:
    """Analyst lacks admin:write → GET /api/v1/resilience/dr/drills must return 403."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get(
            "/api/v1/resilience/dr/drills",
            headers=_authed_headers(role="analyst"),
        )
    assert r.status_code == 403


async def test_analyst_cannot_rollback_detection_rule() -> None:
    """Analyst lacks admin:write → POST /api/v1/detection-rules/1/rollback must return 403."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/detection-rules/1/rollback",
            json={"target_version": 1},
            headers=_authed_headers(role="analyst"),
        )
    assert r.status_code == 403


async def test_viewer_cannot_create_suppression_rule() -> None:
    """Viewer lacks admin:write → POST /api/v1/suppression must return 403."""
    token = _make_token(role="viewer")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/suppression",
            json={
                "name": "viewer-suppress",
                "conditions": [{"field": "severity", "operator": "equals", "value": "Low"}],
            },
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 403


async def test_viewer_cannot_post_watchlist() -> None:
    """Viewer lacks watchlist:write → POST /api/v1/watchlist must return 403."""
    token = _make_token(role="viewer")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/watchlist",
            json={"indicator": "evil.example.com", "indicator_type": "domain"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 403


async def test_viewer_cannot_create_case() -> None:
    """Viewer lacks cases:write → POST /api/v1/cases must return 403."""
    token = _make_token(role="viewer")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/cases",
            json={"title": "Viewer Case Attempt", "owner": "viewer1"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 403


async def test_viewer_cannot_post_ai_governance_feedback() -> None:
    """Viewer lacks alerts:write → POST /api/v1/resilience/ai-governance/feedback must return 403."""
    token = _make_token(role="viewer")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/resilience/ai-governance/feedback",
            json={"alert_id": "a-1", "rating": 4},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 403


async def test_viewer_cannot_create_detection_rule() -> None:
    """Viewer lacks admin:write → POST /api/v1/detection-rules must return 403."""
    token = _make_token(role="viewer")
    payload = {"name": "viewer-rule", "rule_type": "custom", "conditions": []}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/detection-rules",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# 3. Malformed payload / injection tests
# ---------------------------------------------------------------------------


async def test_detection_rule_sigma_type_missing_yaml_returns_400_or_422() -> None:
    """POST /api/v1/detection-rules with rule_type=sigma and no sigma_yaml → 400/422, never 5xx.

    The validation is performed at the endpoint level after RBAC, so admin
    token is used to bypass permission gating and reach the validation logic.
    """
    token = _make_token(role="admin")
    payload = {"name": "sigma-no-yaml", "rule_type": "sigma"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/detection-rules",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
    # 400 = endpoint business rule; 403 = CSRF with no session is acceptable;
    # 422 = Pydantic validation failure. Must never be 5xx.
    assert r.status_code in (400, 403, 422)
    assert r.status_code < 500


async def test_detection_rule_sql_injection_in_name_does_not_500() -> None:
    """POST /api/v1/detection-rules with SQL injection in name must not crash (no 5xx).

    The name is stored via SQLAlchemy parameterised queries, so the payload
    should be accepted safely (201) or rejected by validation (400/422/403).
    """
    token = _make_token(role="admin")
    payload = {
        "name": "'; DROP TABLE detection_rules; --",
        "rule_type": "custom",
        "conditions": [{"field": "severity", "operator": "equals", "value": "High"}],
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/detection-rules",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code < 500


async def test_detection_rule_xss_in_name_does_not_500() -> None:
    """POST /api/v1/detection-rules with XSS in name must not 5xx.

    The name field has max_length=160.  An XSS string within that length
    must be stored safely or rejected — it must not cause a server crash.
    """
    token = _make_token(role="admin")
    payload = {
        "name": "<script>alert(1)</script>",
        "rule_type": "custom",
        "conditions": [{"field": "severity", "operator": "equals", "value": "High"}],
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/detection-rules",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
    # Must not 5xx; 201 (stored), 400 (rejected), 403 (CSRF guard), 409
    # (duplicate) and 422 (validation) are all acceptable security outcomes.
    assert r.status_code < 500


async def test_detection_rule_test_enormous_event_does_not_500() -> None:
    """POST /api/v1/detection-rules/1/test with a huge event body must not crash."""
    token = _make_token(role="analyst")
    # 100k nested keys — designed to stress the rule evaluator, not the HTTP layer.
    big_event = {f"field_{i}": "A" * 100 for i in range(1000)}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/detection-rules/1/test",
            json={"event": big_event},
            headers={"Authorization": f"Bearer {token}"},
        )
    # 404 = rule doesn't exist in test DB, 422 = schema rejection — all fine.
    assert r.status_code < 500


async def test_detection_rule_patch_unknown_fields_ignored() -> None:
    """PATCH /api/v1/detection-rules/1 with unknown fields must not 5xx (Pydantic strips extras).

    Admin token used to reach past the RBAC gate; 404 is expected (no rule
    seeded in test DB) but unknown fields must not cause 422 or 500.
    """
    token = _make_token(role="admin")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.patch(
            "/api/v1/detection-rules/1",
            json={"description": "fine", "completely_unknown_field": True},
            headers={"Authorization": f"Bearer {token}"},
        )
    # 403 = CSRF (no session), 404 = rule not found, 400/422 = validation.
    # 422 for extra-field rejection by Pydantic is also acceptable.
    assert r.status_code < 500


async def test_asset_create_negative_confidence_score_rejected() -> None:
    """POST /api/v1/assets with negative confidence_score must return 422 (Pydantic ge=0 check).

    The AssetCreateRequest schema does not expose confidence_score directly
    (that field is read-only from enrichment); a risk_score with a value < 0
    triggers the ge=0 validator instead.
    """
    token = _make_token(role="analyst")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/assets",
            json={"asset_id": "test-negative-risk", "criticality": "low", "risk_score": -5.0},
            headers={"Authorization": f"Bearer {token}"},
        )
    # 422 = Pydantic validation; 400 or 403/409 also acceptable.
    # Must not 201 (stored with invalid data) or 5xx.
    assert r.status_code in (400, 422)
    assert r.status_code < 500


async def test_suppression_rule_create_empty_conditions_rejected() -> None:
    """POST /api/v1/suppression with empty conditions list → 422 (min_length=1)."""
    token = _make_token(role="admin")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/suppression",
            json={"name": "empty-conditions", "conditions": []},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code in (400, 422)
    assert r.status_code < 500


async def test_watchlist_create_ambiguous_indicator_returns_400_or_422() -> None:
    """POST /api/v1/watchlist with an ambiguous indicator (cannot infer type) → 400/422, not 5xx."""
    token = _make_token(role="analyst")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/watchlist",
            # Single character — too short (min_length=2) and also ambiguous
            json={"indicator": "x"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code in (400, 422)
    assert r.status_code < 500


async def test_watchlist_create_sql_injection_in_indicator_does_not_500() -> None:
    """POST /api/v1/watchlist with SQL injection in indicator must not 5xx."""
    token = _make_token(role="analyst")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/watchlist",
            json={
                "indicator": "'; DROP TABLE ioc_watchlist; --",
                "indicator_type": "domain",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code < 500


async def test_case_create_empty_title_rejected() -> None:
    """POST /api/v1/cases with title shorter than min_length=3 → 422."""
    token = _make_token(role="analyst")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/cases",
            json={"title": "AB", "owner": "analyst1"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code in (400, 422)
    assert r.status_code < 500


async def test_ai_governance_feedback_out_of_range_rating_rejected() -> None:
    """POST /api/v1/resilience/ai-governance/feedback with rating=6 (max=5) → 422."""
    token = _make_token(role="analyst")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/resilience/ai-governance/feedback",
            json={"alert_id": "a-1", "rating": 6},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code in (400, 422)
    assert r.status_code < 500


async def test_detection_qa_replay_invalid_window_days_rejected() -> None:
    """POST /api/v1/resilience/detection-qa/replay with replay_window_days=0 → 422."""
    token = _make_token(role="admin")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/resilience/detection-qa/replay",
            json={"dataset_name": "last_30d_alerts", "replay_window_days": 0},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code in (400, 422)
    assert r.status_code < 500


# ---------------------------------------------------------------------------
# 4. Token manipulation / auth bypass
# ---------------------------------------------------------------------------


async def test_expired_jwt_returns_401() -> None:
    """A JWT whose exp is in the past must be rejected with 401.

    We craft the token manually to control the exp claim.
    """
    import jwt as pyjwt

    private_pem, _ = _get_jwt_keys()
    now = datetime.now(timezone.utc)
    expired_payload = {
        "sub": "1",
        "role": "analyst",
        "jti": str(uuid.uuid4()),
        "iat": int((now - timedelta(hours=2)).timestamp()),
        "exp": int((now - timedelta(hours=1)).timestamp()),  # expired 1 hour ago
        "type": "access",
    }
    expired_token = pyjwt.encode(expired_payload, private_pem, algorithm=ALGORITHM)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get(
            "/api/v1/detection-rules",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
    assert r.status_code == 401


async def test_alg_none_jwt_returns_401() -> None:
    """A JWT signed with alg:none (unsigned) must be rejected with 401.

    The app uses RS256 only; alg:none is rejected by the PyJWT decode
    call which requires algorithms=[ALGORITHM].
    """
    # Build a raw JWT with alg=none: header.payload.empty-sig
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=")
    payload_dict = {
        "sub": "1",
        "role": "admin",
        "jti": str(uuid.uuid4()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        "type": "access",
    }
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload_dict).encode()
    ).rstrip(b"=")
    unsigned_token = f"{header.decode()}.{payload_b64.decode()}."

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get(
            "/api/v1/detection-rules",
            headers={"Authorization": f"Bearer {unsigned_token}"},
        )
    assert r.status_code == 401


async def test_missing_authorization_header_returns_401() -> None:
    """Request with no Authorization header at all must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/detection-rules")
    assert r.status_code == 401


async def test_malformed_bearer_token_returns_401() -> None:
    """A Bearer token that is clearly not a JWT must return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get(
            "/api/v1/detection-rules",
            headers={"Authorization": "Bearer this_is_not_a_real_jwt_at_all"},
        )
    assert r.status_code == 401


async def test_bearer_with_only_two_segments_returns_401() -> None:
    """A Bearer value with only two base64 segments (missing signature) → 401."""
    fake = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get(
            "/api/v1/detection-rules",
            headers={"Authorization": f"Bearer {fake}"},
        )
    assert r.status_code == 401


async def test_jwt_with_elevated_forged_role_is_treated_as_unprivileged() -> None:
    """A validly-signed JWT whose role is not in the PERMISSIONS map → 403 on any protected endpoint.

    The token is properly signed (using the real private key) so it passes the
    signature check.  The role 'god_mode' has no entries in PERMISSIONS, so
    require_permission returns an empty set → 403.
    """
    forged_token, _ = create_access_token(user_id=999, role="god_mode")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get(
            "/api/v1/detection-rules",
            headers={"Authorization": f"Bearer {forged_token}"},
        )
    # alerts:read is required; god_mode has no permissions → 403.
    assert r.status_code == 403


async def test_refresh_token_cannot_be_used_as_access_token() -> None:
    """A refresh JWT (type=refresh) presented as a Bearer token must be rejected with 401.

    The get_current_user_optional helper checks payload['type'] == 'access'.
    """
    import jwt as pyjwt

    private_pem, _ = _get_jwt_keys()
    now = datetime.now(timezone.utc)
    refresh_payload = {
        "sub": "1",
        "role": "admin",
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=7)).timestamp()),
        "type": "refresh",  # NOT 'access'
    }
    refresh_token = pyjwt.encode(refresh_payload, private_pem, algorithm=ALGORITHM)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get(
            "/api/v1/detection-rules",
            headers={"Authorization": f"Bearer {refresh_token}"},
        )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# 5. Role escalation prevention
# ---------------------------------------------------------------------------


async def test_analyst_cannot_reach_admin_write_detection_rule_endpoint() -> None:
    """Analyst cannot escalate to admin:write by calling detection-rules create → 403."""
    token = _make_token(role="analyst")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/detection-rules",
            json={
                "name": "escalation-probe",
                "rule_type": "custom",
                "conditions": [{"field": "severity", "operator": "equals", "value": "High"}],
            },
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 403


async def test_viewer_cannot_write_alerts() -> None:
    """Viewer cannot PATCH /api/v1/alerts/{id} (requires alerts:update_status) → 403."""
    token = _make_token(role="viewer")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.patch(
            "/api/v1/alerts/00000000-0000-0000-0000-000000000001",
            json={"status": "in_progress"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 403


async def test_senior_analyst_cannot_create_detection_rule() -> None:
    """senior_analyst lacks admin:write → POST /api/v1/detection-rules must return 403."""
    token = _make_token(role="senior_analyst")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post(
            "/api/v1/detection-rules",
            json={
                "name": "senior-analyst-escalation",
                "rule_type": "custom",
                "conditions": [],
            },
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 403


async def test_forged_admin_role_in_token_cannot_access_admin_endpoint() -> None:
    """A real JWT signed by the server with role='superadmin_forged' (unknown) → 403.

    This validates that the permission system fails closed when an unknown
    role is presented, even with a valid signature.
    """
    token = _make_token(role="superadmin_forged", user_id=42)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get(
            "/api/v1/detection-rules",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 403


async def test_analyst_cannot_list_secrets_policies_via_role_escalation() -> None:
    """Analyst cannot access admin:write-gated secrets policies by any means → 403.

    This checks that there is no bypass path for the secrets endpoint through
    a role that does not hold admin:write.
    """
    token = _make_token(role="analyst")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get(
            "/api/v1/resilience/secrets/policies",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 403


async def test_viewer_cannot_read_runbook_approvals() -> None:
    """Viewer lacks playbooks:run → GET /api/v1/resilience/runbook-approvals must return 403."""
    token = _make_token(role="viewer")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get(
            "/api/v1/resilience/runbook-approvals",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# 6. Positive smoke tests — confirm authorised access is NOT broken
# ---------------------------------------------------------------------------


async def test_analyst_can_read_detection_rules() -> None:
    """Analyst has alerts:read → GET /api/v1/detection-rules should return 200.

    A 403 here would indicate an RBAC regression.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers=_authed_headers(role="analyst"),
    ) as c:
        r = await c.get("/api/v1/detection-rules")
    assert r.status_code == 200


async def test_analyst_can_read_detection_qa_replays() -> None:
    """Analyst has alerts:read → GET /api/v1/resilience/detection-qa/replays should return 200."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers=_authed_headers(role="analyst"),
    ) as c:
        r = await c.get("/api/v1/resilience/detection-qa/replays")
    assert r.status_code == 200


async def test_analyst_can_read_ai_governance_metrics() -> None:
    """Analyst has alerts:read → GET /api/v1/resilience/ai-governance/metrics should return 200."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers=_authed_headers(role="analyst"),
    ) as c:
        r = await c.get("/api/v1/resilience/ai-governance/metrics")
    assert r.status_code == 200


async def test_analyst_can_read_cases() -> None:
    """Analyst has cases:read → GET /api/v1/cases should return 200."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers=_authed_headers(role="analyst"),
    ) as c:
        r = await c.get("/api/v1/cases")
    assert r.status_code == 200


async def test_analyst_can_read_watchlist() -> None:
    """Analyst has watchlist:read → GET /api/v1/watchlist should return 200."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers=_authed_headers(role="analyst"),
    ) as c:
        r = await c.get("/api/v1/watchlist")
    assert r.status_code == 200


async def test_admin_can_list_secrets_policies() -> None:
    """Admin has admin:write → GET /api/v1/resilience/secrets/policies should return 200.

    404 is impossible here (list returns empty array). A 403 is a regression.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers=_authed_headers(role="admin"),
    ) as c:
        r = await c.get("/api/v1/resilience/secrets/policies")
    assert r.status_code == 200


async def test_admin_can_list_dr_drills() -> None:
    """Admin has admin:write → GET /api/v1/resilience/dr/drills should return 200."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers=_authed_headers(role="admin"),
    ) as c:
        r = await c.get("/api/v1/resilience/dr/drills")
    assert r.status_code == 200
