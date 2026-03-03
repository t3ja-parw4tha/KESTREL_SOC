"""Tests for decision engine."""

from datetime import datetime, timezone

import pytest

from app.core.decision_engine.confidence import calculate_confidence
from app.core.decision_engine.correlation import correlate_alerts
from app.core.decision_engine.engine import run_decision_engine
from app.core.decision_engine.scorer import calculate_risk_score
from app.core.decision_engine.types import (
    AssetContext,
    DecisionInput,
    HistoryContext,
    NormalizedAlert,
    ThreatContext,
)


def _make_alert(**kwargs) -> NormalizedAlert:
    defaults = dict(
        id="test-id",
        title="Test Alert",
        source="Suricata",
        severity="High",
        category="Network",
        asset_id="server-01",
        user_id="jdoe",
        source_ip="1.2.3.4",
        alert_type="network_scan",
        timestamp=datetime.now(timezone.utc),
        raw={"event": "test"},
        mitre_techniques=[],
        enrichment={},
    )
    defaults.update(kwargs)
    return NormalizedAlert(**defaults)


def _make_input(alert=None, asset=None, threat=None, history=None):
    return DecisionInput(
        alert=alert or _make_alert(),
        asset=asset,
        threat=threat,
        history=history,
    )


# SCORER TESTS
def test_low_severity_base_score():
    inp = _make_input(_make_alert(severity="Low"))
    assert calculate_risk_score(inp) == 10


def test_critical_severity_base_score():
    inp = _make_input(_make_alert(severity="Critical"))
    assert calculate_risk_score(inp) == 80


def test_production_internet_exposed_adds_20():
    asset = AssetContext(
        asset_id="s1",
        asset_type="server",
        is_production=True,
        is_internet_exposed=True,
        business_criticality="low",
        tags=[],
    )
    inp = _make_input(_make_alert(severity="High"), asset=asset)
    score = calculate_risk_score(inp)
    assert score == 80  # 60 + 10 + 10


def test_false_positive_reduces_score():
    history = HistoryContext(
        prior_false_positives=3,
        similar_alerts_7d=2,
        last_seen=None,
    )
    inp = _make_input(_make_alert(severity="High"), history=history)
    score = calculate_risk_score(inp)
    assert score == 40  # 60 - 20


def test_score_clamped_at_100():
    asset = AssetContext(
        asset_id="s1",
        asset_type="server",
        is_production=True,
        is_internet_exposed=True,
        business_criticality="high",
        tags=[],
    )
    threat = ThreatContext(
        has_active_exploit=True,
        cvss_score=9.5,
        cve_id="CVE-2024-1234",
        threat_actor="APT29",
    )
    inp = _make_input(
        _make_alert(severity="Critical"),
        asset=asset,
        threat=threat,
    )
    score = calculate_risk_score(inp)
    assert score == 100  # Clamped


def test_score_clamped_at_0():
    history = HistoryContext(
        prior_false_positives=10,
        similar_alerts_7d=50,
        last_seen=None,
    )
    inp = _make_input(
        _make_alert(severity="Low"),
        history=history,
    )
    score = calculate_risk_score(inp)
    assert score == 0  # 10 - 20 - 10 = -20 → clamped


# CORRELATION TESTS
def test_same_asset_user_within_15min_correlates():
    now = datetime.now(timezone.utc)
    alert1 = _make_alert(
        id="a1",
        asset_id="srv",
        user_id="joe",
        timestamp=now,
    )
    alert2 = _make_alert(
        id="a2",
        asset_id="srv",
        user_id="joe",
        timestamp=now,
    )
    result = correlate_alerts(alert1, [alert2])
    assert "a2" in result.correlated_alert_ids
    assert result.incident_group_id is not None
    assert result.correlation_rule_triggered == "same_asset_user_15min"


def test_same_source_ip_within_5min_correlates():
    now = datetime.now(timezone.utc)
    alert1 = _make_alert(
        id="a1",
        source_ip="1.2.3.4",
        timestamp=now,
    )
    alert2 = _make_alert(
        id="a2",
        source_ip="1.2.3.4",
        timestamp=now,
    )
    result = correlate_alerts(alert1, [alert2])
    assert "a2" in result.correlated_alert_ids


def test_different_assets_do_not_correlate():
    now = datetime.now(timezone.utc)
    alert1 = _make_alert(
        id="a1",
        asset_id="srv1",
        user_id="joe",
        source_ip=None,
        timestamp=now,
    )
    alert2 = _make_alert(
        id="a2",
        asset_id="srv2",
        user_id="joe",
        source_ip=None,
        timestamp=now,
    )
    result = correlate_alerts(alert1, [alert2])
    assert len(result.correlated_alert_ids) == 0
    assert result.incident_group_id is None


# CONFIDENCE TESTS
def test_baseline_confidence_no_context():
    inp = _make_input(_make_alert(raw={}))
    conf = calculate_confidence(inp)
    assert conf == 0.3  # 0.5 - 0.2 (no raw payload)


def test_full_context_max_confidence():
    asset = AssetContext(
        asset_id="s1",
        asset_type="server",
        is_production=True,
        is_internet_exposed=True,
        business_criticality="high",
        tags=[],
    )
    threat = ThreatContext(
        has_active_exploit=True,
        cvss_score=9.5,
        cve_id="CVE-x",
        threat_actor="APT",
    )
    history = HistoryContext(
        prior_false_positives=0,
        similar_alerts_7d=0,
        last_seen=None,
    )
    inp = _make_input(
        _make_alert(enrichment={"vt": {"score": 80}}),
        asset=asset,
        threat=threat,
        history=history,
    )
    conf = calculate_confidence(inp)
    assert conf == pytest.approx(1.0)


# ENGINE INTEGRATION TEST
def test_engine_returns_valid_output():
    inp = _make_input(_make_alert(severity="High"))
    output = run_decision_engine(inp, [])
    assert 0 <= output.risk_score <= 100
    assert output.risk_level in [
        "info",
        "low",
        "medium",
        "high",
        "critical",
    ]
    assert 0.0 <= output.confidence <= 1.0
    assert isinstance(output.explanation, list)
    assert len(output.explanation) >= 1
    assert output.engine_version == "v1"
