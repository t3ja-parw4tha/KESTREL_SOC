from datetime import datetime, timezone

from app.core.decision_engine.types import NormalizedAlert
from app.core.mitre.mapping import (
    get_mitre_techniques_for_alert,
    map_alert_to_techniques,
)
from app.core.mitre.techniques import TECHNIQUES


def _alert(category, alert_type="", source="Suricata", title="", raw=None):
    return NormalizedAlert(
        id="t1",
        title=title or category,
        source=source,
        severity="High",
        category=category,
        asset_id=None,
        user_id=None,
        source_ip="1.2.3.4",
        alert_type=alert_type,
        timestamp=datetime.now(timezone.utc),
        raw=raw or {},
        mitre_techniques=None,
        enrichment=None,
    )


def test_auth_failed_maps_brute_force():
    alert = _alert("Auth", "failed_login", title="Login failure")
    techs = map_alert_to_techniques(alert)
    ids = [t.technique_id for t in techs]
    assert "T1110" in ids


def test_lateral_movement_maps_T1021():
    techs = map_alert_to_techniques(_alert("Lateral Movement"))
    ids = [t.technique_id for t in techs]
    assert "T1021" in ids
    assert "T1570" in ids


def test_privilege_escalation_maps_T1068():
    techs = map_alert_to_techniques(_alert("Privilege Escalation"))
    ids = [t.technique_id for t in techs]
    assert "T1068" in ids
    assert "T1548" in ids


def test_network_scan_maps_T1046():
    alert = _alert("Network", "port_scan", title="Port scan detected")
    techs = map_alert_to_techniques(alert)
    ids = [t.technique_id for t in techs]
    assert "T1046" in ids


def test_no_duplicate_techniques():
    alert = _alert("Auth", source="Sentinel", title="Failed login")
    techs = map_alert_to_techniques(alert)
    ids = [t.technique_id for t in techs]
    assert len(ids) == len(set(ids))


def test_all_technique_ids_valid():
    for tid in [
        "T1110",
        "T1078",
        "T1021",
        "T1570",
        "T1550",
        "T1068",
        "T1548",
        "T1204",
        "T1059",
        "T1046",
        "T1041",
        "T1048",
        "T1213",
        "T1530",
        "T1053",
        "T1136",
        "T1543",
        "T1562",
        "T1070",
        "T1571",
        "T1190",
    ]:
        assert tid in TECHNIQUES, f"{tid} used in mapping but not in TECHNIQUES"


def test_get_mitre_techniques_for_alert_returns_dicts():
    result = get_mitre_techniques_for_alert("Auth", "failed_login", {})
    assert isinstance(result, list)
    assert len(result) > 0
    assert "technique_id" in result[0]
    assert "technique_name" in result[0]
    assert "tactic" in result[0]
