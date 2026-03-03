from app.core.parsers import get_parser, parse_event
from app.core.parsers.guardduty import GuardDutyParser
from app.core.parsers.sentinel import SentinelParser
from app.core.parsers.suricata import SuricataParser
from app.core.parsers.windows_event import WindowsEventParser
from app.core.parsers.defender import DefenderParser


# Sentinel tests
def test_sentinel_high_severity():
    p = SentinelParser()
    assert p.get_severity({"Severity": "High"}) == "High"


def test_sentinel_informational_maps_to_low():
    p = SentinelParser()
    assert p.get_severity({"Severity": "Informational"}) == "Low"


def test_sentinel_extracts_user_principal_name():
    p = SentinelParser()
    assert p.extract_user_id({"UserPrincipalName": "jdoe@corp.com"}) == "jdoe@corp.com"


def test_sentinel_extracts_source_ip():
    p = SentinelParser()
    assert p.extract_source_ip({"SourceIP": "10.0.0.1"}) == "10.0.0.1"


# Suricata tests
def test_suricata_severity_1_is_critical():
    p = SuricataParser()
    assert p.get_severity({"alert": {"severity": 1}}) == "Critical"


def test_suricata_severity_2_is_high():
    p = SuricataParser()
    assert p.get_severity({"alert": {"severity": 2}}) == "High"


def test_suricata_non_alert_event_type_handled():
    p = SuricataParser()
    result = p.parse({"event_type": "dns", "timestamp": "2024-01-01T00:00:00Z"})
    assert result.title is not None


def test_suricata_src_ip_extracted():
    p = SuricataParser()
    assert p.extract_source_ip({"src_ip": "192.168.1.1"}) == "192.168.1.1"


def test_suricata_dest_ip_in_parsed_event():
    p = SuricataParser()
    result = p.parse(
        {
            "event_type": "alert",
            "src_ip": "1.2.3.4",
            "dest_ip": "5.6.7.8",
            "alert": {"severity": 1, "signature": "ET SCAN", "category": "Network"},
            "timestamp": "2024-01-01T00:00:00Z",
        }
    )
    assert result.dest_ip == "5.6.7.8"
    assert result.source_ip == "1.2.3.4"


# Windows Event tests
def test_windows_4625_is_high_auth():
    p = WindowsEventParser()
    assert p.get_severity({"EventID": 4625}) == "High"
    assert p.get_category({"EventID": 4625}) == "Auth"


def test_windows_4720_is_persistence():
    p = WindowsEventParser()
    assert p.get_category({"EventID": 4720}) == "Persistence"


def test_windows_unknown_event_defaults():
    p = WindowsEventParser()
    assert p.get_severity({"EventID": 9999}) == "Medium"
    assert p.get_category({"EventID": 9999}) == "Other"


# GuardDuty tests
def test_guardduty_severity_9_is_critical():
    p = GuardDutyParser()
    assert p.get_severity({"severity": 9.0}) == "Critical"


def test_guardduty_severity_7_is_high():
    p = GuardDutyParser()
    assert p.get_severity({"severity": 7.5}) == "High"


def test_guardduty_brute_force_category():
    p = GuardDutyParser()
    assert (
        p.get_category({"type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller"})
        == "Auth"
    )


# parse_event dispatch tests
def test_parse_event_sentinel_dispatch():
    result = parse_event(
        "Sentinel",
        {
            "Severity": "High",
            "DisplayName": "Suspicious login",
            "AlertType": "Auth",
            "StartTime": "2024-01-01T00:00:00Z",
        },
    )
    assert result.severity == "High"
    assert result.title == "Suspicious login"


def test_parse_event_unknown_source_uses_generic():
    result = parse_event(
        "UnknownSource",
        {
            "severity": "Low",
            "title": "Test event",
        },
    )
    assert result.title == "Test event"


def test_parse_event_generates_uuid_when_no_id():
    result = parse_event(
        "Suricata",
        {
            "event_type": "alert",
            "alert": {"severity": 2, "signature": "Test"},
            "timestamp": "2024-01-01T00:00:00Z",
        },
    )
    import uuid

    uuid.UUID(result.id)
