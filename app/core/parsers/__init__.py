"""Parsers package: source-specific log parsers and factory."""

from __future__ import annotations

from app.core.decision_engine.types import NormalizedAlert
from app.core.parsers.base import BaseParser, ParsedEvent
from app.core.parsers.defender import DefenderParser
from app.core.parsers.generic import GenericParser
from app.core.parsers.guardduty import GuardDutyParser
from app.core.parsers.sentinel import SentinelParser
from app.core.parsers.suricata import SuricataParser
from app.core.parsers.windows_event import WindowsEventParser


def get_parser(source: str) -> BaseParser:
    """Return the parser for the given source name. Default is GenericParser."""
    normalized = (source or "").strip()
    if normalized == "Sentinel":
        return SentinelParser()
    if normalized == "Suricata":
        return SuricataParser()
    if normalized == "Defender":
        return DefenderParser()
    if normalized == "GuardDuty":
        return GuardDutyParser()
    if normalized == "WindowsEventLog":
        return WindowsEventParser()
    return GenericParser()


def to_normalized_alert(
    parsed: ParsedEvent,
    source: str,
    alert_id: str,
    alert_type: str = "",
) -> NormalizedAlert:
    """Build a NormalizedAlert from a ParsedEvent for the decision engine."""
    return NormalizedAlert(
        id=alert_id,
        title=parsed.title,
        source=source,
        severity=parsed.severity,
        category=parsed.category,
        asset_id=parsed.asset_id,
        user_id=parsed.user_id,
        source_ip=parsed.source_ip,
        dest_ip=parsed.dest_ip,
        alert_type=alert_type,
        timestamp=parsed.timestamp,
        raw=parsed.raw,
        mitre_techniques=None,
        enrichment=None,
    )


def parse_event(source: str, event: dict) -> NormalizedAlert:
    """
    Parse a raw event into NormalizedAlert using the appropriate parser.
    Uses get_parser(source).parse(event) and to_normalized_alert with a generated id.
    """
    from uuid import uuid4

    parser = get_parser(source)
    parsed = parser.parse(event)
    alert_id = str(event.get("id") or uuid4())
    alert_type = str(event.get("alert_type") or event.get("type") or "").strip()
    return to_normalized_alert(parsed, source, alert_id, alert_type)


__all__ = [
    "BaseParser",
    "ParsedEvent",
    "GenericParser",
    "GuardDutyParser",
    "SentinelParser",
    "SuricataParser",
    "WindowsEventParser",
    "get_parser",
    "to_normalized_alert",
    "parse_event",
]
