"""Suricata EVE JSON parser."""

from __future__ import annotations

from typing import Any

from app.core.parsers.base import BaseParser, ParsedEvent, parse_timestamp


class SuricataParser(BaseParser):
    """Parser for Suricata EVE JSON; only processes event_type 'alert'."""

    _SEVERITY_MAP = {
        1: "Critical",
        2: "High",
        3: "Medium",
    }

    def get_severity(self, event: dict[str, Any]) -> str:
        alert = event.get("alert") or {}
        sev = alert.get("severity")
        if isinstance(sev, int):
            return self._SEVERITY_MAP.get(sev, "Low")
        return "Low"

    def get_category(self, event: dict[str, Any]) -> str:
        alert = event.get("alert") or {}
        cat = alert.get("category")
        if cat:
            return str(cat)
        return "Network"

    def extract_title(self, event: dict[str, Any]) -> str:
        alert = event.get("alert") or {}
        sig = alert.get("signature")
        if sig:
            return str(sig)
        return "Suricata Alert"

    def extract_asset_id(self, event: dict[str, Any]) -> str | None:
        dest = event.get("dest_ip")
        if dest is not None:
            return str(dest)
        return None

    def extract_user_id(self, event: dict[str, Any]) -> str | None:
        return None

    def extract_source_ip(self, event: dict[str, Any]) -> str | None:
        ip = event.get("src_ip")
        if ip is not None:
            return str(ip)
        return None

    def parse(self, event: dict[str, Any]) -> ParsedEvent:
        if event.get("event_type") != "alert":
            # Return a minimal valid ParsedEvent for non-alert; caller may filter
            return ParsedEvent(
                title=self.extract_title(event),
                severity=self.get_severity(event),
                category=self.get_category(event),
                asset_id=self.extract_asset_id(event),
                user_id=self.extract_user_id(event),
                source_ip=self.extract_source_ip(event),
                dest_ip=event.get("dest_ip") and str(event["dest_ip"]) or None,
                timestamp=parse_timestamp(event.get("timestamp")),
                raw=dict(event),
            )
        alert = event.get("alert") or {}
        src_ip = event.get("src_ip")
        dest_ip = event.get("dest_ip")
        return ParsedEvent(
            title=alert.get("signature") or "Suricata Alert",
            severity=self.get_severity(event),
            category=str(alert.get("category") or "Network"),
            asset_id=str(dest_ip) if dest_ip is not None else None,
            user_id=None,
            source_ip=str(src_ip) if src_ip is not None else None,
            dest_ip=str(dest_ip) if dest_ip is not None else None,
            timestamp=parse_timestamp(event.get("timestamp")),
            raw=dict(event),
        )
