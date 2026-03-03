"""Microsoft Sentinel log parser."""

from __future__ import annotations

from typing import Any

from app.core.parsers.base import BaseParser, ParsedEvent, parse_timestamp


class SentinelParser(BaseParser):
    """Parser for Microsoft Sentinel SecurityAlert and SigninLogs schemas."""

    _SEVERITY_MAP = {
        "Informational": "Low",
        "Low": "Low",
        "Medium": "Medium",
        "High": "High",
    }

    def get_severity(self, event: dict[str, Any]) -> str:
        raw = event.get("Severity") or event.get("severity")
        if raw is None:
            return "Medium"
        s = str(raw).strip()
        return self._SEVERITY_MAP.get(s, "Medium")

    def get_category(self, event: dict[str, Any]) -> str:
        raw = event.get("AlertType") or event.get("Category") or event.get("category") or ""
        return str(raw).strip() or "Other"

    def extract_title(self, event: dict[str, Any]) -> str:
        title = event.get("DisplayName") or event.get("Title") or event.get("title")
        if title:
            return str(title)
        msg = event.get("ResultType") or event.get("Message") or event.get("message")
        if msg:
            return str(msg)
        return "Microsoft Sentinel Alert"

    def extract_asset_id(self, event: dict[str, Any]) -> str | None:
        entity = event.get("CompromisedEntity") or event.get("compromised_entity")
        if entity:
            return str(entity)
        return None

    def extract_user_id(self, event: dict[str, Any]) -> str | None:
        uid = event.get("UserPrincipalName") or event.get("Identity") or event.get("UserId")
        if isinstance(uid, dict):
            uid = uid.get("userPrincipalName") or uid.get("id")
        if uid is not None:
            return str(uid)
        return None

    def extract_source_ip(self, event: dict[str, Any]) -> str | None:
        ip = event.get("SourceIP") or event.get("IPAddress") or event.get("clientIPAddress")
        if ip is not None:
            return str(ip)
        return None

    def parse(self, event: dict[str, Any]) -> ParsedEvent:
        ts = parse_timestamp(
            event.get("StartTime") or event.get("TimeGenerated") or event.get("createdDateTime")
        )
        return ParsedEvent(
            title=self.extract_title(event),
            severity=self.get_severity(event),
            category=self.get_category(event),
            asset_id=self.extract_asset_id(event),
            user_id=self.extract_user_id(event),
            source_ip=self.extract_source_ip(event),
            dest_ip=None,
            timestamp=ts,
            raw=dict(event),
        )
