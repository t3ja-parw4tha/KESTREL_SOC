"""Generic fallback parser: structured fields first, then keyword matching on specific fields."""

from __future__ import annotations

from typing import Any

from app.core.parsers.base import BaseParser, ParsedEvent, parse_timestamp


def _text_from_fields(event: dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = event.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()
    return ""


def _severity_from_keywords(text: str) -> str:
    t = text.lower()
    if "critical" in t or "crit" in t:
        return "Critical"
    if "high" in t or "error" in t or "failed" in t:
        return "High"
    if "medium" in t or "med" in t or "warn" in t:
        return "Medium"
    if "low" in t or "info" in t:
        return "Low"
    return "Medium"


def _category_from_keywords(text: str) -> str:
    t = text.lower()
    if "login" in t or "auth" in t or "credential" in t or "brute" in t:
        return "Auth"
    if "exfil" in t or "download" in t or "data" in t:
        return "Data"
    if "scan" in t or "port" in t or "network" in t:
        return "Network"
    if "malware" in t or "virus" in t:
        return "Malware"
    if "persistence" in t or "account created" in t:
        return "Persistence"
    if "privilege" in t or "escalation" in t:
        return "Privilege Escalation"
    if "lateral" in t:
        return "Lateral Movement"
    return "Network"


class GenericParser(BaseParser):
    """Fallback parser: prefer structured fields; keyword match only on title/message/name."""

    def get_severity(self, event: dict[str, Any]) -> str:
        raw = (
            event.get("severity")
            or event.get("Severity")
            or event.get("level")
            or event.get("priority")
        )
        if raw is not None and str(raw).strip():
            s = str(raw).strip().lower()
            if s in ("critical", "crit"):
                return "Critical"
            if s in ("high", "error"):
                return "High"
            if s in ("medium", "med", "warn", "warning"):
                return "Medium"
            if s in ("low", "info", "informational"):
                return "Low"
            return "Medium"
        combined = _text_from_fields(event, "title", "message", "name", "Message", "Title")
        if combined:
            return _severity_from_keywords(combined)
        return "Medium"

    def get_category(self, event: dict[str, Any]) -> str:
        raw = event.get("category") or event.get("Category") or event.get("AlertType")
        if raw is not None and str(raw).strip():
            return str(raw).strip()
        combined = _text_from_fields(event, "title", "message", "name", "Message", "Title")
        if combined:
            return _category_from_keywords(combined)
        return "Network"

    def extract_title(self, event: dict[str, Any]) -> str:
        title = _text_from_fields(
            event,
            "title", "Title", "message", "Message", "rule", "Rule",
            "name", "Name", "signature", "summary",
        )
        if title:
            return title[:500]
        return "Event"

    def extract_asset_id(self, event: dict[str, Any]) -> str | None:
        raw = event.get("asset_id") or event.get("device_id") or event.get("host") or event.get("compromised_entity")
        if raw is not None and str(raw).strip():
            return str(raw).strip()
        return None

    def extract_user_id(self, event: dict[str, Any]) -> str | None:
        raw = event.get("user_id") or event.get("account") or event.get("UserId") or event.get("userPrincipalName")
        if raw is not None and str(raw).strip():
            return str(raw).strip()
        return None

    def extract_source_ip(self, event: dict[str, Any]) -> str | None:
        raw = (
            event.get("source_ip") or event.get("src_ip") or event.get("client_ip")
            or event.get("SourceIP") or event.get("IPAddress") or event.get("clientIPAddress")
        )
        if raw is not None and str(raw).strip():
            return str(raw).strip()
        return None

    def parse(self, event: dict[str, Any]) -> ParsedEvent:
        dest_ip = event.get("dest_ip") or event.get("dst_ip")
        if dest_ip is not None:
            dest_ip = str(dest_ip).strip() or None
        ts = parse_timestamp(
            event.get("timestamp") or event.get("@timestamp") or event.get("TimeGenerated") or event.get("createdDateTime")
        )
        return ParsedEvent(
            title=self.extract_title(event),
            severity=self.get_severity(event),
            category=self.get_category(event),
            asset_id=self.extract_asset_id(event),
            user_id=self.extract_user_id(event),
            source_ip=self.extract_source_ip(event),
            dest_ip=dest_ip,
            timestamp=ts,
            raw=dict(event),
        )
