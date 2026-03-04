"""Microsoft Defender for Endpoint alert parser."""

from __future__ import annotations

from typing import Any

from app.core.parsers.base import BaseParser, ParsedEvent, parse_timestamp


class DefenderParser(BaseParser):
    _SEVERITY_MAP = {
        "Informational": "Low",
        "Low": "Low",
        "Medium": "Medium",
        "High": "High",
        "Critical": "Critical",
    }
    _CATEGORY_MAP = {
        "DefenseEvasion": "Policy",
        "Execution": "Malware",
        "Exfiltration": "Data",
        "Impact": "Malware",
        "InitialAccess": "Auth",
        "LateralMovement": "Lateral Movement",
        "Persistence": "Persistence",
        "PrivilegeEscalation": "Privilege Escalation",
        "CredentialAccess": "Auth",
        "Discovery": "Network",
        "CommandAndControl": "Network",
        "Collection": "Data",
    }

    def get_severity(self, event: dict[str, Any]) -> str:
        raw = event.get("severity") or event.get("Severity")
        if raw:
            return self._SEVERITY_MAP.get(str(raw).strip(), "Medium")
        return "Medium"

    def get_category(self, event: dict[str, Any]) -> str:
        mitre = event.get("mitreTechniques")
        if isinstance(mitre, list) and mitre:
            mt0 = mitre[0] or {}
            raw = mt0.get("category", "") or ""
        else:
            raw = event.get("category") or event.get("Category") or ""
        t = str(raw).strip()
        return self._CATEGORY_MAP.get(t, "Network")

    def extract_title(self, event: dict[str, Any]) -> str:
        title = event.get("title") or event.get("Title")
        if title:
            return str(title)[:500]
        return "Microsoft Defender Alert"

    def extract_asset_id(self, event: dict[str, Any]) -> str | None:
        devices = event.get("devices") or []
        if isinstance(devices, list) and devices:
            d0 = devices[0] or {}
            val = d0.get("deviceDnsName") or d0.get("id")
            if val:
                return str(val)
        return None

    def extract_user_id(self, event: dict[str, Any]) -> str | None:
        actors = event.get("relatedUser") or {}
        if isinstance(actors, dict):
            uid = actors.get("userName")
            if uid:
                return str(uid)
        return None

    def extract_source_ip(self, event: dict[str, Any]) -> str | None:
        devices = event.get("devices") or []
        if isinstance(devices, list) and devices:
            nics = devices[0].get("networkInterfaces") or []
            if isinstance(nics, list) and nics:
                ip = nics[0].get("ipAddress")
                if ip:
                    return str(ip)
        return None

    def parse(self, event: dict[str, Any]) -> ParsedEvent:
        ts = parse_timestamp(
            event.get("firstEventTime")
            or event.get("createdTime")
            or event.get("alertCreationTime")
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
