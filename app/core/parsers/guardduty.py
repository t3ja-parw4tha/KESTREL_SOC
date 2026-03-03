"""AWS GuardDuty log parser."""

from __future__ import annotations

from typing import Any

from app.core.parsers.base import BaseParser, ParsedEvent, parse_timestamp


class GuardDutyParser(BaseParser):
    """Parser for AWS GuardDuty findings."""

    def get_severity(self, event: dict[str, Any]) -> str:
        score = event.get("severity") or event.get("Severity")
        if score is None:
            return "Medium"
        try:
            s = float(score)
        except (TypeError, ValueError):
            return "Medium"
        if s >= 9:
            return "Critical"
        if s >= 7:
            return "High"
        if s >= 4:
            return "Medium"
        return "Low"

    def get_category(self, event: dict[str, Any]) -> str:
        raw = event.get("type") or event.get("Type") or ""
        t = str(raw).strip()
        if not t:
            return "Other"
        if "UnauthorizedAccess" in t or "Credential" in t or "BruteForce" in t:
            return "Auth"
        if "Backdoor" in t or "CryptoCurrency" in t or "Trojan" in t:
            return "Malware"
        if "Recon" in t or "PortProbe" in t:
            return "Network"
        if "Persistence" in t or "PrivilegeEscalation" in t:
            return "Privilege Escalation"
        if "LateralMovement" in t:
            return "Lateral Movement"
        if "Exfiltration" in t or "DataAccess" in t:
            return "Data"
        return "Other"

    def extract_title(self, event: dict[str, Any]) -> str:
        title = event.get("title") or event.get("Title")
        if title:
            return str(title)
        return "GuardDuty Finding"

    def extract_asset_id(self, event: dict[str, Any]) -> str | None:
        try:
            resource = event.get("resource") or event.get("Resource") or {}
            details = resource.get("instanceDetails") or resource.get("InstanceDetails") or {}
            instance_id = details.get("instanceId")
            if instance_id:
                return str(instance_id)
        except Exception:
            pass
        return None

    def extract_user_id(self, event: dict[str, Any]) -> str | None:
        return None

    def extract_source_ip(self, event: dict[str, Any]) -> str | None:
        service = event.get("service") or event.get("Service") or {}
        action = service.get("action") or service.get("Action") or {}
        net = action.get("networkConnectionAction") or action.get("NetworkConnectionAction") or {}
        ip = net.get("remoteIpDetails", {}).get("ipAddress") or net.get("remoteIpDetails", {}).get("ipAddressV4")
        if ip:
            return str(ip)
        return None

    def parse(self, event: dict[str, Any]) -> ParsedEvent:
        ts = parse_timestamp(event.get("updatedAt") or event.get("createdAt"))
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
