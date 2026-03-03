"""Windows Event Log parser."""

from __future__ import annotations

from typing import Any

from app.core.parsers.base import BaseParser, ParsedEvent, parse_timestamp


# EventID -> (severity, category)
_WINDOWS_EVENT_MAP: dict[int, tuple[str, str]] = {
    4625: ("High", "Auth"),      # Failed logon
    4624: ("Low", "Auth"),       # Successful logon
    4648: ("Medium", "Auth"),    # Explicit credentials
    4720: ("High", "Persistence"),  # Account created
    4728: ("High", "Privilege Escalation"),  # Added to security group
    4768: ("Medium", "Auth"),    # Kerberos TGT
    4769: ("Medium", "Auth"),    # Kerberos service ticket
    4776: ("Medium", "Auth"),    # NTLM auth
}


class WindowsEventParser(BaseParser):
    """Parser for Windows Event Log (Security) events."""

    def get_severity(self, event: dict[str, Any]) -> str:
        eid = event.get("EventID") or event.get("EventId") or event.get("System", {}).get("EventID")
        if eid is not None:
            try:
                n = int(eid)
                if n in _WINDOWS_EVENT_MAP:
                    return _WINDOWS_EVENT_MAP[n][0]
            except (TypeError, ValueError):
                pass
        return "Medium"

    def get_category(self, event: dict[str, Any]) -> str:
        eid = event.get("EventID") or event.get("EventId") or event.get("System", {}).get("EventID")
        if eid is not None:
            try:
                n = int(eid)
                if n in _WINDOWS_EVENT_MAP:
                    return _WINDOWS_EVENT_MAP[n][1]
            except (TypeError, ValueError):
                pass
        return "Other"

    def extract_title(self, event: dict[str, Any]) -> str:
        msg = event.get("Message") or event.get("message")
        if msg:
            return str(msg)[:500]
        eid = event.get("EventID") or event.get("EventId")
        if eid is not None:
            return f"Windows Event {eid}"
        return "Windows Event"

    def extract_asset_id(self, event: dict[str, Any]) -> str | None:
        return None

    def extract_user_id(self, event: dict[str, Any]) -> str | None:
        subj = event.get("SubjectUserName") or event.get("TargetUserName")
        if subj:
            return str(subj)
        evt_data = event.get("EventData") or event.get("eventData") or {}
        if isinstance(evt_data, dict):
            subj = evt_data.get("SubjectUserName") or evt_data.get("TargetUserName")
            if subj:
                return str(subj)
        return None

    def extract_source_ip(self, event: dict[str, Any]) -> str | None:
        ip = event.get("IpAddress") or event.get("WorkstationName")
        if ip:
            return str(ip)
        evt_data = event.get("EventData") or event.get("eventData") or {}
        if isinstance(evt_data, dict):
            ip = evt_data.get("IpAddress") or evt_data.get("WorkstationName")
            if ip:
                return str(ip)
        return None

    def parse(self, event: dict[str, Any]) -> ParsedEvent:
        ts = parse_timestamp(
            event.get("TimeCreated") or event.get("System", {}).get("TimeCreated", {}).get("#text")
            or event.get("timestamp") or event.get("@timestamp")
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
