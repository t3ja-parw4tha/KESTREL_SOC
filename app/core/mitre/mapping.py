"""MITRE ATT&CK technique mapping by category, alert type, and source."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from app.core.mitre.techniques import TECHNIQUES

if TYPE_CHECKING:
    from app.core.decision_engine.types import NormalizedAlert


@dataclass
class MitreTechnique:
    """Single MITRE ATT&CK technique reference."""

    technique_id: str
    technique_name: str
    tactic: str
    subtechniques: list[str]


def _technique_to_obj(tid: str) -> MitreTechnique | None:
    entry = TECHNIQUES.get(tid)
    if not entry:
        return None
    return MitreTechnique(
        technique_id=tid,
        technique_name=entry["name"],
        tactic=entry["tactic"],
        subtechniques=entry.get("subtechniques", []),
    )


def _mitre_technique_to_dict(t: MitreTechnique) -> dict[str, Any]:
    return {
        "technique_id": t.technique_id,
        "technique_name": t.technique_name,
        "tactic": t.tactic,
        "subtechniques": t.subtechniques,
    }


def _is_auth_failed(alert: "NormalizedAlert") -> bool:
    raw = alert.raw or {}
    at = (alert.alert_type or "").lower()
    title = (alert.title or "").lower()
    if "fail" in at or "failure" in at or "brute" in at:
        return True
    if "fail" in title or "failure" in title or "brute" in title:
        return True
    if raw.get("outcome") == "failure" or raw.get("result") == "failure":
        return True
    msg = (raw.get("message") or raw.get("msg") or "").lower()
    if "failed" in msg or "failure" in msg or "invalid" in msg:
        return True
    return False


def _is_auth_success_after_failures(alert: "NormalizedAlert") -> bool:
    raw = alert.raw or {}
    at = (alert.alert_type or "").lower()
    title = (alert.title or "").lower()
    if "success_after" in at or "valid_after" in at or "login_after_brute" in at:
        return True
    if "success after" in title or "valid account" in title:
        return True
    if raw.get("success_after_failures") or raw.get("after_multiple_failures"):
        return True
    return False


def _is_network_scan(alert: "NormalizedAlert") -> bool:
    at = (alert.alert_type or "").lower()
    title = (alert.title or "").lower()
    if "scan" in at or "port_scan" in at or "network_scan" in at:
        return True
    if "scan" in title or "recon" in title:
        return True
    return False


def _is_network_exfil(alert: "NormalizedAlert") -> bool:
    at = (alert.alert_type or "").lower()
    title = (alert.title or "").lower()
    raw = alert.raw or {}
    if "exfil" in at or "exfiltration" in at or "data_exfil" in at:
        return True
    if "exfil" in title or "exfiltration" in title:
        return True
    if raw.get("exfiltration") or "exfil" in str(raw).lower():
        return True
    return False


def map_alert_to_techniques(alert: "NormalizedAlert") -> list[MitreTechnique]:
    """
    Map a normalized alert to MITRE ATT&CK techniques by category, alert type, and source.
    Returns list of MitreTechnique objects: technique_id, technique_name, tactic, subtechniques.
    """
    seen: set[str] = set()
    result: list[MitreTechnique] = []
    category = (alert.category or "").strip()
    source = (alert.source or "").strip()
    source_lower = source.lower()

    def add(tid: str) -> None:
        if tid in seen:
            return
        obj = _technique_to_obj(tid)
        if obj:
            seen.add(tid)
            result.append(obj)

    # --- Map by category (with conditions where specified) ---
    if category == "Auth":
        if _is_auth_failed(alert):
            add("T1110")  # Brute Force
            add("T1078")  # Valid Accounts
        elif _is_auth_success_after_failures(alert):
            add("T1078")  # Valid Accounts
        else:
            add("T1110")
            add("T1078")
    elif category == "Lateral Movement":
        add("T1021")   # Remote Services
        add("T1570")   # Lateral Tool Transfer
        add("T1550")   # Use Alternate Authentication Material
    elif category == "Privilege Escalation":
        add("T1068")   # Exploitation for Privilege Escalation
        add("T1548")   # Abuse Elevation Control Mechanism
    elif category == "Malware":
        add("T1204")   # User Execution
        add("T1059")   # Command and Scripting Interpreter
    elif category == "Network":
        if _is_network_scan(alert):
            add("T1046")  # Network Service Discovery
        elif _is_network_exfil(alert):
            add("T1041")  # Exfiltration Over C2
            add("T1048")  # Exfiltration Over Alternative Protocol
        else:
            add("T1046")
            add("T1041")
            add("T1048")
    elif category == "Data":
        add("T1213")   # Data from Information Repositories
        add("T1530")   # Data from Cloud Storage Object
    elif category == "Persistence":
        add("T1053")   # Scheduled Task/Job
        add("T1136")   # Create Account
        add("T1543")   # Create or Modify System Process
    elif category == "Policy":
        add("T1562")   # Impair Defenses
        add("T1070")   # Indicator Removal on Host

    # --- Map by source (additives) ---
    if source_lower == "suricata" and category == "Network":
        add("T1046")   # Network Service Discovery
        add("T1571")   # Non-Standard Port
    if source_lower == "sentinel" and category == "Auth":
        add("T1078")
        add("T1110")
    if source_lower == "guardduty":
        add("T1190")   # Exploit Public-Facing Application

    return result


def get_mitre_techniques_for_alert(
    category: str,
    alert_type: str = "",
    raw: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Return MITRE technique dicts for the given category and optional alert_type/raw.
    Used by the decision engine when alert has no pre-tagged techniques.
    """
    from datetime import datetime, timezone

    from app.core.decision_engine.types import NormalizedAlert

    synthetic = NormalizedAlert(
        id="",
        title="",
        source="",
        severity="Medium",
        category=category,
        asset_id=None,
        user_id=None,
        source_ip=None,
        alert_type=alert_type,
        timestamp=datetime.now(timezone.utc),
        raw=raw,
        mitre_techniques=None,
        enrichment=None,
    )
    techniques = map_alert_to_techniques(synthetic)
    return [_mitre_technique_to_dict(t) for t in techniques]
