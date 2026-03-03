"""Recommended actions by category and MITRE technique."""

from app.core.decision_engine.types import NormalizedAlert

_CATEGORY_ACTIONS: dict[str, list[str]] = {
    "Auth": [
        "Block source IP",
        "Reset compromised credentials",
        "Enable MFA",
        "Review recent account activity",
    ],
    "Malware": [
        "Isolate endpoint immediately",
        "Collect memory dump",
        "Run full AV scan",
        "Review process tree",
    ],
    "Network": [
        "Block source IP at perimeter",
        "Capture network traffic",
        "Review firewall rules",
    ],
    "Data": [
        "Revoke data access",
        "Review DLP logs",
        "Notify data owner",
        "Preserve evidence",
    ],
    "Policy": [
        "Review policy violation context",
        "Update security policy if needed",
        "Notify compliance team",
    ],
    "Lateral Movement": [
        "Isolate affected systems",
        "Review authentication logs",
        "Reset credentials on jump hosts",
    ],
    "Privilege Escalation": [
        "Revoke elevated privileges",
        "Review privilege changes",
        "Audit local admin accounts",
    ],
    "Other": [
        "Triage alert manually",
        "Gather additional context",
        "Escalate if needed",
    ],
}

_MITRE_ACTIONS: dict[str, list[str]] = {
    "T1110": ["Block source IP", "Enable account lockout", "Review brute force patterns"],
    "T1003": ["Isolate endpoint", "Rotate credentials", "Check for LSASS access"],
    "T1046": ["Block scanning IP", "Review firewall rules", "Check for reconnaissance"],
    "T1547": ["Review startup items", "Remove persistence", "Audit registry"],
    "T1053": ["Review scheduled tasks", "Remove malicious tasks", "Audit task history"],
    "T1041": ["Review C2 channels", "Block exfiltration", "Capture traffic"],
    "T1048": ["Review DNS tunneling", "Block anomalous DNS", "Capture DNS logs"],
    "T1068": ["Patch vulnerability", "Review privilege chain", "Audit local privileges"],
    "T1548": ["Revoke admin", "Review UAC bypass", "Audit elevation events"],
    "T1021": ["Review RDP/SMB access", "Reset remote credentials", "Isolate systems"],
    "T1570": ["Block lateral traffic", "Review internal connectivity", "Isolate segment"],
    "T1136": ["Disable created account", "Review account creation", "Audit new users"],
    "T1098": ["Revoke account changes", "Review persistence", "Audit group membership"],
}


def get_recommended_actions(alert: NormalizedAlert) -> list[str]:
    """
    Return category-specific, prioritized action list.
    Includes MITRE technique-specific actions when applicable.
    """
    category = alert.category or "Other"
    base = _CATEGORY_ACTIONS.get(category, _CATEGORY_ACTIONS["Other"])

    # Add MITRE-specific actions
    mitre_ids: set[str] = set()
    for t in alert.mitre_techniques or []:
        if isinstance(t, dict):
            tid = t.get("technique_id") or t.get("id")
            if tid:
                mitre_ids.add(tid)
                # Handle sub-techniques (e.g. T1021.002 -> T1021)
                base_id = tid.split(".")[0]
                mitre_ids.add(base_id)

    extra: list[str] = []
    for tid in sorted(mitre_ids):
        if tid in _MITRE_ACTIONS:
            for a in _MITRE_ACTIONS[tid]:
                if a not in base and a not in extra:
                    extra.append(a)
        base_id = tid.split(".")[0]
        if base_id != tid and base_id in _MITRE_ACTIONS:
            for a in _MITRE_ACTIONS[base_id]:
                if a not in base and a not in extra:
                    extra.append(a)

    return list(base) + extra[:5]
