"""Pre-built SOC playbook templates for rapid automation onboarding."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PlaybookTemplate:
    """A declarative template for creating a playbook row."""

    key: str
    name: str
    description: str
    trigger_type: str
    conditions: list[dict[str, str]]
    actions: list[dict[str, str]]


PLAYBOOK_LIBRARY: tuple[PlaybookTemplate, ...] = (
    PlaybookTemplate(
        key="phishing_triage",
        name="Phishing Triage - High Confidence Mail Threat",
        description=(
            "Auto-tag and assign likely phishing alerts so analysts can quickly "
            "validate user impact and mailbox spread."
        ),
        trigger_type="alert_created",
        conditions=[
            {"field": "category", "operator": "contains", "value": "email"},
            {"field": "title", "operator": "contains", "value": "phish"},
        ],
        actions=[
            {"type": "add_tag", "value": "PHISHING_TRIAGE"},
            {"type": "set_status", "value": "in_progress"},
            {"type": "assign_to", "value": "email-ir-queue"},
        ],
    ),
    PlaybookTemplate(
        key="ransomware_triage",
        name="Ransomware Triage - Immediate Containment",
        description=(
            "Escalate and triage likely ransomware behaviors with high urgency "
            "to reduce dwell time and blast radius."
        ),
        trigger_type="alert_created",
        conditions=[
            {"field": "title", "operator": "contains", "value": "ransom"},
            {"field": "severity", "operator": "equals", "value": "critical"},
        ],
        actions=[
            {"type": "add_tag", "value": "RANSOMWARE_TRIAGE"},
            {"type": "set_status", "value": "in_progress"},
            {"type": "set_severity", "value": "critical"},
            {"type": "assign_to", "value": "containment-lead"},
        ],
    ),
    PlaybookTemplate(
        key="bruteforce_triage",
        name="Brute-Force Triage - Identity Attack Pattern",
        description=(
            "Detect repeated identity authentication attack patterns and route "
            "to identity response queue for rapid lockout and validation."
        ),
        trigger_type="alert_created",
        conditions=[
            {"field": "category", "operator": "contains", "value": "identity"},
            {"field": "title", "operator": "contains", "value": "brute"},
        ],
        actions=[
            {"type": "add_tag", "value": "BRUTEFORCE_TRIAGE"},
            {"type": "set_status", "value": "in_progress"},
            {"type": "assign_to", "value": "identity-ir-queue"},
        ],
    ),
)


def get_playbook_template(key: str) -> PlaybookTemplate | None:
    """Return a template by key if available."""
    normalized = key.strip().lower()
    for template in PLAYBOOK_LIBRARY:
        if template.key == normalized:
            return template
    return None
