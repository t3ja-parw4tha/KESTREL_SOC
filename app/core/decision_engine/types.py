"""Decision engine types."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class NormalizedAlert:
    """Normalized alert for decision engine input."""

    id: str
    title: str
    source: str
    severity: str
    category: str
    asset_id: str | None
    user_id: str | None
    source_ip: str | None
    alert_type: str
    timestamp: datetime
    raw: dict[str, Any] | None = None
    dest_ip: str | None = None
    mitre_techniques: list[dict[str, str]] | None = None
    enrichment: dict[str, Any] | None = None


@dataclass
class AssetContext:
    """Asset context for risk scoring."""

    asset_id: str | None
    asset_type: str | None
    is_production: bool
    is_internet_exposed: bool
    business_criticality: str | None
    tags: list[str]


@dataclass
class ThreatContext:
    """Threat intelligence context."""

    has_active_exploit: bool
    cvss_score: float | None
    cve_id: str | None
    threat_actor: str | None


@dataclass
class HistoryContext:
    """Historical context for the alert/asset."""

    prior_false_positives: int
    similar_alerts_7d: int
    last_seen: datetime | None


@dataclass
class DecisionInput:
    """Input to the decision engine."""

    alert: NormalizedAlert
    asset: AssetContext | None
    threat: ThreatContext | None
    history: HistoryContext | None


@dataclass
class DecisionOutput:
    """Output from the decision engine."""

    risk_score: int
    risk_level: str
    confidence: float
    explanation: list[str]
    recommended_actions: list[str]
    mitre_techniques: list[dict[str, str]]
    correlated_alert_ids: list[str]
    incident_group_id: str | None
    generated_at: datetime
    engine_version: str
    correlation_rule_triggered: str | None = None
