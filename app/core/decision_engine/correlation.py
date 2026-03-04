"""Alert correlation for incident grouping."""

import hashlib
from datetime import datetime, timezone
from typing import NamedTuple

from app.core.decision_engine.types import NormalizedAlert


class CorrelationResult(NamedTuple):
    correlated_alert_ids: list[str]
    incident_group_id: str | None
    correlation_rule_triggered: str | None


def _ensure_aware(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


def _get_mitre_ids(alert: NormalizedAlert) -> set[str]:
    ids: set[str] = set()
    for t in alert.mitre_techniques or []:
        if isinstance(t, dict) and "technique_id" in t:
            ids.add(t["technique_id"])
        elif isinstance(t, dict) and "id" in t:
            ids.add(t["id"])
    return ids


def _make_incident_group_id(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:36]


def correlate_alerts(
    current: NormalizedAlert,
    recent_alerts: list[NormalizedAlert],
) -> CorrelationResult:
    """
    Correlate current alert with recent alerts.
    Rules: same asset+user 15min, same asset+alert_type 10min,
    same source_ip 5min, same MITRE technique 30min.
    Returns correlated_alert_ids, incident_group_id, correlation_rule_triggered.
    """
    now = _ensure_aware(current.timestamp)
    correlated: list[str] = []
    rule_triggered: str | None = None
    incident_group_id: str | None = None

    for other in recent_alerts:
        if other.id == current.id:
            continue
        other_ts = _ensure_aware(other.timestamp)

        # Rule 1: same asset_id + same user_id within 15 minutes
        if (
            current.asset_id
            and current.user_id
            and current.asset_id == other.asset_id
            and current.user_id == other.user_id
            and abs((now - other_ts).total_seconds()) <= 15 * 60
        ):
            correlated.append(other.id)
            if rule_triggered is None:
                rule_triggered = "same_asset_user_15min"
                incident_group_id = _make_incident_group_id(
                    f"{current.asset_id}|{current.user_id}|{now.isoformat()[:16]}"
                )

        # Rule 2: same asset_id + same alert_type within 10 minutes
        if (
            current.asset_id
            and current.asset_id == other.asset_id
            and current.alert_type == other.alert_type
            and abs((now - other_ts).total_seconds()) <= 10 * 60
        ):
            if other.id not in correlated:
                correlated.append(other.id)
            if rule_triggered is None:
                rule_triggered = "same_asset_alert_type_10min"
                incident_group_id = _make_incident_group_id(
                    f"{current.asset_id}|{current.alert_type}|{now.isoformat()[:16]}"
                )

        # Rule 3: same source_ip within 5 minutes (network attack pattern)
        if (
            current.source_ip
            and current.source_ip == other.source_ip
            and abs((now - other_ts).total_seconds()) <= 5 * 60
        ):
            if other.id not in correlated:
                correlated.append(other.id)
            if rule_triggered is None:
                rule_triggered = "same_source_ip_5min"
                incident_group_id = _make_incident_group_id(
                    f"{current.source_ip}|{now.isoformat()[:16]}"
                )

        # Rule 4: same MITRE technique within 30 minutes (campaign detection)
        curr_mitre = _get_mitre_ids(current)
        other_mitre = _get_mitre_ids(other)
        overlap = curr_mitre & other_mitre
        if overlap and abs((now - other_ts).total_seconds()) <= 30 * 60:
            if other.id not in correlated:
                correlated.append(other.id)
            if rule_triggered is None:
                rule_triggered = "same_mitre_technique_30min"
                incident_group_id = _make_incident_group_id(
                    f"{sorted(overlap)[0]}|{now.isoformat()[:16]}"
                )

    if correlated and incident_group_id is None:
        incident_group_id = _make_incident_group_id(
            f"{current.id}|{','.join(sorted(correlated)[:5])}|{now.isoformat()[:16]}"
        )

    return CorrelationResult(
        correlated_alert_ids=sorted(set(correlated)),
        incident_group_id=incident_group_id,
        correlation_rule_triggered=rule_triggered,
    )
