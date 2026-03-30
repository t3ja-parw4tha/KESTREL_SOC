"""
Shared ingest processing: parse, decision engine, persist.
Used by API ingest endpoint and by pull connectors (runner).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.alert_clustering import assign_alert_cluster
from app.core.decision_engine.engine import run_decision_engine
from app.core.decision_engine.types import DecisionInput
from app.core.mitre.mapping import map_alert_to_techniques
from app.core.parsers import parse_event
from app.models import Alert, AlertDecision
from app.models.alert import AlertSeverity, AlertStatus
from app.observability.metrics import ALERTS_INGESTED
from app.security.sanitization import sanitize_log_data
from app.services.soar import run_playbooks_for_alert

DEDUP_WINDOW_MINUTES = 60  # Deduplicate within a 60-minute window


async def _find_duplicate(db: AsyncSession, title: str, source: str) -> Alert | None:
    """Return an existing open alert with the same title+source within the dedup window."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=DEDUP_WINDOW_MINUTES)
    r = await db.execute(
        select(Alert)
        .where(
            Alert.title == title[:512],
            Alert.source == source,
            Alert.status.in_([AlertStatus.OPEN, AlertStatus.IN_PROGRESS]),
            Alert.created_at >= cutoff,
        )
        .order_by(Alert.created_at.desc())
        .limit(1)
    )
    return r.scalar_one_or_none()


async def process_events(
    db: AsyncSession,
    source: str,
    events: list[dict],
) -> tuple[list[str], list[str]]:
    """
    Sanitize, parse, run decision engine, and persist alerts.
    Returns (ingested_ids, errors). Caller commits and enqueues enrichment/notifications.
    """
    ingested_ids: list[str] = []
    errors: list[str] = []
    for idx, raw_event in enumerate(events):
        try:
            sanitized = sanitize_log_data(raw_event)
            normalized = parse_event(source, sanitized)
            mitre_objs = map_alert_to_techniques(normalized)
            mitre_dicts = [
                {
                    "technique_id": t.technique_id,
                    "technique_name": t.technique_name,
                    "tactic": t.tactic,
                    "subtechniques": list(t.subtechniques),
                }
                for t in mitre_objs
            ]
            normalized.mitre_techniques = mitre_dicts  # type: ignore[assignment]

            decision_input = DecisionInput(
                alert=normalized,
                asset=None,
                threat=None,
                history=None,
            )
            decision_output = run_decision_engine(decision_input, recent_alerts=[])

            # ── Deduplication ──────────────────────────────────────────────────
            existing = await _find_duplicate(db, normalized.title[:512], normalized.source)
            if existing is not None:
                enrichment = dict(existing.enrichment or {})
                enrichment["duplicate_count"] = enrichment.get("duplicate_count", 1) + 1
                existing.enrichment = enrichment
                await db.flush()
                # Don't add to ingested_ids — no new alert created
                continue

            alert_id = normalized.id or str(uuid.uuid4())
            try:
                severity_enum = AlertSeverity(normalized.severity)
            except ValueError:
                severity_enum = AlertSeverity.HIGH

            db_alert = Alert(
                id=alert_id,
                title=normalized.title[:512],
                source=normalized.source,
                severity=severity_enum,
                category=normalized.category,
                status=AlertStatus.OPEN,
                asset_id=normalized.asset_id,
                user_id=normalized.user_id,
                source_ip=normalized.source_ip,
                dest_ip=getattr(normalized, "dest_ip", None),
                mitre_techniques=mitre_dicts,
                raw=normalized.raw,
                enrichment={},
                risk_score=decision_output.risk_score,
                risk_level=decision_output.risk_level,
                confidence=decision_output.confidence,
                incident_group_id=decision_output.incident_group_id,
                correlated_alert_ids={
                    "ids": decision_output.correlated_alert_ids
                }
                if decision_output.correlated_alert_ids
                else None,
            )
            db.add(db_alert)
            db.add(
                AlertDecision(
                    id=str(uuid.uuid4()),
                    alert_id=alert_id,
                    risk_score=decision_output.risk_score,
                    risk_level=decision_output.risk_level,
                    confidence=decision_output.confidence,
                    explanation={"items": decision_output.explanation},
                    recommended_actions={"items": decision_output.recommended_actions},
                    mitre_techniques={"items": mitre_dicts},
                    correlated_alert_ids={
                        "ids": decision_output.correlated_alert_ids
                    }
                    if decision_output.correlated_alert_ids
                    else None,
                    incident_group_id=decision_output.incident_group_id,
                    engine_version=decision_output.engine_version,
                )
            )

            # Semantic clustering fallback: if decision engine did not group,
            # try to attach to a recent, similar investigation cluster.
            if not db_alert.incident_group_id:
                cluster = await assign_alert_cluster(db, db_alert)
                if cluster:
                    db_alert.enrichment = {
                        **(db_alert.enrichment or {}),
                        "ai_cluster": cluster,
                    }

            # Evaluate playbooks
            await run_playbooks_for_alert(db, db_alert)

            ingested_ids.append(alert_id)
            ALERTS_INGESTED.labels(
                source=normalized.source,
                severity=normalized.severity,
                category=normalized.category,
            ).inc()
        except Exception as e:
            errors.append(f"Event index={idx}: {e}")
            continue
    return ingested_ids, errors
