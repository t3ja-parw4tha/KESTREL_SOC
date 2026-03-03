"""Ingest API router. All incoming payloads sanitized (OWASP)."""

from __future__ import annotations

import asyncio
import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.decision_engine.engine import run_decision_engine
from app.core.decision_engine.types import DecisionInput
from app.core.mitre.mapping import map_alert_to_techniques
from app.core.parsers import parse_event
from sqlalchemy import select

from app.database import SessionLocal, get_db
from app.enrichment import EnrichmentOrchestrator
from app.models import Alert, AlertDecision
from app.models.alert import AlertSeverity, AlertStatus
from app.observability.log_sanitizer import sanitize_for_log
from app.observability.metrics import ALERTS_INGESTED
from app.schemas.ingest import IngestResponseSchema, IngestSchema
from app.security.exceptions import SecurityError
from app.security.rbac import require_permission
from app.security.sanitization import sanitize_json, sanitize_log_data

router = APIRouter(prefix="/ingest", tags=["ingest"])
log = structlog.get_logger(__name__)


async def _enqueue_enrichment(alert_ids: list[str]) -> None:
    """Run enrichment (IOC extraction, VT/AbuseIPDB, feeds) and write back to alerts."""
    if not alert_ids:
        return
    orchestrator = EnrichmentOrchestrator()
    async with SessionLocal() as db:
        for alert_id in alert_ids:
            try:
                r = await db.execute(select(Alert).where(Alert.id == alert_id))
                alert = r.scalar_one_or_none()
                if not alert:
                    continue
                result = await orchestrator.enrich_alert(alert)
                existing = alert.enrichment or {}
                alert.enrichment = {
                    **existing,
                    "iocs": {
                        "ips": result.iocs_found.ips,
                        "domains": result.iocs_found.domains,
                        "hashes": result.iocs_found.hashes,
                        "cves": result.iocs_found.cves,
                    },
                    "vt_results": [
                        {
                            "indicator": r.indicator,
                            "malicious_count": r.malicious_count,
                            "detection_ratio": r.detection_ratio,
                            "threat_categories": r.threat_categories,
                            "cached": r.cached,
                            "error": r.error,
                        }
                        for r in result.vt_results
                    ],
                    "abuse_results": [
                        {
                            "ip": r.ip,
                            "abuse_score": r.abuse_score,
                            "country_code": r.country_code,
                            "total_reports": r.total_reports,
                            "cached": r.cached,
                        }
                        for r in result.abuse_results
                    ],
                    "feed_matches": [
                        {
                            "indicator": m.indicator,
                            "feed_name": m.feed_name,
                        }
                        for m in result.feed_matches
                    ],
                    "risk_modifier": result.risk_modifier,
                    "summary": result.summary,
                }
                if result.risk_modifier > 0 and alert.risk_score is not None:
                    alert.risk_score = min(
                        100, alert.risk_score + result.risk_modifier
                    )
                await db.flush()
                await db.commit()
                log.info(
                    "alert.enriched",
                    alert_id=alert_id,
                    risk_modifier=result.risk_modifier,
                    summary=result.summary,
                )
            except Exception as e:
                log.warning(
                    "alert.enrichment_error",
                    alert_id=alert_id,
                    error=str(e),
                )


@router.post("", response_model=IngestResponseSchema)
async def ingest_events(
    body: dict,
    background_tasks: BackgroundTasks,
    _user: Annotated[dict, Depends(require_permission("ingest:write"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> IngestResponseSchema:
    """
    Accept ingested events. Payload is sanitized (sanitize_json) before validation and processing.
    Event contents are further sanitized for log storage (sensitive fields redacted).
    """
    try:
        sanitized_payload = sanitize_json(body)
    except SecurityError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    try:
        parsed = IngestSchema.model_validate(sanitized_payload)
    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    source = sanitize_for_log(parsed.source)
    event_count = len(parsed.events)
    log.info("alert.received", source=source, event_count=event_count)

    ingested_ids: list[str] = []
    errors: list[str] = []

    for idx, raw_event in enumerate(parsed.events):
        try:
            sanitized_event = sanitize_log_data(raw_event)

            # Normalize to decision engine alert
            normalized = parse_event(parsed.source, sanitized_event)

            # MITRE mapping
            mitre_objs = map_alert_to_techniques(normalized)
            mitre_dicts = [
                {
                    "technique_id": t.technique_id,
                    "technique_name": t.technique_name,
                    "tactic": t.tactic,
                    "subtechniques": t.subtechniques,
                }
                for t in mitre_objs
            ]
            normalized.mitre_techniques = mitre_dicts

            # Decision engine
            decision_input = DecisionInput(
                alert=normalized,
                asset=None,
                threat=None,
                history=None,
            )
            decision_output = run_decision_engine(decision_input, recent_alerts=[])

            # Persist alert (enrichment populated by background _enqueue_enrichment)
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

            # Persist decision
            db_decision = AlertDecision(
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
            db.add(db_decision)

            ingested_ids.append(alert_id)
            ALERTS_INGESTED.labels(
                source=normalized.source,
                severity=normalized.severity,
                category=normalized.category,
            ).inc()

            log.info(
                "alert.decision_complete",
                source=source,
                risk_score=decision_output.risk_score,
                risk_level=decision_output.risk_level,
            )
        except Exception as e:  # pragma: no cover - best-effort per-event error capture
            msg = f"Failed to ingest event index={idx}: {e}"
            log.warning("alert.ingest_error", source=source, error=str(e))
            errors.append(msg)

    if ingested_ids:
        background_tasks.add_task(_enqueue_enrichment, ingested_ids)

    log.info("alert.stored", event_count=len(ingested_ids))

    return IngestResponseSchema(
        status="ok",
        ingested=len(ingested_ids),
        alerts=ingested_ids,
        errors=errors,
    )
