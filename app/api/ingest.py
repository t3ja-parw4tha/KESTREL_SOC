"""Ingest API router. All incoming payloads sanitized (OWASP)."""

from __future__ import annotations

from typing import Annotated

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ingest import process_events
from app.database import SessionLocal, get_db
from app.enrichment import EnrichmentOrchestrator
from app.models import Alert
from app.observability.log_sanitizer import sanitize_for_log
from app.schemas.ingest import IngestResponseSchema, IngestSchema
from app.security.exceptions import SecurityError
from app.security.rbac import require_permission
from app.security.sanitization import sanitize_json, sanitize_log_data

router = APIRouter(prefix="/ingest", tags=["ingest"])
log = structlog.get_logger(__name__)


async def _enqueue_notifications(alert_ids: list[str]) -> None:
    """Send Slack/email for critical/high alerts (background)."""
    if not alert_ids:
        return
    from app.notifications.dispatcher import notify_new_alert

    async with SessionLocal() as db:
        for alert_id in alert_ids:
            try:
                r = await db.execute(select(Alert).where(Alert.id == alert_id))
                alert = r.scalar_one_or_none()
                if not alert:
                    continue
                severity = alert.severity.value if alert.severity else ""
                if severity not in ("Critical", "High"):
                    continue
                payload = {
                    "id": alert.id,
                    "title": alert.title or "",
                    "severity": severity,
                    "source": alert.source or "",
                    "ai_summary": alert.ai_summary or "",
                }
                await notify_new_alert(payload)
            except Exception as e:
                log.warning("notification.error", alert_id=alert_id, error=str(e))


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

    try:
        ingested_ids, errors = await process_events(db, parsed.source, parsed.events)
    except Exception as e:
        log.warning("alert.ingest_error", source=source, error=str(e))
        raise HTTPException(status_code=500, detail="Ingest processing failed") from e

    if ingested_ids:
        background_tasks.add_task(_enqueue_enrichment, ingested_ids)
        background_tasks.add_task(_enqueue_notifications, ingested_ids)

    log.info("alert.stored", event_count=len(ingested_ids))

    return IngestResponseSchema(
        status="ok",
        ingested=len(ingested_ids),
        alerts=ingested_ids,
        errors=errors,
    )
