"""Ingest API router. All incoming payloads sanitized (OWASP)."""

from __future__ import annotations

from typing import Annotated
import hashlib
from time import perf_counter

import structlog
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ingest import process_events
from app.ai.fp_classifier import classify_false_positive_score
from app.database import SessionLocal, get_db
from app.enrichment import EnrichmentOrchestrator
from app.models import Alert
from app.observability.log_sanitizer import sanitize_for_log
from app.schemas.ingest import IngestResponseSchema, IngestSchema
from app.security.exceptions import SecurityError
from app.security.rbac import require_permission
from app.security.sanitization import sanitize_json
from app.services.watchlist import find_watchlist_matches
from app.services.job_queue import enqueue_job
from app.services.source_health import record_source_ingestion

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


async def _enqueue_playbooks(alert_ids: list[str]) -> None:
    """Run active playbooks against each new alert (background)."""
    from app.playbooks.executor import run_playbooks_for_alerts
    await run_playbooks_for_alerts(alert_ids)


async def _enqueue_suppression(alert_ids: list[str]) -> None:
    """Apply active suppression rules against each new alert (background)."""
    from app.core.suppression import apply_suppression_rules
    await apply_suppression_rules(alert_ids)


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
                watchlist_matches = await find_watchlist_matches(
                    db,
                    ips=result.iocs_found.ips,
                    domains=result.iocs_found.domains,
                    hashes=result.iocs_found.hashes,
                )
                watchlist_tags = [str(m.get("tag")) for m in watchlist_matches if m.get("tag")]
                existing = alert.enrichment or {}
                duplicate_count = int((existing.get("duplicate_count") or 1) if isinstance(existing, dict) else 1)
                fp_classifier = classify_false_positive_score(
                    severity=alert.severity.value if alert.severity else "",
                    duplicate_count=duplicate_count,
                    feed_match_count=len(result.feed_matches),
                    vt_results=[
                        {
                            "malicious_count": r.malicious_count,
                            "suspicious_count": r.suspicious_count,
                        }
                        for r in result.vt_results
                    ],
                    abuse_results=[
                        {"abuse_score": r.abuse_score}
                        for r in result.abuse_results
                    ],
                )
                existing_tags = list(existing.get("watchlist_tags") or [])
                for tag in watchlist_tags:
                    if tag not in existing_tags:
                        existing_tags.append(tag)
                if fp_classifier["candidate"]:
                    if "FP_CANDIDATE" not in existing_tags:
                        existing_tags.append("FP_CANDIDATE")
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
                    "watchlist_matches": watchlist_matches,
                    "watchlist_tags": existing_tags,
                    "fp_classifier": fp_classifier,
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


def _job_key(job_type: str, alert_ids: list[str]) -> str:
    joined = ",".join(sorted(set(alert_ids)))
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()
    return f"{job_type}:{digest}"


@router.post("", response_model=IngestResponseSchema)
async def ingest_events(
    body: dict,
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
    started_at = perf_counter()
    log.info("alert.received", source=source, event_count=event_count)

    try:
        ingested_ids, errors = await process_events(db, parsed.source, parsed.events)
    except Exception as e:
        await record_source_ingestion(
            db,
            source_id=parsed.source,
            source_name=parsed.source,
            events_received=event_count,
            alerts_ingested=0,
            processing_errors=event_count,
            success=False,
            last_error=str(e),
            ingest_lag_seconds=perf_counter() - started_at,
        )
        log.warning("alert.ingest_error", source=source, error=str(e))
        raise HTTPException(status_code=500, detail="Ingest processing failed") from e

    if ingested_ids:
        await enqueue_job(
            db,
            job_type="alerts_suppression",
            payload={"alert_ids": ingested_ids},
            idempotency_key=_job_key("alerts_suppression", ingested_ids),
        )
        await enqueue_job(
            db,
            job_type="alerts_enrichment",
            payload={"alert_ids": ingested_ids},
            idempotency_key=_job_key("alerts_enrichment", ingested_ids),
        )
        await enqueue_job(
            db,
            job_type="alerts_notifications",
            payload={"alert_ids": ingested_ids},
            idempotency_key=_job_key("alerts_notifications", ingested_ids),
        )
        await enqueue_job(
            db,
            job_type="alerts_playbooks",
            payload={"alert_ids": ingested_ids},
            idempotency_key=_job_key("alerts_playbooks", ingested_ids),
        )

    await record_source_ingestion(
        db,
        source_id=parsed.source,
        source_name=parsed.source,
        events_received=event_count,
        alerts_ingested=len(ingested_ids),
        processing_errors=len(errors),
        success=len(errors) == 0,
        last_error=(errors[0] if errors else None),
        ingest_lag_seconds=perf_counter() - started_at,
    )

    log.info("alert.stored", event_count=len(ingested_ids))

    return IngestResponseSchema(
        status="ok",
        ingested=len(ingested_ids),
        alerts=ingested_ids,
        errors=errors,
    )
