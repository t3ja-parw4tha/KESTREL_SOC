"""Alert background task handlers shared by ingest and durable job worker."""

from __future__ import annotations

import structlog
from sqlalchemy import select

from app.ai.fp_classifier import classify_false_positive_score
from app.database import SessionLocal
from app.enrichment import EnrichmentOrchestrator
from app.models import Alert
from app.notifications.dispatcher import notify_new_alert
from app.playbooks.executor import run_playbooks_for_alerts
from app.core.suppression import apply_suppression_rules
from app.services.watchlist import find_watchlist_matches

log = structlog.get_logger(__name__)


async def run_notifications_for_alerts(alert_ids: list[str]) -> None:
    """Send Slack/email notifications for high-severity alerts."""
    if not alert_ids:
        return

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
            except Exception as e:  # noqa: BLE001
                log.warning("notification.error", alert_id=alert_id, error=str(e))


async def run_suppression_for_alerts(alert_ids: list[str]) -> None:
    """Apply suppression rules to new alerts."""
    await apply_suppression_rules(alert_ids)


async def run_enrichment_for_alerts(alert_ids: list[str]) -> None:
    """Run enrichment + watchlist + FP classifier and persist results."""
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
                if fp_classifier["candidate"] and "FP_CANDIDATE" not in existing_tags:
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
                    alert.risk_score = min(100, alert.risk_score + result.risk_modifier)
                await db.flush()
                await db.commit()
                log.info(
                    "alert.enriched",
                    alert_id=alert_id,
                    risk_modifier=result.risk_modifier,
                    summary=result.summary,
                )
            except Exception as e:  # noqa: BLE001
                log.warning("alert.enrichment_error", alert_id=alert_id, error=str(e))


async def run_playbooks_for_alerts_task(alert_ids: list[str]) -> None:
    """Run active playbooks against new alerts."""
    await run_playbooks_for_alerts(alert_ids)
