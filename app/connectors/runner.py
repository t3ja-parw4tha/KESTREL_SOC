"""
Run pull connectors on a schedule. Uses credentials from config only.
Starts background task that runs all configured pull-based connectors at a
configurable interval (default 5 minutes).
"""

import asyncio
import logging
from time import perf_counter
from typing import Any

from app.core.ingest import process_events
from app.database import SessionLocal
from app.connectors.base import BaseConnector
from app.connectors.sentinel import SentinelConnector
from app.connectors.guardduty import GuardDutyConnector
from app.connectors.splunk import SplunkConnector
from app.connectors.qradar import QRadarConnector
from app.connectors.elastic import ElasticConnector
from app.connectors.crowdstrike import CrowdStrikeConnector
from app.connectors.sentinelone import SentinelOneConnector
from app.connectors.carbonblack import CarbonBlackConnector
from app.connectors.cortex_xdr import CortexXDRConnector
from app.connectors.azure_defender import AzureDefenderConnector
from app.connectors.cloudtrail import CloudTrailConnector
from app.connectors.okta import OktaConnector
from app.connectors.azure_ad import AzureADConnector
from app.connectors.microsoft_365 import Microsoft365Connector
from app.connectors.panos import PanosConnector
from app.connectors.fortinet import FortinetConnector
from app.connectors.tenable import TenableConnector
from app.connectors.qualys import QualysConnector
from app.connectors.gcp_scc import GcpSccConnector
from app.connectors.google_workspace import GoogleWorkspaceConnector
from app.observability.metrics import (
    CONNECTOR_EVENTS_FETCHED,
    CONNECTOR_INGESTION_DURATION,
    CONNECTOR_LAST_RUN,
)
from app.services.source_health import record_source_ingestion

logger = logging.getLogger(__name__)

# All pull-based connectors — each pulls data on the configured interval
CONNECTORS: list[BaseConnector] = [
    SentinelConnector(),
    GuardDutyConnector(),
    SplunkConnector(),
    QRadarConnector(),
    ElasticConnector(),
    CrowdStrikeConnector(),
    SentinelOneConnector(),
    CarbonBlackConnector(),
    CortexXDRConnector(),
    AzureDefenderConnector(),
    CloudTrailConnector(),
    OktaConnector(),
    AzureADConnector(),
    Microsoft365Connector(),
    PanosConnector(),
    FortinetConnector(),
    TenableConnector(),
    QualysConnector(),
    GcpSccConnector(),
    GoogleWorkspaceConnector(),
]

# Default interval seconds between runs
DEFAULT_INTERVAL_SEC = 300  # 5 minutes


async def _enqueue_enrichment(alert_ids: list[str]) -> None:
    """Reuse enrichment from ingest (avoid circular import by late import)."""
    if not alert_ids:
        return
    from app.api.ingest import _enqueue_enrichment as _enrich
    await _enrich(alert_ids)


async def _enqueue_notifications(alert_ids: list[str]) -> None:
    """Reuse notifications from ingest."""
    if not alert_ids:
        return
    from app.api.ingest import _enqueue_notifications as _notify
    await _notify(alert_ids)


async def _run_connector(connector: BaseConnector) -> list[str]:
    """Pull events from one connector and process into alerts. Returns ingested IDs."""
    source = connector.source_name
    source_id = connector.source_id
    started_at = perf_counter()

    try:
        events = await connector.pull()
    except Exception as e:
        CONNECTOR_EVENTS_FETCHED.labels(connector=source_id, status="error").inc()
        async with SessionLocal() as db:
            await record_source_ingestion(
                db,
                source_id=source_id,
                source_name=source,
                events_received=0,
                alerts_ingested=0,
                processing_errors=1,
                success=False,
                last_error=str(e),
                ingest_lag_seconds=perf_counter() - started_at,
            )
            await db.commit()
        logger.warning("connector.pull failed: %s %s", source, e)
        return []

    CONNECTOR_EVENTS_FETCHED.labels(connector=source_id, status="success").inc(len(events))
    if not events:
        CONNECTOR_LAST_RUN.labels(connector=source_id).set_to_current_time()
        CONNECTOR_INGESTION_DURATION.labels(connector=source_id).observe(perf_counter() - started_at)
        async with SessionLocal() as db:
            await record_source_ingestion(
                db,
                source_id=source_id,
                source_name=source,
                events_received=0,
                alerts_ingested=0,
                processing_errors=0,
                success=True,
                ingest_lag_seconds=perf_counter() - started_at,
            )
            await db.commit()
        return []

    async with SessionLocal() as db:
        try:
            ingested, errors = await process_events(db, source, events)
            await record_source_ingestion(
                db,
                source_id=source_id,
                source_name=source,
                events_received=len(events),
                alerts_ingested=len(ingested),
                processing_errors=len(errors),
                success=len(errors) == 0,
                last_error=(errors[0] if errors else None),
                ingest_lag_seconds=perf_counter() - started_at,
            )
            await db.commit()
            CONNECTOR_LAST_RUN.labels(connector=source_id).set_to_current_time()
            CONNECTOR_INGESTION_DURATION.labels(connector=source_id).observe(perf_counter() - started_at)
            if ingested:
                asyncio.create_task(_enqueue_enrichment(ingested))
                asyncio.create_task(_enqueue_notifications(ingested))
            return ingested
        except Exception as e:
            await db.rollback()
            async with SessionLocal() as db_failed:
                await record_source_ingestion(
                    db_failed,
                    source_id=source_id,
                    source_name=source,
                    events_received=len(events),
                    alerts_ingested=0,
                    processing_errors=len(events),
                    success=False,
                    last_error=str(e),
                    ingest_lag_seconds=perf_counter() - started_at,
                )
                await db_failed.commit()
            logger.warning("connector.process_events failed: %s %s", source, e)
            return []


async def run_once() -> dict[str, Any]:
    """Run all connectors once. Returns summary { connector_id: count }."""
    summary: dict[str, Any] = {}
    for conn in CONNECTORS:
        try:
            ids = await _run_connector(conn)
            summary[conn.source_id] = len(ids)
        except Exception as e:
            logger.warning("connector run failed: %s %s", conn.source_id, e)
            summary[conn.source_id] = {"error": str(e)}
    return summary


async def run_loop(interval_sec: int = DEFAULT_INTERVAL_SEC) -> None:
    """Run connectors every interval_sec. Never returns; catch and log errors."""
    while True:
        try:
            await run_once()
        except Exception as e:
            logger.exception("connector_loop error: %s", e)
        await asyncio.sleep(interval_sec)
