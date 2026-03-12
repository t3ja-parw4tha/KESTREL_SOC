"""
Run pull connectors on a schedule. Uses credentials from config only.
Starts background task that runs Sentinel and GuardDuty at a configurable interval.
"""

import asyncio
import logging
from typing import Any

from app.core.ingest import process_events
from app.database import SessionLocal
from app.connectors.base import BaseConnector
from app.connectors.sentinel import SentinelConnector
from app.connectors.guardduty import GuardDutyConnector

logger = logging.getLogger(__name__)

# Connectors to run (pull sources only)
CONNECTORS: list[BaseConnector] = [
    SentinelConnector(),
    GuardDutyConnector(),
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
    try:
        events = await connector.pull()
    except Exception as e:
        logger.warning("connector.pull failed: %s %s", source, e)
        return []
    if not events:
        return []
    async with SessionLocal() as db:
        try:
            ingested, _ = await process_events(db, source, events)
            await db.commit()
            if ingested:
                asyncio.create_task(_enqueue_enrichment(ingested))
                asyncio.create_task(_enqueue_notifications(ingested))
            return ingested
        except Exception as e:
            await db.rollback()
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
