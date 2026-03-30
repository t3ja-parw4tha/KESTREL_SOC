"""Heuristic semantic clustering for investigation grouping."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert
from app.models.alert import AlertStatus

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_CLUSTER_WINDOW_HOURS = 24
_CLUSTER_THRESHOLD = 0.6


def _tokens(text: str) -> set[str]:
    return {t for t in _TOKEN_RE.findall((text or "").lower()) if len(t) > 2}


def _title_similarity(a: str, b: str) -> float:
    at = _tokens(a)
    bt = _tokens(b)
    if not at or not bt:
        return 0.0
    inter = len(at & bt)
    union = len(at | bt)
    return inter / union if union else 0.0


def _cluster_score(new_alert: Alert, existing: Alert) -> float:
    score = 0.0

    score += 0.45 * _title_similarity(new_alert.title, existing.title)
    if (new_alert.category or "").lower() == (existing.category or "").lower():
        score += 0.2
    if (new_alert.source or "").lower() == (existing.source or "").lower():
        score += 0.15

    if new_alert.source_ip and existing.source_ip and new_alert.source_ip == existing.source_ip:
        score += 0.15
    if new_alert.asset_id and existing.asset_id and new_alert.asset_id == existing.asset_id:
        score += 0.1

    return min(1.0, score)


async def assign_alert_cluster(db: AsyncSession, alert: Alert) -> dict | None:
    """Assign incident group by similarity with recent active alerts."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_CLUSTER_WINDOW_HOURS)
    rows = (
        await db.execute(
            select(Alert)
            .where(
                Alert.id != alert.id,
                Alert.status.in_([AlertStatus.OPEN, AlertStatus.IN_PROGRESS]),
                Alert.created_at >= cutoff,
                Alert.source == alert.source,
            )
            .order_by(Alert.created_at.desc())
            .limit(150)
        )
    ).scalars().all()

    best: Alert | None = None
    best_score = 0.0
    for row in rows:
        score = _cluster_score(alert, row)
        if score > best_score:
            best = row
            best_score = score

    if best is None or best_score < _CLUSTER_THRESHOLD:
        return None

    cluster_id = best.incident_group_id or str(uuid.uuid4())
    if best.incident_group_id is None:
        best.incident_group_id = cluster_id

    alert.incident_group_id = cluster_id
    return {
        "cluster_id": cluster_id,
        "score": round(best_score, 3),
        "matched_alert_id": best.id,
        "reason": "semantic_similarity",
    }
