"""Watchlist matching helpers for enrichment pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import IOCWatchlistEntry

_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


def normalize_indicator(indicator: str, indicator_type: str) -> str:
    """Normalize indicator format for consistent matching."""
    value = indicator.strip()
    kind = indicator_type.strip().lower()
    if kind in {"ip", "domain"}:
        return value.lower()
    if kind == "hash":
        return value.lower()
    return value.lower()


def infer_indicator_type(indicator: str) -> str | None:
    """Infer IOC type from value shape."""
    value = indicator.strip()
    if not value:
        return None
    if _HASH_RE.fullmatch(value):
        return "hash"
    if "." in value and not any(ch.isspace() for ch in value):
        if value.replace(".", "").isdigit():
            return "ip"
        return "domain"
    return None


async def find_watchlist_matches(
    db: AsyncSession,
    ips: list[str],
    domains: list[str],
    hashes: list[str],
) -> list[dict[str, str | int]]:
    """Return active watchlist matches and bump hit counters."""
    normalized_map: dict[str, str] = {}
    for ip in ips:
        normalized_map[normalize_indicator(ip, "ip")] = "ip"
    for domain in domains:
        normalized_map[normalize_indicator(domain, "domain")] = "domain"
    for h in hashes:
        normalized_map[normalize_indicator(h, "hash")] = "hash"

    if not normalized_map:
        return []

    rows = (
        await db.execute(
            select(IOCWatchlistEntry).where(
                IOCWatchlistEntry.is_active.is_(True),
                IOCWatchlistEntry.indicator.in_(list(normalized_map.keys())),
            )
        )
    ).scalars().all()

    matches: list[dict[str, str | int]] = []
    now = datetime.now(timezone.utc)
    for row in rows:
        row.match_count = int(row.match_count or 0) + 1
        row.last_matched_at = now
        matches.append(
            {
                "indicator": row.indicator,
                "indicator_type": row.indicator_type,
                "confidence": int(row.confidence),
                "tag": f"WATCHLIST:{row.indicator}",
            }
        )

    return matches
