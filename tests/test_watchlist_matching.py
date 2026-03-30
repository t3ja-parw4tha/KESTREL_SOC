"""Unit tests for IOC watchlist matching/tagging service (P3-2)."""

import uuid

import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.models import IOCWatchlistEntry
from app.services.watchlist import find_watchlist_matches


@pytest.mark.asyncio
async def test_find_watchlist_matches_increments_hit_count_and_returns_tags():
    indicator = f"{uuid.uuid4().hex[:8]}.watchlist.test"

    async with SessionLocal() as db:
        row = IOCWatchlistEntry(
            indicator=indicator,
            indicator_type="domain",
            confidence=90,
            notes="Test IOC",
            is_active=True,
            created_by="pytest",
        )
        db.add(row)
        await db.commit()

        matches = await find_watchlist_matches(db, ips=[], domains=[indicator], hashes=[])
        await db.commit()

        assert len(matches) == 1
        assert matches[0]["indicator"] == indicator
        assert matches[0]["tag"] == f"WATCHLIST:{indicator}"

        refreshed = (
            await db.execute(select(IOCWatchlistEntry).where(IOCWatchlistEntry.indicator == indicator))
        ).scalar_one()
        assert refreshed.match_count >= 1
        assert refreshed.last_matched_at is not None
