"""Pytest fixtures."""

import os

# Force test DB before any app imports so engine and Settings use this URL (overrides .env).
os.environ["DATABASE_URL"] = "sqlite:///./pytest_soc_platform.db"

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


def pytest_configure(config):
    """Ensure all model tables exist before any test runs (lifespan may not run before DB access)."""
    import asyncio

    import app.models  # noqa: F401 — register metadata

    from app.database import Base, engine

    async def _setup_schema() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(lambda sync_conn: Base.metadata.drop_all(sync_conn, checkfirst=True))
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_setup_schema())


@pytest.fixture(autouse=True)
def _clear_rate_limit_buckets() -> None:
    """Avoid cross-test 429s: all tests share 127.0.0.1 and the default rate tier."""
    import asyncio

    from sqlalchemy import delete

    from app.database import SessionLocal
    from app.models import RateLimitBucket, RateLimitViolation

    async def _run() -> None:
        async with SessionLocal() as db:
            await db.execute(delete(RateLimitBucket))
            await db.execute(delete(RateLimitViolation))
            await db.commit()

    asyncio.run(_run())


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac
