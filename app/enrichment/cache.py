"""SQLite-based enrichment cache using SQLAlchemy."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


class EnrichmentCache(Base):
    __tablename__ = "enrichment_cache"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    indicator: Mapped[str] = mapped_column(index=True)
    indicator_type: Mapped[str] = mapped_column(index=True)
    source: Mapped[str] = mapped_column(index=True)
    result_json: Mapped[str] = mapped_column()
    cached_at: Mapped[datetime] = mapped_column()
    expires_at: Mapped[datetime] = mapped_column(index=True)


def _get_engine():
    settings = get_settings()
    data_dir = Path(settings.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "enrichment_cache.db"
    url = f"sqlite:///{db_path}"
    engine = create_engine(url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return engine


_engine = None
_SessionLocal = None


@contextmanager
def _session():
    global _engine, _SessionLocal
    if _engine is None:
        _engine = _get_engine()
        _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    session = _SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def is_expired(cached_at: datetime, ttl_hours: int = 24) -> bool:
    """Return True if the cached entry has expired."""
    if cached_at.tzinfo is None:
        cached_at = cached_at.replace(tzinfo=timezone.utc)
    expiry = cached_at + timedelta(hours=ttl_hours)
    return datetime.now(timezone.utc) >= expiry


def get(indicator: str, source: str, ttl_hours: int = 24) -> dict | None:
    """Return cached result if present and not expired, else None."""
    import json

    with _session() as session:
        stmt = select(EnrichmentCache).where(
            EnrichmentCache.indicator == indicator,
            EnrichmentCache.source == source,
        )
        row = session.execute(stmt).scalar_one_or_none()
        if row is None:
            return None
        if is_expired(row.cached_at, ttl_hours):
            session.delete(row)
            session.commit()
            return None
        try:
            return json.loads(row.result_json)
        except Exception:
            return None


def set(
    indicator: str,
    indicator_type: str,
    source: str,
    result: dict,
    ttl_hours: int = 24,
) -> None:
    """Store result in cache with expiry."""
    import json

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=ttl_hours)
    result_json = json.dumps(result)
    with _session() as session:
        stmt = select(EnrichmentCache).where(
            EnrichmentCache.indicator == indicator,
            EnrichmentCache.source == source,
        )
        existing = session.execute(stmt).scalar_one_or_none()
        if existing:
            existing.result_json = result_json
            existing.cached_at = now
            existing.expires_at = expires_at
        else:
            entry = EnrichmentCache(
                indicator=indicator,
                indicator_type=indicator_type,
                source=source,
                result_json=result_json,
                cached_at=now,
                expires_at=expires_at,
            )
            session.add(entry)
        session.commit()
