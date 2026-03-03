"""Threat intel feed manager: CISA KEV, URLhaus, and indicator matching."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.config import get_settings

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


class Base(DeclarativeBase):
    pass


class FeedEntry(Base):
    __tablename__ = "feed_entries"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    feed_name: Mapped[str] = mapped_column(index=True)
    indicator: Mapped[str] = mapped_column(index=True)
    indicator_type: Mapped[str] = mapped_column()
    raw_json: Mapped[str] = mapped_column()
    updated_at: Mapped[datetime] = mapped_column()


@dataclass
class FeedMatch:
    """Match from threat feed."""

    indicator: str
    feed_name: str
    raw: dict


def _get_engine():
    settings = get_settings()
    data_dir = Path(settings.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "enrichment_feeds.db"
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


class ThreatFeedManager:
    """Fetch and query threat intel feeds."""

    def fetch_cisa_kev(self) -> list[dict]:
        """Fetch CISA Known Exploited Vulnerabilities catalog."""
        try:
            with httpx.Client(timeout=60.0) as client:
                r = client.get(CISA_KEV_URL)
                r.raise_for_status()
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                return vulns if isinstance(vulns, list) else []
        except Exception:
            return []

    def fetch_urlhaus(self) -> list[dict]:
        """Fetch recent malicious URLs from URLhaus."""
        try:
            with httpx.Client(timeout=60.0) as client:
                r = client.get(URLHAUS_URL)
                r.raise_for_status()
                data = r.json()
                urls = data.get("urls", [])
                return urls if isinstance(urls, list) else []
        except Exception:
            return []

    def is_known_bad(self, indicator: str) -> FeedMatch | None:
        """Check if indicator is in cached feeds. Returns FeedMatch or None."""
        import json

        with _session() as session:
            stmt = select(FeedEntry).where(
                FeedEntry.indicator == indicator,
            )
            row = session.execute(stmt).scalar_one_or_none()
            if row is None:
                return None
            try:
                raw = json.loads(row.raw_json)
            except Exception:
                return None
            return FeedMatch(
                indicator=indicator,
                feed_name=row.feed_name,
                raw=raw,
            )

    def update_all_feeds(self) -> None:
        """Refresh all feeds and store in SQLite."""
        import json

        now = datetime.now(timezone.utc)
        entries = []

        cisa = self.fetch_cisa_kev()
        for v in cisa:
            cve = v.get("cveID") or v.get("cve_id")
            if cve:
                entries.append(
                    FeedEntry(
                        feed_name="cisa_kev",
                        indicator=cve,
                        indicator_type="cve",
                        raw_json=json.dumps(v),
                        updated_at=now,
                    )
                )

        urlhaus = self.fetch_urlhaus()
        for u in urlhaus:
            url = u.get("url") or u.get("urlhaus_url")
            if url:
                entries.append(
                    FeedEntry(
                        feed_name="urlhaus",
                        indicator=url,
                        indicator_type="url",
                        raw_json=json.dumps(u),
                        updated_at=now,
                    )
                )

        with _session() as session:
            session.execute(text("DELETE FROM feed_entries"))
            for e in entries:
                session.add(e)
            session.commit()
