"""SQLAlchemy async engine, session factory, and get_db dependency."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

_settings = get_settings()
# SQLAlchemy async needs sqlite+aiosqlite for async SQLite
_database_url = _settings.database_url.get_secret_value()
if _database_url.startswith("sqlite"):
    _database_url = _database_url.replace("sqlite://", "sqlite+aiosqlite://", 1)

engine = create_async_engine(
    _database_url,
    echo=_settings.debug,
    pool_pre_ping=True,
)

SessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Declarative base for models."""

    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async database session."""
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
