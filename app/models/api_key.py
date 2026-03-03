"""API key model for programmatic access."""

from datetime import datetime

from sqlalchemy import Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database import Base


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    permissions: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array of permission strings
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    # Grace period: old key hash stored here when rotating, valid until grace_expires_at
    superseded_by_id: Mapped[int] = mapped_column(Integer, nullable=True)
    grace_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
