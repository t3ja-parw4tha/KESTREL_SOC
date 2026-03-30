"""Persisted AI chat messages for analyst investigation context."""

from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database import Base


class AIChatMessage(Base):
    """Stores per-context chat turns between analyst and AI assistant."""

    __tablename__ = "ai_chat_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    context_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # alert | incident
    context_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False)  # user | assistant
    message: Mapped[str] = mapped_column(Text, nullable=False)
    analyst: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
