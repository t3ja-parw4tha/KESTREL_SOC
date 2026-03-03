"""Audit log for access and security events."""

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database import Base


class AuditLog(Base):
    """SOC audit log for alert actions, analyst events, and request audit."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    analyst: Mapped[str | None] = mapped_column(String(256), nullable=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    request_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
