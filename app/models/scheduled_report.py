"""Scheduled report delivery model."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON
from sqlalchemy.sql import func

from app.database import Base


class ScheduledReport(Base):
    """Report delivery schedule with cadence and recipients."""

    __tablename__ = "scheduled_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    framework: Mapped[str] = mapped_column(String(32), nullable=False)
    cadence: Mapped[str] = mapped_column(String(16), nullable=False)  # daily | weekly
    recipients: Mapped[list | dict] = mapped_column(JSON, nullable=False, default=list)
    delivery_format: Mapped[str] = mapped_column(String(16), nullable=False, default="pdf")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    delivery_receipts: Mapped[list | None] = mapped_column(JSON, nullable=True, default=list)
    last_checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)
