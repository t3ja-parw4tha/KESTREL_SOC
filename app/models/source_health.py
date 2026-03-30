"""Per-source ingestion health and SLO tracking state."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SourceHealth(Base):
    __tablename__ = "source_health"

    source_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    source_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    source_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Last-run health markers
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Rolling SLO/error-budget window counters
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_successes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    window_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Throughput and lag
    events_received_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    alerts_ingested_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    processing_errors_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_ingest_lag_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Stale-feed alerting control (cooldown / auto-resolve)
    stale_alert_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    stale_alert_last_fired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
