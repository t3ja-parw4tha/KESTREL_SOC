"""Threat hunting workspace models (P5-6)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func
from sqlalchemy.types import JSON

from app.database import Base


class HuntQueryRecord(Base):
    """Saved threat hunt query with workspace scoping."""

    __tablename__ = "hunt_queries"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    query: Mapped[str] = mapped_column(Text, nullable=False)
    query_type: Mapped[str] = mapped_column(String(16), nullable=False, default="kql")
    created_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, default="default")
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, default="default")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(32), nullable=False, default="saved")
    results_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    notebook_timeline: Mapped[list | dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class HuntResultRecord(Base):
    """Persisted result rows per hunt run."""

    __tablename__ = "hunt_results"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    hunt_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    alert_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    host: Mapped[str | None] = mapped_column(String(256), nullable=True)
    event_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, default="default")
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, default="default")
