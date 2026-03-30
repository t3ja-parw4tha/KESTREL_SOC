"""Case management model for SOC workflows."""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func
from sqlalchemy.types import JSON

from app.database import Base


class CaseSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CaseStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CaseRecord(Base):
    """Persistent investigation case with linked alerts/incidents and SLA context."""

    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    owner: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    severity: Mapped[CaseSeverity] = mapped_column(
        Enum(CaseSeverity), nullable=False, default=CaseSeverity.MEDIUM, index=True
    )
    status: Mapped[CaseStatus] = mapped_column(
        Enum(CaseStatus), nullable=False, default=CaseStatus.OPEN, index=True
    )

    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    linked_alert_ids: Mapped[list | dict] = mapped_column(JSON, nullable=False, default=list)
    linked_incident_ids: Mapped[list | dict] = mapped_column(JSON, nullable=False, default=list)

    closure_reason: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    closure_notes: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
