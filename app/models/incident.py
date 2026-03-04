"""Incident model for correlated alert groups."""

import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, Integer, String
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_ids: Mapped[dict] = mapped_column(JSON, nullable=False)
    highest_severity: Mapped[str] = mapped_column(String(32), nullable=False)
    total_risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    asset_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    user_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    mitre_techniques: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus), nullable=False, default=IncidentStatus.OPEN
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False)
