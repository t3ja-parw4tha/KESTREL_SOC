"""Decision model for alert decision engine results."""

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AlertDecision(Base):
    __tablename__ = "alert_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    explanation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    recommended_actions: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    mitre_techniques: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    correlated_alert_ids: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    incident_group_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    engine_version: Mapped[str] = mapped_column(String(16), nullable=False, default="v1")
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
