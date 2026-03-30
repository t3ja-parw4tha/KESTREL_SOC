"""Immutable compliance export artifact metadata."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database import Base


class ComplianceReportArtifact(Base):
    """Stores immutable report export bundle identity and verification metadata."""

    __tablename__ = "compliance_report_artifacts"

    report_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    framework: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    period_days: Mapped[int] = mapped_column(Integer, nullable=False)
    report_checksum: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    artifact_name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
