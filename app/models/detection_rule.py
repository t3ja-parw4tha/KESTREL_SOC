"""Detection rule model for SIGMA/custom rule management."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON
from sqlalchemy.sql import func

from app.database import Base


class DetectionRule(Base):
    """User-managed detection rules (SIGMA or custom conditions)."""

    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False, unique=True, index=True)
    rule_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # sigma | custom
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="Medium")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    sigma_yaml: Mapped[str | None] = mapped_column(Text, nullable=True)
    conditions: Mapped[list | dict | None] = mapped_column(JSON, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
