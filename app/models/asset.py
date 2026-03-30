"""Asset / CMDB model."""

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, JSON
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database import Base


class Asset(Base):
    """
    Basic asset register (CMDB). Tracks hosts, servers, workstations, etc.
    Risk score is computed from recent alert activity or set manually.
    """
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(String(256), nullable=False, unique=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    asset_type: Mapped[str | None] = mapped_column(String(64), nullable=True)   # server, workstation, network, cloud
    os: Mapped[str | None] = mapped_column(String(128), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(256), nullable=True)
    department: Mapped[str | None] = mapped_column(String(256), nullable=True)
    criticality: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)  # low/medium/high/critical
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    tags: Mapped[list | None] = mapped_column(JSON, nullable=True, default=list)
    notes: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)  # 0.0-1.0 data quality confidence
    last_enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
