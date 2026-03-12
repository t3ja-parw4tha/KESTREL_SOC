"""Automation Playbook model for SOAR engine."""

from datetime import datetime

from sqlalchemy import Integer, String, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database import Base


class Playbook(Base):
    """
    Playbooks contain automated rules to evaluate incoming alerts.
    If conditions match, actions are automatically executed.
    """
    __tablename__ = "playbooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(String(512), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    
    # E.g., 'alert_created', 'incident_created'
    trigger_type: Mapped[str] = mapped_column(String(64), nullable=False, default="alert_created")
    
    # JSON arrays of conditions and actions. We use Pydantic models in memory to validate them.
    conditions: Mapped[dict | list] = mapped_column(JSON, nullable=False)
    actions: Mapped[dict | list] = mapped_column(JSON, nullable=False)
    
    # Audit tracking
    created_by_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), onupdate=func.now())
