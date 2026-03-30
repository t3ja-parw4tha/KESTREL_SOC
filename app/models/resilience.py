"""Resilience, governance, and control-plane models (P5-5,7-12)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func
from sqlalchemy.types import JSON

from app.database import Base


class DetectionQARun(Base):
    __tablename__ = "detection_qa_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    dataset_name: Mapped[str] = mapped_column(String(128), nullable=False)
    replay_window_days: Mapped[int] = mapped_column(Integer, nullable=False, default=7)
    sample_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    matched_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    precision_pct: Mapped[float] = mapped_column(nullable=False, default=0)
    recall_pct: Mapped[float] = mapped_column(nullable=False, default=0)
    gate_passed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    notes: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class SecretRotationPolicy(Base):
    __tablename__ = "secret_rotation_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    secret_name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="env")
    rotation_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    policy_meta: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class TenantWorkspace(Base):
    __tablename__ = "tenant_workspaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RunbookApprovalRequest(Base):
    __tablename__ = "runbook_approval_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    playbook_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    alert_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="high")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    requested_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    executed_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    action_summary: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    audit_trail: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RestoreDrillRecord(Base):
    __tablename__ = "restore_drills"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="scheduled", index=True)
    rpo_target_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    rto_target_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=120)
    rpo_actual_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rto_actual_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AIGovernanceFeedback(Base):
    __tablename__ = "ai_governance_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    analyst: Mapped[str | None] = mapped_column(String(256), nullable=True)
    rating: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    hallucination_flag: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    confidence_score: Mapped[float | None] = mapped_column(nullable=True)
    comments: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
