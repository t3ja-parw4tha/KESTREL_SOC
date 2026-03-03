"""Initial migration: alerts, alert_decisions, incidents, audit_logs

Revision ID: 001
Revises:
Create Date: 2025-03-01

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Alerts table
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("assigned_to", sa.String(256), nullable=True),
        sa.Column("asset_id", sa.String(256), nullable=True),
        sa.Column("user_id", sa.String(256), nullable=True),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("dest_ip", sa.String(45), nullable=True),
        sa.Column("mitre_techniques", sa.JSON(), nullable=True),
        sa.Column("raw", sa.JSON(), nullable=True),
        sa.Column("ai_summary", sa.Text(), nullable=True),
        sa.Column("ai_key_facts", sa.JSON(), nullable=True),
        sa.Column("ai_affected", sa.JSON(), nullable=True),
        sa.Column("ai_evidence", sa.JSON(), nullable=True),
        sa.Column("ai_remediation", sa.JSON(), nullable=True),
        sa.Column("ai_next_steps", sa.JSON(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("risk_level", sa.String(32), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("incident_group_id", sa.String(36), nullable=True),
        sa.Column("correlated_alert_ids", sa.JSON(), nullable=True),
        sa.Column("enrichment", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_source", "alerts", ["source"])
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])
    op.create_index("ix_alerts_incident_group_id", "alerts", ["incident_group_id"])

    # Alert decisions table
    op.create_table(
        "alert_decisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("alert_id", sa.String(36), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("risk_level", sa.String(32), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("explanation", sa.JSON(), nullable=True),
        sa.Column("recommended_actions", sa.JSON(), nullable=True),
        sa.Column("mitre_techniques", sa.JSON(), nullable=True),
        sa.Column("correlated_alert_ids", sa.JSON(), nullable=True),
        sa.Column("incident_group_id", sa.String(36), nullable=True),
        sa.Column("engine_version", sa.String(16), nullable=False, server_default="v1"),
        sa.Column(
            "generated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_alert_decisions_alert_id", "alert_decisions", ["alert_id"])

    # Incidents table
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("alert_ids", sa.JSON(), nullable=False),
        sa.Column("highest_severity", sa.String(32), nullable=False),
        sa.Column("total_risk_score", sa.Integer(), nullable=True),
        sa.Column("asset_id", sa.String(256), nullable=True),
        sa.Column("user_id", sa.String(256), nullable=True),
        sa.Column("mitre_techniques", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
    )

    # Audit logs table (SOC-specific)
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("alert_id", sa.String(36), nullable=True),
        sa.Column("analyst", sa.String(256), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column("method", sa.String(16), nullable=True),
        sa.Column("path", sa.String(512), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("duration_ms", sa.Float(), nullable=True),
    )
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])
    op.create_index("ix_audit_logs_request_id", "audit_logs", ["request_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_request_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_timestamp", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_table("incidents")
    op.drop_index("ix_alert_decisions_alert_id", table_name="alert_decisions")
    op.drop_table("alert_decisions")
    op.drop_index("ix_alerts_incident_group_id", table_name="alerts")
    op.drop_index("ix_alerts_created_at", table_name="alerts")
    op.drop_index("ix_alerts_source", table_name="alerts")
    op.drop_index("ix_alerts_status", table_name="alerts")
    op.drop_index("ix_alerts_severity", table_name="alerts")
    op.drop_table("alerts")
