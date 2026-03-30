"""Tests for semantic alert clustering (P3-4)."""

import uuid

import pytest

from app.ai.alert_clustering import assign_alert_cluster
from app.database import SessionLocal
from app.models import Alert
from app.models.alert import AlertSeverity, AlertStatus


@pytest.mark.asyncio
async def test_assign_alert_cluster_groups_similar_alerts():
    async with SessionLocal() as db:
        existing = Alert(
            id=str(uuid.uuid4()),
            title="Multiple failed admin logins from 203.0.113.10",
            source="okta",
            severity=AlertSeverity.HIGH,
            category="identity",
            status=AlertStatus.OPEN,
            source_ip="203.0.113.10",
        )
        db.add(existing)
        await db.commit()

        new_alert = Alert(
            id=str(uuid.uuid4()),
            title="Repeated failed admin login attempts from 203.0.113.10",
            source="okta",
            severity=AlertSeverity.HIGH,
            category="identity",
            status=AlertStatus.OPEN,
            source_ip="203.0.113.10",
            enrichment={},
        )

        cluster = await assign_alert_cluster(db, new_alert)

        assert cluster is not None
        assert cluster["reason"] == "semantic_similarity"
        assert cluster["cluster_id"]
        assert new_alert.incident_group_id == cluster["cluster_id"]


@pytest.mark.asyncio
async def test_assign_alert_cluster_skips_dissimilar_alerts():
    async with SessionLocal() as db:
        existing = Alert(
            id=str(uuid.uuid4()),
            title="Ransomware encryption behavior detected on endpoint",
            source="crowdstrike",
            severity=AlertSeverity.CRITICAL,
            category="endpoint",
            status=AlertStatus.OPEN,
        )
        db.add(existing)
        await db.commit()

        new_alert = Alert(
            id=str(uuid.uuid4()),
            title="Suspicious outbound DNS query volume spike",
            source="crowdstrike",
            severity=AlertSeverity.MEDIUM,
            category="network",
            status=AlertStatus.OPEN,
            enrichment={},
        )

        cluster = await assign_alert_cluster(db, new_alert)

        assert cluster is None
        assert new_alert.incident_group_id is None
