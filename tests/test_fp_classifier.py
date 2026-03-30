"""Tests for AI false-positive classifier scoring (P3-3)."""

import uuid

import pytest
from sqlalchemy import select

from app.ai.fp_classifier import classify_false_positive_score
from app.api.ingest import _enqueue_enrichment
from app.database import SessionLocal
from app.enrichment import EnrichmentResult
from app.enrichment.ioc_extractor import IOCResults
from app.models import Alert
from app.models.alert import AlertSeverity, AlertStatus


def test_fp_classifier_high_score_for_likely_noise():
    result = classify_false_positive_score(
        severity="Low",
        duplicate_count=6,
        feed_match_count=0,
        vt_results=[{"malicious_count": 0, "suspicious_count": 0}],
        abuse_results=[{"abuse_score": 0}],
    )

    assert result["score"] >= 85
    assert result["candidate"] is True


def test_fp_classifier_low_score_for_malicious_signals():
    result = classify_false_positive_score(
        severity="Critical",
        duplicate_count=1,
        feed_match_count=2,
        vt_results=[{"malicious_count": 12, "suspicious_count": 0}],
        abuse_results=[{"abuse_score": 95}],
    )

    assert result["score"] <= 40
    assert result["candidate"] is False


@pytest.mark.asyncio
async def test_enqueue_enrichment_writes_fp_classifier(monkeypatch):
    alert_id = str(uuid.uuid4())
    async with SessionLocal() as db:
        db.add(
            Alert(
                id=alert_id,
                title="Routine DNS noise",
                source="unit-test",
                severity=AlertSeverity.LOW,
                category="network",
                status=AlertStatus.OPEN,
                raw={"message": "query bad-domain.test from 198.51.100.10"},
                enrichment={"duplicate_count": 6},
            )
        )
        await db.commit()

    async def _fake_enrich_alert(_self, _alert: Alert):
        return EnrichmentResult(
            iocs_found=IOCResults(
                ips=["198.51.100.10"],
                domains=["bad-domain.test"],
                hashes=[],
                cves=[],
            ),
            vt_results=[],
            abuse_results=[],
            feed_matches=[],
            risk_modifier=0,
            summary="test",
        )

    monkeypatch.setattr("app.enrichment.EnrichmentOrchestrator.enrich_alert", _fake_enrich_alert)

    await _enqueue_enrichment([alert_id])

    async with SessionLocal() as db:
        alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalar_one()

    fp = (alert.enrichment or {}).get("fp_classifier")
    assert isinstance(fp, dict)
    assert fp.get("score") is not None
    assert fp.get("candidate") in (True, False)
