"""AI API router."""

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from app.ai.client import run_ai_triage
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Alert
from app.security.rbac import require_permission

router = APIRouter(prefix="/ai", tags=["ai"])

CACHE_TTL_HOURS = 24


class SummarizeRequest(BaseModel):
    alert_id: str


class SummarizeResponse(BaseModel):
    alert_id: str
    ai_summary: str | None
    ai_key_facts: dict | None
    ai_affected: dict | None
    ai_evidence: dict | None
    ai_remediation: dict | None
    ai_next_steps: dict | None
    cached: bool = False


def _stub_ai_summary(alert: Alert) -> tuple[str, dict, dict, dict, dict, dict]:
    """
    Placeholder for AI provider call. Replace with real LLM call when provider is wired.
    """
    summary = f"Summary for alert: {alert.title} (severity {alert.severity})."
    key_facts = {"severity": str(alert.severity), "source": alert.source, "category": alert.category}
    affected = {"asset_id": alert.asset_id, "user_id": alert.user_id}
    evidence = {"raw_preview": str(alert.raw or "")[:200]}
    remediation = {"actions": ["Review alert details", "Check correlated alerts"]}
    next_steps = {"recommendations": ["Triage", "Enrich IOCs"]}
    return summary, key_facts, affected, evidence, remediation, next_steps


@router.post("/analyze")
async def analyze_alert(
    _user: Annotated[dict, Depends(require_permission("ai:generate"))],
):
    """Request AI analysis (stub)."""
    return {"status": "ok"}


@router.post("/summarize", response_model=SummarizeResponse)
async def summarize_alert(
    body: SummarizeRequest,
    _user: Annotated[dict, Depends(require_permission("ai:generate"))],
    db: AsyncSession = Depends(get_db),
) -> SummarizeResponse:
    """
    Generate or return cached AI summary for an alert.
    Skips generation if summary exists and was updated within the last 24 hours.
    """
    r = await db.execute(select(Alert).where(Alert.id == body.alert_id))
    alert = r.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    now = datetime.now(timezone.utc)
    cache_cutoff = now - timedelta(hours=CACHE_TTL_HOURS)
    updated_at = alert.updated_at
    if updated_at is not None and updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=timezone.utc)
    is_stub = bool(alert.ai_summary and alert.ai_summary.startswith("Summary for alert:"))
    if alert.ai_summary and not is_stub and updated_at and updated_at >= cache_cutoff:
        return SummarizeResponse(
            alert_id=alert.id,
            ai_summary=alert.ai_summary,
            ai_key_facts=alert.ai_key_facts,
            ai_affected=alert.ai_affected,
            ai_evidence=alert.ai_evidence,
            ai_remediation=alert.ai_remediation,
            ai_next_steps=alert.ai_next_steps,
            cached=True,
        )

    alert_dict = {
        "id": alert.id,
        "title": alert.title,
        "severity": str(alert.severity),
        "source": alert.source,
        "category": alert.category,
        "description": getattr(alert, "description", None),
        "asset_id": alert.asset_id,
        "user_id": alert.user_id,
        "source_ip": alert.source_ip,
        "mitre_techniques": alert.mitre_techniques,
        "risk_score": alert.risk_score,
    }
    result = await run_ai_triage(alert_dict)
    if result:
        import json as _json
        now_ts = datetime.now(timezone.utc)
        await db.execute(
            text(
                "UPDATE alerts SET ai_summary=:summary, ai_key_facts=:key_facts,"
                " ai_affected=:affected, ai_evidence=:evidence,"
                " ai_remediation=:remediation, ai_next_steps=:next_steps,"
                " updated_at=:updated_at WHERE id=:id"
            ),
            {
                "summary": result.get("summary", ""),
                "key_facts": _json.dumps(result.get("key_facts") or {}),
                "affected": _json.dumps(result.get("affected") or {}),
                "evidence": _json.dumps(result.get("evidence") or {}),
                "remediation": _json.dumps(result.get("remediation") or {}),
                "next_steps": _json.dumps(result.get("next_steps") or {}),
                "updated_at": now_ts.isoformat(),
                "id": alert.id,
            },
        )
        await db.commit()
        return SummarizeResponse(
            alert_id=alert.id,
            ai_summary=alert.ai_summary,
            ai_key_facts=alert.ai_key_facts,
            ai_affected=alert.ai_affected,
            ai_evidence=alert.ai_evidence,
            ai_remediation=alert.ai_remediation,
            ai_next_steps=alert.ai_next_steps,
            cached=False,
        )
    else:
        # No AI key configured — save stub to DB so the UI shows the rule-based
        # summary rather than looping on "Queuing analysis…" indefinitely.
        # The frontend detects stubs (starts with "Summary for alert:") and shows
        # a banner prompting the user to configure an AI provider.
        import json as _json
        stub = _stub_ai_summary(alert)
        now_ts = datetime.now(timezone.utc)
        await db.execute(
            text(
                "UPDATE alerts SET ai_summary=:summary, ai_key_facts=:key_facts,"
                " ai_affected=:affected, ai_evidence=:evidence,"
                " ai_remediation=:remediation, ai_next_steps=:next_steps,"
                " updated_at=:updated_at WHERE id=:id"
            ),
            {
                "summary": stub[0],
                "key_facts": _json.dumps(stub[1]),
                "affected": _json.dumps(stub[2]),
                "evidence": _json.dumps(stub[3]),
                "remediation": _json.dumps(stub[4]),
                "next_steps": _json.dumps(stub[5]),
                "updated_at": now_ts.isoformat(),
                "id": alert.id,
            },
        )
        await db.commit()
        return SummarizeResponse(
            alert_id=alert.id,
            ai_summary=stub[0],
            ai_key_facts=stub[1],
            ai_affected=stub[2],
            ai_evidence=stub[3],
            ai_remediation=stub[4],
            ai_next_steps=stub[5],
            cached=False,
        )
