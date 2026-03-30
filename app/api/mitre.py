"""MITRE ATT&CK API router."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.mitre.techniques import TECHNIQUES
from app.database import get_db
from app.models.alert import Alert
from app.security.rbac import require_permission

router = APIRouter(prefix="/mitre", tags=["mitre"])


TACTICS_LIST = [
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0003", "name": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation"},
    {"id": "TA0005", "name": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access"},
    {"id": "TA0007", "name": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement"},
    {"id": "TA0009", "name": "Collection"},
    {"id": "TA0010", "name": "Exfiltration"},
    {"id": "TA0011", "name": "Command and Control"},
    {"id": "TA0040", "name": "Impact"},
]

TACTIC_NAME_TO_ID = {t["name"]: t["id"] for t in TACTICS_LIST}


@router.get("/techniques")
async def list_techniques(
    _user: Annotated[dict, Depends(require_permission("mitre:read"))],
):
    """List MITRE ATT&CK Enterprise techniques with tactic IDs."""
    items = [
        {
            "id": tid,
            "name": entry["name"],
            "tactic_id": TACTIC_NAME_TO_ID.get(entry["tactic"], "TA0000"),
            "tactic_name": entry["tactic"],
            "description": entry["description"],
            "subtechniques": entry["subtechniques"],
            "platforms": entry["platforms"],
            "data_sources": entry["data_sources"],
        }
        for tid, entry in sorted(TECHNIQUES.items())
    ]
    return {"items": items}


@router.get("/coverage")
async def get_mitre_coverage(
    _user: Annotated[dict, Depends(require_permission("mitre:read"))],
    db: AsyncSession = Depends(get_db),
):
    """Return MITRE coverage details and aggregated stats including live alert severity."""
    techniques_out: list[dict] = []
    for tid, technique_entry in TECHNIQUES.items():
        tactic_id = TACTIC_NAME_TO_ID.get(technique_entry["tactic"], "TA0000")
        techniques_out.append(
            {
                "id": tid,
                "name": technique_entry["name"],
                "tactic_id": tactic_id,
                "tactic_name": technique_entry["tactic"],
                "description": technique_entry["description"],
                "alert_count": 0,
            }
        )

    result = await db.execute(
        select(Alert.mitre_techniques, Alert.severity, Alert.risk_score)
        .where(Alert.mitre_techniques.is_not(None))
    )
    rows = result.all()

    technique_counts: dict[str, int] = {}
    # live_coverage: keyed by technique_id, carries alert_count, max_severity, max_risk_score
    live_coverage: dict[str, dict[str, Any]] = {}
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    for row in rows:
        mt = row.mitre_techniques
        items: list = []
        if isinstance(mt, list):
            items = mt
        elif isinstance(mt, dict) and "items" in mt:
            items = mt.get("items") or []

        row_sev = str(
            row.severity.value if hasattr(row.severity, "value") else (row.severity or "low")
        )
        row_risk = float(row.risk_score or 0)

        for t in items:
            if not isinstance(t, dict):
                continue
            tech_id = t.get("technique_id") or t.get("id") or ""
            if not tech_id or not isinstance(tech_id, str):
                continue
            technique_counts[tech_id] = technique_counts.get(tech_id, 0) + 1
            if tech_id not in live_coverage:
                live_coverage[tech_id] = {
                    "technique_id": tech_id,
                    "technique_name": t.get("technique_name") or t.get("name") or tech_id,
                    "tactic": t.get("tactic") or t.get("phase") or "",
                    "alert_count": 0,
                    "max_severity": "low",
                    "max_risk_score": 0,
                }
            cov_entry = live_coverage[tech_id]
            cov_entry["alert_count"] += 1
            if sev_order.get(row_sev, 0) > sev_order.get(cov_entry["max_severity"], 0):
                cov_entry["max_severity"] = row_sev
            if row_risk > cov_entry["max_risk_score"]:
                cov_entry["max_risk_score"] = row_risk

    for t in techniques_out:
        t["alert_count"] = technique_counts.get(t["id"], 0)

    tactic_technique_map: dict[str, list[str]] = {t["id"]: [] for t in TACTICS_LIST}
    for t in techniques_out:
        if t["tactic_id"] in tactic_technique_map:
            tactic_technique_map[t["tactic_id"]].append(t["id"])

    tactics_out = [
        {
            "id": t["id"],
            "name": t["name"],
            "technique_ids": tactic_technique_map[t["id"]],
        }
        for t in TACTICS_LIST
    ]

    detected = [t for t in techniques_out if t["alert_count"] > 0]

    coverage_pct = round(len(detected) / len(TECHNIQUES) * 100, 1) if TECHNIQUES else 0.0
    tactics_covered_ids = {t["tactic_id"] for t in detected}
    tactics_covered_names = [t["name"] for t in TACTICS_LIST if t["id"] in tactics_covered_ids]
    techniques_detected_ids = [t["id"] for t in techniques_out if technique_counts.get(t["id"], 0) > 0]

    summary = {
        "total_techniques": len(TECHNIQUES),
        "techniques_detected": len(detected),
        "tactics_covered": len(tactics_covered_ids),
        "coverage_percentage": coverage_pct,
    }

    return {
        "tactics": tactics_out,
        "techniques": techniques_out,
        "summary": summary,
        "techniques_detected": techniques_detected_ids,
        "tactics_covered": tactics_covered_names,
        "coverage_percentage": coverage_pct,
        "alerts_by_technique": technique_counts,
        # Live coverage list for frontend overlay (P6-6)
        "coverage": list(live_coverage.values()),
        "total_techniques": len(live_coverage),
    }
