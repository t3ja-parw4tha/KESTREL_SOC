"""MITRE ATT&CK API router."""

from typing import Annotated

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
    """Return MITRE coverage details and aggregated stats."""
    techniques_out: list[dict] = []
    for tid, entry in TECHNIQUES.items():
        tactic_id = TACTIC_NAME_TO_ID.get(entry["tactic"], "TA0000")
        techniques_out.append(
            {
                "id": tid,
                "name": entry["name"],
                "tactic_id": tactic_id,
                "tactic_name": entry["tactic"],
                "description": entry["description"],
                "alert_count": 0,
            }
        )

    result = await db.execute(
        select(Alert.mitre_techniques).where(Alert.mitre_techniques.is_not(None))
    )
    rows = result.scalars().all()

    technique_counts: dict[str, int] = {}
    for row in rows:
        if isinstance(row, list):
            for t in row:
                if isinstance(t, dict):
                    tid = t.get("technique_id")
                    if tid:
                        technique_counts[tid] = technique_counts.get(tid, 0) + 1
        elif isinstance(row, dict) and "items" in row:
            for t in row.get("items") or []:
                if isinstance(t, dict):
                    tid = t.get("technique_id")
                    if tid:
                        technique_counts[tid] = technique_counts.get(tid, 0) + 1

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
    }
