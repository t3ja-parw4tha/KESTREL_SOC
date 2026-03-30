"""Heuristic threat actor attribution from ATT&CK techniques."""

from __future__ import annotations

from typing import Any

ACTOR_TTPS: dict[str, set[str]] = {
    "APT29": {"T1078", "T1059", "T1027", "T1566.001", "T1110"},
    "APT28": {"T1059", "T1210", "T1046", "T1105", "T1110"},
    "Lazarus Group": {"T1486", "T1027", "T1071", "T1059", "T1562.001"},
    "FIN7": {"T1566.001", "T1204", "T1059", "T1071", "T1110"},
    "Scattered Spider": {"T1078", "T1110", "T1059", "T1210", "T1566.002"},
}


def _normalize_technique_id(v: str) -> str:
    return (v or "").strip().upper()


def attribute_actors(technique_ids: list[str]) -> list[dict[str, Any]]:
    """Return ranked actor candidates using overlap score."""
    observed = {_normalize_technique_id(t) for t in technique_ids if t}
    observed = {t for t in observed if t}
    if not observed:
        return []

    results: list[dict[str, Any]] = []
    for actor, tpps in ACTOR_TTPS.items():
        common = sorted(observed & tpps)
        if not common:
            continue
        coverage = len(common) / max(1, len(observed))
        confidence = min(0.99, round(0.45 + 0.5 * coverage, 2))
        results.append(
            {
                "actor": actor,
                "confidence": confidence,
                "matched_ttps": common,
                "match_count": len(common),
            }
        )

    results.sort(key=lambda x: (x["confidence"], x["match_count"]), reverse=True)
    return results
