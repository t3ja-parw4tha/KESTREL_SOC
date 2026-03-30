"""False-positive scoring helpers for alert triage."""

from __future__ import annotations

from typing import Any


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def classify_false_positive_score(
    *,
    severity: str,
    duplicate_count: int,
    feed_match_count: int,
    vt_results: list[dict[str, Any]],
    abuse_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return false-positive score [0..100] with reasons and candidate flag."""
    score = 15
    reasons: list[str] = []

    sev = (severity or "").strip().lower()
    if sev == "low":
        score += 30
        reasons.append("Low severity increases FP likelihood")
    elif sev == "medium":
        score += 15
        reasons.append("Medium severity moderately increases FP likelihood")
    elif sev == "critical":
        score -= 30
        reasons.append("Critical severity reduces FP likelihood")
    elif sev == "high":
        score -= 20
        reasons.append("High severity reduces FP likelihood")

    if duplicate_count >= 5:
        score += 20
        reasons.append("High duplicate volume suggests recurring benign noise")
    elif duplicate_count >= 3:
        score += 10
        reasons.append("Repeated duplicate events suggest potential noise pattern")

    if feed_match_count > 0:
        score -= 25
        reasons.append("Threat feed matches reduce FP likelihood")
    else:
        score += 10
        reasons.append("No threat feed match increases FP likelihood")

    malicious_vt = max((_safe_int(v.get("malicious_count"), 0) for v in vt_results), default=0)
    suspicious_vt = max((_safe_int(v.get("suspicious_count"), 0) for v in vt_results), default=0)
    abuse_max = max((_safe_int(a.get("abuse_score"), 0) for a in abuse_results), default=0)

    if malicious_vt >= 3 or abuse_max >= 50:
        score -= 25
        reasons.append("External intel indicates likely malicious activity")
    elif malicious_vt == 0 and suspicious_vt == 0 and abuse_max <= 20:
        score += 15
        reasons.append("Intel checks are clean, increasing FP likelihood")

    score = max(0, min(100, score))
    candidate = score >= 85

    return {
        "score": score,
        "candidate": candidate,
        "label": "high_confidence_fp" if candidate else "needs_review",
        "reasons": reasons,
    }
