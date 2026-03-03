"""Risk score calculation for the decision engine."""

from app.core.decision_engine.types import DecisionInput

_SEVERITY_BASE: dict[str, int] = {
    "Low": 10,
    "Medium": 30,
    "High": 60,
    "Critical": 80,
}


def calculate_risk_score(input_data: DecisionInput) -> int:
    """
    Calculate risk score 0-100 from decision input.
    Base score from severity, modifiers from asset, threat, history, enrichment.
    """
    score = _SEVERITY_BASE.get(input_data.alert.severity, 30)

    # Asset modifiers
    if input_data.asset:
        if input_data.asset.is_production:
            score += 10
        if input_data.asset.is_internet_exposed:
            score += 10
        if input_data.asset.business_criticality == "high":
            score += 10

    # Threat modifiers
    if input_data.threat:
        if input_data.threat.has_active_exploit:
            score += 15
        if input_data.threat.cvss_score is not None:
            if input_data.threat.cvss_score >= 9.0:
                score += 10
            elif input_data.threat.cvss_score >= 7.0:
                score += 5

    # History modifiers
    if input_data.history:
        if input_data.history.prior_false_positives > 0:
            score -= 20
        if input_data.history.similar_alerts_7d > 10:
            score -= 10

    # Enrichment modifier (from alert.enrichment)
    enrichment = input_data.alert.enrichment or {}
    vt = enrichment.get("virustotal") or {}
    if isinstance(vt, dict):
        malicious_pct = vt.get("malicious_percentage") or vt.get("malicious_percent")
        if malicious_pct is not None and malicious_pct > 50:
            score += 15
    abuseipdb = enrichment.get("abuseipdb") or {}
    if isinstance(abuseipdb, dict):
        ab_score = abuseipdb.get("abuse_score") or abuseipdb.get("score")
        if ab_score is not None and ab_score > 50:
            score += 10

    return max(0, min(100, score))
