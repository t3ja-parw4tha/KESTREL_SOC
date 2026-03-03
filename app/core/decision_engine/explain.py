"""Explanation generation for decision engine output."""

from app.core.decision_engine.types import DecisionInput, DecisionOutput

_SEVERITY_DRIVER: dict[str, str] = {
    "Low": "Base risk 10 from Low severity",
    "Medium": "Base risk 30 from Medium severity",
    "High": "Base risk 60 from High severity",
    "Critical": "Base risk 80 from Critical severity",
}


def generate_explanation(
    input_data: DecisionInput,
    output: DecisionOutput,
) -> list[str]:
    """
    Generate 3-7 bullet points explaining the risk score.
    Always reference specific values, cover severity, asset, threat, history, correlation.
    """
    bullets: list[str] = []

    # Severity driver
    sev = input_data.alert.severity
    bullets.append(_SEVERITY_DRIVER.get(sev, f"Base risk from severity: {sev}"))

    # Asset context impact
    if input_data.asset:
        parts = []
        if input_data.asset.is_production:
            parts.append("production")
        if input_data.asset.is_internet_exposed:
            parts.append("internet-exposed")
        if input_data.asset.business_criticality == "high":
            parts.append("high business criticality")
        if parts:
            mod = min(30, len(parts) * 10)
            bullets.append(f"Risk +{mod}: Asset is {', '.join(parts)}")
    else:
        bullets.append("No asset context; risk unchanged for asset modifiers")

    # Threat intel impact
    if input_data.threat:
        if input_data.threat.has_active_exploit:
            cve = input_data.threat.cve_id or "unknown"
            cvss = input_data.threat.cvss_score or 0
            bullets.append(f"Risk +15: Active exploit for {cve} (CVSS {cvss})")
        elif input_data.threat.cvss_score is not None:
            if input_data.threat.cvss_score >= 9.0:
                bullets.append(f"Risk +10: CVSS {input_data.threat.cvss_score} >= 9.0")
            elif input_data.threat.cvss_score >= 7.0:
                bullets.append(f"Risk +5: CVSS {input_data.threat.cvss_score} >= 7.0")
        if input_data.threat.threat_actor:
            bullets.append(f"Threat actor attributed: {input_data.threat.threat_actor}")

    # History impact
    if input_data.history:
        if input_data.history.prior_false_positives > 0:
            n = input_data.history.prior_false_positives
            bullets.append(f"Risk -20: {n} prior false positive(s)")
        if input_data.history.similar_alerts_7d > 10:
            n = input_data.history.similar_alerts_7d
            bullets.append(f"Risk -10: {n} similar alerts in 7 days (potential noise)")

    # Correlation status
    if output.correlated_alert_ids:
        count = len(output.correlated_alert_ids)
        rule = output.correlation_rule_triggered or "unknown"
        bullets.append(f"Correlated with {count} alert(s) (rule: {rule})")
        if output.incident_group_id:
            short = output.incident_group_id[:16] + "..."
            bullets.append(f"Included in incident group: {short}")

    # Enrichment impact
    enrichment = input_data.alert.enrichment or {}
    vt = enrichment.get("virustotal") or {}
    if isinstance(vt, dict):
        mal = vt.get("malicious_percentage") or vt.get("malicious_percent")
        if mal is not None and mal > 50:
            bullets.append(f"Risk +15: VirusTotal malicious ratio {mal}%")
    abuseipdb = enrichment.get("abuseipdb") or {}
    if isinstance(abuseipdb, dict):
        ab = abuseipdb.get("abuse_score") or abuseipdb.get("score")
        if ab is not None and ab > 50:
            bullets.append(f"Risk +10: AbuseIPDB score {ab}")

    return bullets[:7]
