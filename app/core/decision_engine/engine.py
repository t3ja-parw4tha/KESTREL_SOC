"""Decision engine orchestration."""

from datetime import datetime, timezone

from app.core.decision_engine.confidence import calculate_confidence
from app.core.decision_engine.correlation import correlate_alerts
from app.observability.metrics import (
    DECISION_ENGINE_DURATION,
    DECISION_RISK_SCORES,
)
from app.core.decision_engine.explain import generate_explanation
from app.core.decision_engine.recommend import get_recommended_actions
from app.core.decision_engine.scorer import calculate_risk_score
from app.core.decision_engine.types import (
    DecisionInput,
    DecisionOutput,
    NormalizedAlert,
)
from app.core.mitre.mapping import get_mitre_techniques_for_alert

ENGINE_VERSION = "v1"


def _score_to_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def run_decision_engine(
    input_data: DecisionInput,
    recent_alerts: list[NormalizedAlert] | None = None,
) -> DecisionOutput:
    """
    Orchestrate scoring, correlation, confidence, explanation, and recommendations.
    Returns complete DecisionOutput.
    """
    with DECISION_ENGINE_DURATION.time():
        recent = recent_alerts or []

        # MITRE techniques from mapping (augment if alert has none)
        mitre = list(input_data.alert.mitre_techniques or [])
        if not mitre:
            mapped = get_mitre_techniques_for_alert(
                input_data.alert.category,
                input_data.alert.alert_type,
                input_data.alert.raw,
            )
            mitre = mapped

        # Correlation
        corr = correlate_alerts(input_data.alert, recent)
        correlated_ids = corr.correlated_alert_ids
        incident_group_id = corr.incident_group_id
        rule_triggered = corr.correlation_rule_triggered

        # Risk score
        risk_score = calculate_risk_score(input_data)
        DECISION_RISK_SCORES.observe(risk_score)
        risk_level = _score_to_level(risk_score)

        # Confidence
        confidence = calculate_confidence(input_data)

        # Recommended actions
        recommended = get_recommended_actions(input_data.alert)

        # Build output for explanation (need risk_score, correlated_ids, etc.)
        output = DecisionOutput(
            risk_score=risk_score,
            risk_level=risk_level,
            confidence=confidence,
            explanation=[],
            recommended_actions=recommended,
            mitre_techniques=mitre,
            correlated_alert_ids=correlated_ids,
            incident_group_id=incident_group_id,
            generated_at=datetime.now(timezone.utc),
            engine_version=ENGINE_VERSION,
            correlation_rule_triggered=rule_triggered,
        )

        # Generate explanation (uses both input and output)
        output.explanation = generate_explanation(input_data, output)

        return output
