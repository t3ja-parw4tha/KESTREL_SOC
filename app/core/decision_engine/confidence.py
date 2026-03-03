"""Confidence calculation for the decision engine."""

from app.core.decision_engine.types import DecisionInput

_KNOWN_SOURCES = frozenset(
    {"Sentinel", "Suricata", "GuardDuty", "WindowsEventLog", "Defender", "Syslog"}
)


def calculate_confidence(input_data: DecisionInput) -> float:
    """
    Calculate confidence 0.0-1.0 from decision input.
    Start at 0.5, add for context, subtract for missing data.
    """
    confidence = 0.5

    if input_data.asset is not None:
        confidence += 0.2
    if input_data.threat is not None:
        confidence += 0.1
    if input_data.history is not None:
        confidence += 0.1
    if input_data.alert.enrichment and len(input_data.alert.enrichment) > 0:
        confidence += 0.1
    if not input_data.alert.raw or input_data.alert.raw == {}:
        confidence -= 0.2
    if (
        not input_data.alert.source
        or input_data.alert.source.lower() == "unknown"
    ):
        confidence -= 0.1

    return max(0.0, min(1.0, confidence))
