"""AI prompts."""


def build_triage_prompt(alert_dict: dict) -> tuple[str, str]:
    """Build system and user prompt for alert triage."""
    system = (
        "You are a senior SOC analyst. Analyze security alerts "
        "and respond in JSON only. No markdown, no explanation. "
        "Return exactly this structure: "
        '{"summary": "...", "key_facts": {"k": "v"}, '
        '"affected": {"asset": "...", "user": "..."}, '
        '"evidence": {"indicators": []}, '
        '"remediation": {"actions": []}, '
        '"next_steps": {"recommendations": []}}'
    )
    user = (
        f"Analyze this security alert and provide triage:\n"
        f"{alert_dict}"
    )
    return system, user
