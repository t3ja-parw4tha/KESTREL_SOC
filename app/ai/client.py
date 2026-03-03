"""AI client."""

import json
import logging

from app.ai.providers.openai import call_openai
from app.ai.prompts import build_triage_prompt

logger = logging.getLogger(__name__)


async def run_ai_triage(alert_dict: dict) -> dict:
    """Run AI triage on an alert dict. Returns structured result."""
    system, prompt = build_triage_prompt(alert_dict)
    try:
        raw = await call_openai(prompt, system)
        if not raw:
            return {}
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[-1].rsplit("```", 1)[0]
        return json.loads(clean)
    except Exception as e:
        logger.warning("AI triage failed: %s", e)
        return {}
