"""AI client. Dispatches to configured provider (openai, anthropic, azure)."""

import json
import logging

from app.config import get_settings
from app.ai.prompts import build_triage_prompt

logger = logging.getLogger(__name__)


def _parse_triage_response(raw: str) -> dict:
    """Parse LLM response into triage JSON. Handles markdown code blocks."""
    if not raw or not raw.strip():
        return {}
    clean = raw.strip()
    if clean.startswith("```"):
        clean = clean.split("\n", 1)[-1].rsplit("```", 1)[0]
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        return {}


async def run_ai_triage(alert_dict: dict) -> dict:
    """Run AI triage on an alert dict. Returns structured result."""
    settings = get_settings()
    provider = settings.ai_provider
    system, prompt = build_triage_prompt(alert_dict)

    try:
        if provider == "openai":
            from app.ai.providers.openai import call_openai
            raw = await call_openai(prompt, system)
        elif provider == "anthropic":
            from app.ai.providers.anthropic import call_anthropic
            raw = await call_anthropic(prompt, system)
        elif provider == "azure":
            from app.ai.providers.azure import call_azure
            raw = await call_azure(prompt, system)
        else:
            logger.warning("Unknown AI provider %r, using OpenAI", provider)
            from app.ai.providers.openai import call_openai
            raw = await call_openai(prompt, system)

        return _parse_triage_response(raw) if raw else {}
    except Exception as e:
        logger.warning("AI triage failed (%s): %s", provider, e)
        return {}
