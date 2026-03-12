"""Anthropic (Claude) provider for AI triage."""

import logging

from app.config import get_settings

logger = logging.getLogger(__name__)


async def call_anthropic(prompt: str, system: str) -> str:
    """Call Anthropic Messages API and return response text."""
    settings = get_settings()
    api_key = settings.anthropic_api_key.get_secret_value()
    if not api_key:
        logger.debug("Anthropic API key not set")
        return ""

    try:
        from anthropic import AsyncAnthropic
    except ImportError:
        logger.warning("anthropic package not installed")
        return ""

    client = AsyncAnthropic(api_key=api_key)
    try:
        message = await client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        if message.content and len(message.content) > 0:
            block = message.content[0]
            if hasattr(block, "text"):
                return block.text
        return ""
    except Exception as e:
        logger.warning("Anthropic API error: %s", e)
        raise
