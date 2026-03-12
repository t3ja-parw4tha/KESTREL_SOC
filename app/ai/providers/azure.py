"""Azure OpenAI provider for AI triage."""

import logging

try:
    from openai import AsyncAzureOpenAI
except ImportError:  # openai package not installed
    AsyncAzureOpenAI = None  # type: ignore[assignment,misc]

from app.config import get_settings

logger = logging.getLogger(__name__)


async def call_azure(prompt: str, system: str) -> str:
    """Call Azure OpenAI endpoint. Returns empty string if not configured."""
    settings = get_settings()
    endpoint = (settings.azure_openai_endpoint or "").strip()
    api_key = (settings.azure_openai_api_key.get_secret_value() or "").strip()
    deployment = (settings.azure_openai_deployment or "").strip()

    if not endpoint or not api_key or not deployment:
        logger.debug(
            "Azure OpenAI not fully configured (endpoint=%s, key_set=%s, deployment=%s)",
            bool(endpoint),
            bool(api_key),
            bool(deployment),
        )
        return ""

    try:
        client = AsyncAzureOpenAI(
            api_key=api_key,
            azure_endpoint=endpoint,
            api_version="2024-02-01",
        )
        response = await client.chat.completions.create(
            model=deployment,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            max_tokens=1000,
            temperature=0.2,
        )
        return response.choices[0].message.content or ""
    except Exception:
        logger.exception("Azure OpenAI request failed")
        raise
