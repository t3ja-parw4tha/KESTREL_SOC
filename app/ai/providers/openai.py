"""OpenAI provider."""

import httpx
from app.config import get_settings


async def call_openai(prompt: str, system: str) -> str:
    """Call OpenAI chat completions API and return response text."""
    settings = get_settings()
    api_key = settings.openai_api_key.get_secret_value()
    if not api_key:
        return ""

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": 1000,
                "temperature": 0.2,
            },
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]
