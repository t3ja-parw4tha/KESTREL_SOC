"""Tests for AI provider fallback and Azure OpenAI implementation."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ── Azure Provider ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_azure_returns_empty_when_not_configured():
    """call_azure returns '' without raising when credentials are missing."""
    from app.ai.providers.azure import call_azure

    with patch("app.ai.providers.azure.get_settings") as mock_settings:
        s = MagicMock()
        s.azure_openai_endpoint = ""
        s.azure_openai_api_key.get_secret_value.return_value = ""
        s.azure_openai_deployment = ""
        mock_settings.return_value = s

        result = await call_azure("test prompt", "test system")

    assert result == ""


@pytest.mark.asyncio
async def test_azure_returns_empty_when_deployment_missing():
    """call_azure returns '' if endpoint/key set but deployment is empty."""
    from app.ai.providers.azure import call_azure

    with patch("app.ai.providers.azure.get_settings") as mock_settings:
        s = MagicMock()
        s.azure_openai_endpoint = "https://example.openai.azure.com/"
        s.azure_openai_api_key.get_secret_value.return_value = "key123"
        s.azure_openai_deployment = ""  # Missing deployment
        mock_settings.return_value = s

        result = await call_azure("test prompt", "test system")

    assert result == ""


@pytest.mark.asyncio
async def test_azure_calls_openai_client_when_configured():
    """call_azure instantiates AsyncAzureOpenAI and calls chat.completions.create."""
    from app.ai.providers.azure import call_azure

    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "AI triage result"

    mock_client = AsyncMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

    with patch("app.ai.providers.azure.get_settings") as mock_settings, \
         patch("app.ai.providers.azure.AsyncAzureOpenAI", return_value=mock_client) as MockAzure:

        s = MagicMock()
        s.azure_openai_endpoint = "https://example.openai.azure.com/"
        s.azure_openai_api_key.get_secret_value.return_value = "key123"
        s.azure_openai_deployment = "gpt-4o"
        mock_settings.return_value = s

        result = await call_azure("my prompt", "my system")

    MockAzure.assert_called_once_with(
        api_key="key123",
        azure_endpoint="https://example.openai.azure.com/",
        api_version="2024-02-01",
    )
    mock_client.chat.completions.create.assert_called_once()
    call_kwargs = mock_client.chat.completions.create.call_args
    assert call_kwargs.kwargs["model"] == "gpt-4o"
    messages = call_kwargs.kwargs["messages"]
    assert any(m["role"] == "system" and m["content"] == "my system" for m in messages)
    assert any(m["role"] == "user" and m["content"] == "my prompt" for m in messages)
    assert result == "AI triage result"


@pytest.mark.asyncio
async def test_azure_propagates_exception():
    """call_azure re-raises exceptions from the OpenAI client."""
    from app.ai.providers.azure import call_azure

    mock_client = AsyncMock()
    mock_client.chat.completions.create = AsyncMock(side_effect=RuntimeError("API error"))

    with patch("app.ai.providers.azure.get_settings") as mock_settings, \
         patch("app.ai.providers.azure.AsyncAzureOpenAI", return_value=mock_client):

        s = MagicMock()
        s.azure_openai_endpoint = "https://example.openai.azure.com/"
        s.azure_openai_api_key.get_secret_value.return_value = "key123"
        s.azure_openai_deployment = "gpt-4o"
        mock_settings.return_value = s

        with pytest.raises(RuntimeError, match="API error"):
            await call_azure("prompt", "system")


@pytest.mark.asyncio
async def test_azure_handles_none_content():
    """call_azure returns '' when response content is None."""
    from app.ai.providers.azure import call_azure

    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = None

    mock_client = AsyncMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

    with patch("app.ai.providers.azure.get_settings") as mock_settings, \
         patch("app.ai.providers.azure.AsyncAzureOpenAI", return_value=mock_client):

        s = MagicMock()
        s.azure_openai_endpoint = "https://example.openai.azure.com/"
        s.azure_openai_api_key.get_secret_value.return_value = "key123"
        s.azure_openai_deployment = "gpt-4o"
        mock_settings.return_value = s

        result = await call_azure("prompt", "system")

    assert result == ""
