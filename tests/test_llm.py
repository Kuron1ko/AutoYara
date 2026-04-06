"""Unit tests for llm module."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestSyncLLMClient:
    """Tests for SyncLLMClient."""

    @patch("autoyara.llm.sync_client.OpenAI")
    def test_chat_returns_content(self, mock_openai):
        from autoyara.llm import SyncLLMClient

        mock_response = MagicMock()
        mock_response.choices[0].message.content = "Hello, World!"
        mock_openai.return_value.chat.completions.create.return_value = mock_response

        client = SyncLLMClient(api_key="test-key")
        result = client.chat([{"role": "user", "content": "Hi"}])

        assert result == "Hello, World!"
        mock_openai.return_value.chat.completions.create.assert_called_once_with(
            model="gpt-5",
            messages=[{"role": "user", "content": "Hi"}],
        )

    @patch("autoyara.llm.sync_client.OpenAI")
    def test_prompt_single_turn(self, mock_openai):
        from autoyara.llm import SyncLLMClient

        mock_response = MagicMock()
        mock_response.choices[0].message.content = "Response text"
        mock_openai.return_value.chat.completions.create.return_value = mock_response

        client = SyncLLMClient(api_key="test-key")
        result = client.prompt("What is this?")

        assert result == "Response text"
        mock_openai.return_value.chat.completions.create.assert_called_once_with(
            model="gpt-5",
            messages=[{"role": "user", "content": "What is this?"}],
        )

    @patch("autoyara.llm.sync_client.OpenAI")
    def test_chat_with_custom_model(self, mock_openai):
        from autoyara.llm import SyncLLMClient

        mock_response = MagicMock()
        mock_response.choices[0].message.content = "Custom model response"
        mock_openai.return_value.chat.completions.create.return_value = mock_response

        client = SyncLLMClient(api_key="test-key", model="gpt-4")
        client.chat([{"role": "user", "content": "Test"}])

        mock_openai.return_value.chat.completions.create.assert_called_once_with(
            model="gpt-4",
            messages=[{"role": "user", "content": "Test"}],
        )

    @patch("autoyara.llm.sync_client.OpenAI")
    def test_chat_with_empty_content(self, mock_openai):
        from autoyara.llm import SyncLLMClient

        mock_response = MagicMock()
        mock_response.choices[0].message.content = None
        mock_openai.return_value.chat.completions.create.return_value = mock_response

        client = SyncLLMClient(api_key="test-key")
        result = client.chat([{"role": "user", "content": "Test"}])

        assert result == ""

    @patch("autoyara.llm.sync_client.OpenAI")
    def test_context_manager_calls_close(self, mock_openai):
        from autoyara.llm import SyncLLMClient

        with SyncLLMClient(api_key="test-key") as client:
            assert isinstance(client, SyncLLMClient)

        mock_openai.return_value.close.assert_called_once()


class TestAsyncLLMClient:
    """Tests for AsyncLLMClient."""

    @patch("autoyara.llm.async_client.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_chat_returns_content(self, mock_openai):
        from autoyara.llm import AsyncLLMClient

        mock_response = MagicMock()
        mock_response.choices[0].message.content = "Async Hello!"
        mock_openai.return_value.chat.completions.create = AsyncMock(return_value=mock_response)

        client = AsyncLLMClient(api_key="test-key")
        result = await client.chat([{"role": "user", "content": "Hi"}])

        assert result == "Async Hello!"

    @patch("autoyara.llm.async_client.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_prompt_single_turn(self, mock_openai):
        from autoyara.llm import AsyncLLMClient

        mock_response = MagicMock()
        mock_response.choices[0].message.content = "Prompt response"
        mock_openai.return_value.chat.completions.create = AsyncMock(return_value=mock_response)

        client = AsyncLLMClient(api_key="test-key")
        result = await client.prompt("What is that?")

        assert result == "Prompt response"

    @patch("autoyara.llm.async_client.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_async_context_manager_calls_close(self, mock_openai):
        from autoyara.llm import AsyncLLMClient

        mock_openai.return_value.close = AsyncMock(return_value=None)

        async with AsyncLLMClient(api_key="test-key") as client:
            assert isinstance(client, AsyncLLMClient)

        mock_openai.return_value.close.assert_awaited_once()


class TestCreateFunctions:
    """Tests for factory functions."""

    @patch("autoyara.llm.sync_client.OpenAI")
    def test_create_sync_client(self, mock_openai):
        from autoyara.llm import SyncLLMClient, create_sync_client

        mock_response = MagicMock()
        mock_response.choices[0].message.content = "test"
        mock_openai.return_value.chat.completions.create.return_value = mock_response

        client = create_sync_client(api_key="my-key", model="gpt-4o")
        assert isinstance(client, SyncLLMClient)
        assert client.model == "gpt-4o"

    @patch("autoyara.llm.async_client.AsyncOpenAI")
    @pytest.mark.asyncio
    async def test_create_async_client(self, mock_openai):
        from autoyara.llm import AsyncLLMClient, create_async_client

        mock_response = MagicMock()
        mock_response.choices[0].message.content = "test"
        mock_openai.return_value.chat.completions.create = AsyncMock(return_value=mock_response)

        client = await create_async_client(api_key="my-key", model="gpt-4o")
        assert isinstance(client, AsyncLLMClient)
        assert client.model == "gpt-4o"
