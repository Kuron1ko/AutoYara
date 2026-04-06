#!/usr/bin/env python
"""Test script for LLM module."""

import sys
from pathlib import Path

project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "src"))

from configs.config import get_openai_api_key  # noqa: E402

from autoyara.llm import SyncLLMClient  # noqa: E402


def test_sync_client():
    api_key = get_openai_api_key().strip()
    if not api_key:
        api_key = input("Enter OpenAI API Key: ").strip()
    if not api_key:
        print("API key is required.")
        return 1

    client = SyncLLMClient(api_key=api_key)

    print("\n=== Testing prompt (single-turn) ===")
    response = client.prompt("Say 'Hello, AutoYara!' in exactly those words.")
    print(f"Response: {response}")

    print("\n=== Testing chat (multi-turn) ===")
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "What is 2 + 2?"},
        {"role": "assistant", "content": "4"},
        {"role": "user", "content": "Multiply that by 3."},
    ]
    response = client.chat(messages)
    print(f"Response: {response}")

    print("\nAll tests passed!")
    return 0


if __name__ == "__main__":
    sys.exit(test_sync_client())
