# LLM Module

## Overview

Provides unified LLM client interfaces for interacting with various language model providers.

## Usage

### Synchronous Client

```python
from autoyara.llm import SyncLLMClient, create_sync_client

client = create_sync_client(api_key="your-api-key")
response = client.chat([
    {"role": "user", "content": "Hello!"}
])
```

### Asynchronous Client

```python
import asyncio
from autoyara.llm import AsyncLLMClient, create_async_client

async def main():
    client = await create_async_client(api_key="your-api-key")
    response = await client.chat([
        {"role": "user", "content": "Hello!"}
    ])

asyncio.run(main())
```

## Configuration

Add to `configs/config.yaml`:

```yaml
OPENAI_API_KEY: "your-openai-api-key"
```
