# 标准库
import asyncio  # noqa: I001

# 第三方库
from mcp import stdio_client

# 内部模块
from configs.config import settings


def get_hex_from_ida(elf_file_path, function_name):
    server_cmd = settings.server_cmd

    async def _call():
        async with stdio_client(command=server_cmd) as session:
            return await session.call_tool(
                "get_hex_from_ida",
                {
                    "elf_file_path": elf_file_path,
                    "function_name": function_name,
                },
            )

    return asyncio.run(_call())


def get_function_name_by_hex(elf_file_path, hex_str):
    server_cmd = settings.server_cmd

    async def _call():
        async with stdio_client(command=server_cmd) as session:
            return await session.call_tool(
                "get_function_name_by_hex",
                {
                    "elf_file_path": elf_file_path,
                    "hex_str": hex_str,
                },
            )

    return asyncio.run(_call())
