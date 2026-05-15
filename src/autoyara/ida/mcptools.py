# 标准库
import asyncio  # noqa: I001
import logging

# 第三方库
from mcp import ClientSession, StdioServerParameters, stdio_client

# 内部模块
from autoyara.config import settings


def _format_exception(exc: BaseException) -> str:
    parts = [f"{exc.__class__.__name__}: {exc}"]

    nested = getattr(exc, "exceptions", None)
    if nested:
        for sub_exc in nested:
            parts.append(_format_exception(sub_exc))

    cause = getattr(exc, "__cause__", None)
    if cause:
        parts.append(_format_exception(cause))

    context = getattr(exc, "__context__", None)
    if context and context is not cause:
        parts.append(_format_exception(context))

    return " | ".join(parts)


def _silence_mcp_noise_logs() -> None:
    """屏蔽 MCP 解析杂质输出时的噪声日志，不影响工具调用结果。"""
    logging.getLogger("mcp.client.stdio").setLevel(logging.CRITICAL)
    logging.getLogger("mcp.client").setLevel(logging.CRITICAL)
    logging.getLogger("mcp").setLevel(logging.CRITICAL)


async def _call_mcp_tool(tool_name, tool_args):
    _silence_mcp_noise_logs()
    server_cmd = settings.server_cmd
    params = StdioServerParameters(
        command=server_cmd[0],
        args=server_cmd[1:],
    )

    print(f"[*] Calling MCP tool: {tool_name} with args: {tool_args}")
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, tool_args)
                if result.isError:
                    print(f"[!] MCP tool error: {result.content}")
                    return f"Error: {result.content}"
                texts = [
                    content.text
                    for content in result.content
                    if hasattr(content, "text")
                ]
                if texts:
                    print(f"[*] MCP tool {tool_name} returned success")
                    return "\n".join(texts)
                return str(result.content)
    except Exception as e:
        detail = _format_exception(e)
        print(f"[!] Exception calling MCP tool: {detail}")
        return f"Error: {detail}"


def get_hex_from_ida(elf_file_path, function_name):
    return asyncio.run(
        _call_mcp_tool(
            "get_hex_from_ida",
            {
                "elf_file_path": elf_file_path,
                "function_name": function_name,
            },
        )
    )


def get_decompiled_code(elf_file_path, function_name):
    return asyncio.run(
        _call_mcp_tool(
            "get_decompiled_code",
            {
                "elf_file_path": elf_file_path,
                "function_name": function_name,
            },
        )
    )


def get_disassembly_code(elf_file_path, function_name):
    return asyncio.run(
        _call_mcp_tool(
            "get_disassembly_code",
            {
                "elf_file_path": elf_file_path,
                "function_name": function_name,
            },
        )
    )


def get_disassembly_by_address_range(elf_file_path, start_addr, end_addr):
    """根据地址范围获取汇编代码"""
    return asyncio.run(
        _call_mcp_tool(
            "get_disassembly_by_address_range",
            {
                "elf_file_path": elf_file_path,
                "start_addr": start_addr,
                "end_addr": end_addr,
            },
        )
    )


def get_function_name_by_string(elf_file_path, search_str):
    return asyncio.run(
        _call_mcp_tool(
            "get_function_name_by_string",
            {
                "elf_file_path": elf_file_path,
                "search_str": search_str,
            },
        )
    )


def get_function_name_by_hex(elf_file_path, hex_str):
    return asyncio.run(
        _call_mcp_tool(
            "get_function_name_by_hex",
            {
                "elf_file_path": elf_file_path,
                "hex_str": hex_str,
            },
        )
    )


def get_hex_by_address_range(elf_file_path, start_addr, end_addr):
    """根据地址范围获取十六进制字节"""
    ret = asyncio.run(
        _call_mcp_tool(
            "get_hex_by_address_range",
            {
                "elf_file_path": elf_file_path,
                "start_addr": start_addr,
                "end_addr": end_addr,
            },
        )
    )
    return ret


def get_hex_by_code_snippet(elf_file_path, function_name, code_snippet):
    return asyncio.run(
        _call_mcp_tool(
            "get_hex_by_code_snippet",
            {
                "elf_file_path": elf_file_path,
                "function_name": function_name,
                "code_snippet": code_snippet,
            },
        )
    )


def get_hex_by_decompiled_snippet(elf_file_path, function_name, code_snippet):
    return asyncio.run(
        _call_mcp_tool(
            "get_hex_by_decompiled_snippet",
            {
                "elf_file_path": elf_file_path,
                "function_name": function_name,
                "code_snippet": code_snippet,
            },
        )
    )
