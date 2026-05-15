# ida_mcp_server.py

# 标准库
import json
import os
import subprocess
import sys
import textwrap
import time

# 记录原始 stdout，因为 MCP 需要它进行通信
_original_stdout = sys.stdout

# 将全局 stdout 重定向到 stderr，这样任何不经意的 print 都会进入 stderr
# 而不会破坏 MCP 的 JSON-RPC 协议
sys.stdout = sys.stderr

# ruff: noqa: E402
# 需要先把 src 加入 sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
src_path = os.path.join(project_root, "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)
    sys.path.insert(0, src_path)

# 第三方库
from mcp.server.fastmcp import FastMCP  # noqa: I001

# 内部模块
from autoyara.config import settings

mcp = FastMCP("IDA_Pro_Analyzer")

LOG_DIR = settings.log_dir
IDA_PATH = settings.ida_path
PYTHON_PATH = settings.python_path
TEMP_DIR = settings.tmp_dir


def append_log(log_path: str, msg: str) -> None:
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(msg.rstrip("\n") + "\n")
    except Exception:
        pass


def read_text(path: str, default: str = "") -> str:
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return default


def kill_process_tree_windows(pid: int) -> None:
    try:
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=3,
        )
    except Exception:
        pass


def finalize_process(p: subprocess.Popen, log_path: str) -> None:
    try:
        p.wait(timeout=5)
        append_log(log_path, "process exited naturally")
        return
    except Exception:
        pass

    try:
        p.terminate()
        append_log(log_path, "process terminate sent")
        p.wait(timeout=2)
        append_log(log_path, "process exited after terminate")
        return
    except Exception:
        pass

    if p.poll() is None:
        append_log(log_path, "process still alive -> taskkill tree")
        kill_process_tree_windows(p.pid)


def _run_ida_script(
    elf_file_path: str, script_content: str, tool_name: str, timeout_sec: int = 600
) -> dict:
    """
    通用函数：运行指定的 IDA 脚本并返回结果。
    """
    if not os.path.exists(elf_file_path):
        return {"status": "error", "message": f"文件不存在: {elf_file_path}"}
    if not os.path.exists(IDA_PATH):
        return {"status": "error", "message": f"IDA 路径不存在: {IDA_PATH}"}

    # 设定储存日志、脚本、结果的目录
    ts = int(time.time() * 1000)
    uniq = f"{ts}_{os.getpid()}"
    log_path = os.path.join(LOG_DIR, f"ida_mcp_{uniq}_{tool_name}.log")
    temp_subdir = os.path.join(TEMP_DIR, uniq)
    os.makedirs(temp_subdir, exist_ok=True)

    script_path = os.path.join(temp_subdir, "script.py")
    done_path = os.path.join(temp_subdir, "done.txt")
    output_json_path = os.path.join(temp_subdir, "output.json")

    processed_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../../data/processed")
    )
    os.makedirs(processed_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(elf_file_path))[0]
    i64_path = os.path.join(processed_dir, base_name + ".i64")
    idb_path = os.path.join(processed_dir, base_name + ".idb")

    # 注入通用的常量和辅助函数
    script_body = textwrap.dedent(script_content)
    full_script = f"""# -*- coding: utf-8 -*-
import os
import json
import traceback

import idautils
import idaapi
import idc
import ida_pro
import re

OUT_JSON = {output_json_path!r}
DONE_PATH = {done_path!r}

def write_json_atomic(obj, path):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def normalize_line(s):
    try:
        s = idaapi.tag_remove(s)
    except: pass
    s = "".join(s.split()).lower()
    return s

def normalize_symbol_name(s):
    if not s:
        return ""
    return re.sub(r"[^0-9A-Za-z_]", "_", s)

def parse_addr(val):
    if isinstance(val, int):
        return val
    s = str(val).strip()
    if not s:
        raise ValueError("empty address")
    # Accept forms like:
    # - 0xFFFF_FFC0_1012_33A0
    # - FFFFFFC0101233A0
    # - 68719492314128
    s_clean = s.replace("_", "")
    if s_clean.lower().startswith("0x"):
        return int(s_clean, 16)
    if re.fullmatch(r"[0-9a-fA-F]+", s_clean):
        # If letters are present, treat as hex; otherwise treat as decimal.
        if re.search(r"[a-fA-F]", s_clean):
            return int(s_clean, 16)
        return int(s_clean, 10)
    return int(s_clean, 10)

def resolve_function_ea(target):
    ea = idc.get_name_ea_simple(target)
    if ea != idc.BADADDR:
        return ea

    target_norm = normalize_symbol_name(target)

    for func_ea in idautils.Functions():
        name = idc.get_func_name(func_ea) or ""
        if name == target:
            return func_ea
        if target_norm and normalize_symbol_name(name) == target_norm:
            return func_ea

    for func_ea in idautils.Functions():
        name = idc.get_func_name(func_ea) or ""
        if target and target in name:
            return func_ea
        if target_norm and target_norm in normalize_symbol_name(name):
            return func_ea

    return idc.BADADDR

def get_line_eas(cf, line_text):
    eas = set()
    try:
        # 尝试从行末或行中的转义序列提取地址 (IDA 7.x+)
        # 支持 8 位 (32-bit) 或 16 位 (64-bit) 地址索引
        matches = re.finditer(r'\\x01\\(([0-9a-fA-F]{{8,16}})', line_text)
        for m in matches:
            try:
                idx = int(m.group(1), 16)
                if idx < len(cf.treeitems):
                    item_ea = cf.treeitems[idx].ea
                    if item_ea != idc.BADADDR:
                        eas.add(item_ea)
            except: pass
        # 另一种可能的转义序列 \\x01\\x05ADDR\\x02
        matches = re.finditer('\\\\x01\\\\x05([0-9a-fA-F]+)\\\\x02', line_text)
        for m in matches:
            try: eas.add(int(m.group(1), 16))
            except: pass
    except: pass
    return eas

{script_body}

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        res = {{"status": "error", "message": "Script Exception: " + str(e), "trace": traceback.format_exc()}}
        write_json_atomic(res, OUT_JSON)
    finally:
        with open(DONE_PATH, "w", encoding="utf-8") as f:
            f.write("ok")
        ida_pro.qexit(0)
"""

    try:
        with open(script_path, "w", encoding="utf-8") as sf:
            sf.write(full_script)
    except Exception as e:
        return {"status": "error", "message": f"写脚本失败: {e}"}

    # 数据库复用
    if os.path.exists(i64_path):
        ida_input = i64_path
    elif os.path.exists(idb_path):
        ida_input = idb_path
    else:
        ida_input = elf_file_path

    ida_cmd = [IDA_PATH, "-A", f"-S{script_path}", ida_input]
    append_log(log_path, f"CMD: {' '.join(ida_cmd)}")

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    creationflags |= getattr(subprocess, "DETACHED_PROCESS", 0x00000008)

    try:
        p = subprocess.Popen(
            ida_cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=creationflags,
        )
    except Exception as e:
        return {"status": "error", "message": f"启动 IDA 失败: {e}"}

    timeout_sec = 600
    deadline = time.time() + timeout_sec
    result = None
    try:
        while time.time() < deadline:
            # 1) 优先等 done（表示 JSON 已完整写好）
            if os.path.exists(done_path):
                append_log(log_path, "done detected")
                txt = read_text(output_json_path).strip()
                if txt:
                    try:
                        result = json.loads(txt)
                        # 成功解析后，更新 i64/idb 文件
                        for orig, dst in [
                            (os.path.splitext(elf_file_path)[0] + ".i64", i64_path),
                            (os.path.splitext(elf_file_path)[0] + ".idb", idb_path),
                        ]:
                            if os.path.exists(orig):
                                os.replace(orig, dst)
                        break
                    except Exception as e:
                        append_log(log_path, f"json parse failed: {e}")

            if p.poll() is not None:
                time.sleep(0.5)
                txt = read_text(output_json_path).strip()
                if txt:
                    try:
                        result = json.loads(txt)
                    except Exception as e:
                        append_log(log_path, f"json parse failed: {e}")
                break
            time.sleep(0.5)

        finalize_process(p, log_path)
        if result:
            return result
        return {"status": "error", "message": "等待结果超时", "log": log_path}
    except Exception as e:
        finalize_process(p, log_path)
        return {"status": "error", "message": f"宿主异常: {e}", "log": log_path}


@mcp.tool()
def get_hex_from_ida(elf_file_path: str, function_name: str) -> str:
    script_content = f"""
    TARGET_NAME = {function_name!r}

    def get_function_hex():
        ea = resolve_function_ea(TARGET_NAME)
        if ea != idaapi.BADADDR:
            start = ea
            end = idc.get_func_attr(ea, idc.FUNCATTR_END)
            if end != idaapi.BADADDR and end > start:
                data = idc.get_bytes(start, end - start)
                if data:
                    hex_str = " ".join(f"{{b:02X}}" for b in data)
                    return {{
                        "status": "success",
                        "func_name": TARGET_NAME,
                        "start_ea": hex(start),
                        "end_ea": hex(end),
                        "size": end - start,
                        "hex": hex_str
                    }}

        # 尝试模糊匹配遍历查找
        for func_ea in idautils.Functions():
            name = idc.get_func_name(func_ea) or ""
            if TARGET_NAME in name:
                start = func_ea
                end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
                if end is None or end <= start: continue
                data = idc.get_bytes(start, end - start)
                if not data: continue
                hex_str = " ".join(f"{{b:02X}}" for b in data)
                return {{
                    "status": "success",
                    "func_name": name,
                    "start_ea": hex(start),
                    "end_ea": hex(end),
                    "size": end - start,
                    "hex": hex_str
                }}
        return {{"status": "error", "message": f"Function not found: {{TARGET_NAME}}"}}

    def main():
        idaapi.auto_wait()
        res = get_function_hex()
        write_json_atomic(res, OUT_JSON)
    """
    result = _run_ida_script(elf_file_path, script_content, "get_hex")
    if result.get("status") == "success":
        return f"函数 {result.get('func_name')} 的 Hex:\n{result.get('hex')}"
    return f"IDA 失败: {result.get('message', '未知错误')}"


@mcp.tool()
def get_function_name_by_hex(elf_file_path: str, hex_str: str) -> list:
    """
    遍历所有函数，提取其 hex_str，与输入的 hex_str 比较，返回包含该 hex_str 的函数名列表。
    """
    script_content = f"""
    TARGET_HEX = {hex_str.upper().replace(" ", "")!r}

    def hex_bytes(data):
        return "".join(f"{{b:02X}}" for b in data)

    def main():
        result = []
        for func_ea in idautils.Functions():
            name = idc.get_func_name(func_ea) or ""
            start = func_ea
            end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
            if end is None or end <= start:
                continue
            data = idc.get_bytes(start, end - start)
            if not data:
                continue
            func_hex = hex_bytes(data).upper()

            if TARGET_HEX in func_hex:
                result.append(name)
        write_json_atomic(result, OUT_JSON)
    """
    result = _run_ida_script(elf_file_path, script_content, "findhex")
    if isinstance(result, list):
        return result
    return [f"Error: {result.get('message', '未知错误')}"]


# 新增：根据字符串查找引用该字符串的所有函数名
@mcp.tool()
def get_function_name_by_string(elf_file_path: str, search_str: str) -> list:
    """
    在 IDA 中查找引用了特定字符串的所有函数名。
    """
    script_content = f"""
    TARGET_STR = {search_str!r}

    def main():
        result = set()
        # 遍历 IDB 中的所有字符串
        for s in idautils.Strings():
            s_content = str(s)
            if TARGET_STR in s_content:
                # 找到匹配字符串后，查找所有引用该地址的地方
                for xref in idautils.XrefsTo(s.ea):
                    func_name = idc.get_func_name(xref.frm)
                    if func_name:
                        result.add(func_name)
        write_json_atomic(list(result), OUT_JSON)
    """
    result = _run_ida_script(elf_file_path, script_content, "findstr")
    if isinstance(result, list):
        return result
    return [f"Error: {result.get('message', '未知错误')}"]


@mcp.tool()
def search_hex_in_function(
    elf_file_path: str, function_name: str, target_hex: str
) -> str:
    """
    在指定函数中搜索十六进制字符串，并返回对应的 C 伪代码行。
    """
    script_content = f"""
    TARGET_FUNC = {function_name!r}
    TARGET_HEX = {target_hex!r}

    def main():
        res = {{"status": "error", "message": "unknown"}}
        ea = resolve_function_ea(TARGET_FUNC)
        if ea == idc.BADADDR:
            res = {{"status": "error", "message": "找不到函数: " + TARGET_FUNC}}
        else:
            start = ea
            end = idc.get_func_attr(ea, idc.FUNCATTR_END)
            found_eas = []
            curr = start
            while curr < end:
                curr = idc.find_binary(curr, idc.SEARCH_DOWN, TARGET_HEX)
                if curr == idc.BADADDR or curr >= end:
                    break
                found_eas.append(curr)
                curr += 1

            if not found_eas:
                res = {{"status": "error", "message": "函数中未找到该 Hex"}}
            else:
                if not idaapi.init_hexrays_plugin():
                    res = {{"status": "error", "message": "Hex-Rays 插件不可用"}}
                else:
                    cf = idaapi.decompile(ea)
                    if not cf:
                        res = {{"status": "error", "message": "反编译失败"}}
                    else:
                        results = []
                        sv = cf.get_pseudocode()
                        for f_ea in found_eas:
                            # 寻找包含该 EA 的行
                            matched_line = ""
                            for sl in sv:
                                line_text = sl.line
                                if hex(f_ea).lower() in line_text.lower():
                                    matched_line = idaapi.tag_remove(line_text)
                                    break
                            if matched_line:
                                results.append(f"{{hex(f_ea)}}: {{matched_line}}")
                            else:
                                results.append(f"{{hex(f_ea)}}: (无对应行)")
                        res = {{"status": "success", "results": results}}
        write_json_atomic(res, OUT_JSON)
    """
    result = _run_ida_script(elf_file_path, script_content, "search_hex")
    if result.get("status") == "success":
        return "\n".join(result.get("results", []))
    return f"Error: {result.get('message', '未知错误')}"


@mcp.tool()
def get_decompiled_code(elf_file_path: str, function_name: str) -> str:
    """
    获取指定函数的反编译（伪代码）内容。
    """
    script_content = f"""
    TARGET_FUNC = {function_name!r}

    def main():
        idaapi.auto_wait()
        res = ""
        ea = resolve_function_ea(TARGET_FUNC)

        # 尝试模糊匹配遍历查找
        if ea == idc.BADADDR:
            for func_ea in idautils.Functions():
                name = idc.get_func_name(func_ea) or ""
                if TARGET_FUNC in name:
                    ea = func_ea
                    break

        if ea == idc.BADADDR:
            res = "Error: 找不到函数 " + TARGET_FUNC
        else:
            try:
                # 尝试反编译
                if not idaapi.init_hexrays_plugin():
                    res = "Error: Hex-Rays 插件未加载或不可用"
                else:
                    cf = idaapi.decompile(ea)
                    if cf:
                        res = str(cf)
                    else:
                        res = "Error: 反编译失败"
            except Exception as e:
                res = "Error: 反编译过程出现异常: " + str(e)
        write_json_atomic(res, OUT_JSON)
    """
    result = _run_ida_script(elf_file_path, script_content, "decompile")
    if isinstance(result, str):
        return result
    return f"Error: {result.get('message', '未知错误')}"


# 新增：获取指定函数的反汇编代码
@mcp.tool()
def get_disassembly_code(elf_file_path: str, function_name: str) -> str:
    """
    获取指定函数的反汇编代码。
    """
    script_content = f"""
    TARGET_FUNC = {function_name!r}

    def main():
        idaapi.auto_wait()
        res = ""
        ea = resolve_function_ea(TARGET_FUNC)

        # 尝试模糊匹配遍历查找
        if ea == idc.BADADDR:
            for func_ea in idautils.Functions():
                name = idc.get_func_name(func_ea) or ""
                if TARGET_FUNC in name:
                    ea = func_ea
                    break

        if ea == idc.BADADDR:
            res = "Error: 找不到函数 " + TARGET_FUNC
        else:
            start_ea = ea
            end_ea = idc.get_func_attr(ea, idc.FUNCATTR_END)
            lines = []
            curr = start_ea
            while curr < end_ea:
                disasm = idc.generate_disasm_line(curr, 0)
                lines.append(f"{{hex(curr)}}: {{disasm}}")
                curr = idc.next_head(curr, end_ea)
            res = "\\n".join(lines)
        write_json_atomic(res, OUT_JSON)
    """
    result = _run_ida_script(elf_file_path, script_content, "disasm")
    if isinstance(result, str):
        return result
    return f"Error: {result.get('message', '未知错误')}"


@mcp.tool()
def get_disassembly_by_address_range(
    elf_file_path: str, start_addr: str, end_addr: str
) -> str:
    """
    获取指定地址范围内的反汇编代码。
    参数:
        elf_file_path: ELF 文件路径
        start_addr: 起始地址 (十六进制字符串或整数)
        end_addr: 结束地址 (十六进制字符串或整数)
    """
    script_content = f"""
    START_ADDR = {start_addr!r}
    END_ADDR = {end_addr!r}

    def main():
        idaapi.auto_wait()
        try:
            s_addr = parse_addr(START_ADDR)
            e_addr = parse_addr(END_ADDR)
        except Exception as e:
            write_json_atomic("Error: 地址格式错误: " + str(e), OUT_JSON)
            return

        lines = []
        curr = s_addr
        while curr < e_addr:
            disasm = idc.generate_disasm_line(curr, 0)
            lines.append(f"{{hex(curr)}}: {{disasm}}")
            curr = idc.next_head(curr, e_addr)
        res = "\\n".join(lines)
        write_json_atomic(res, OUT_JSON)
    """
    result = _run_ida_script(elf_file_path, script_content, "disasm_range")
    if isinstance(result, str):
        return result
    return f"Error: {result.get('message', '未知错误')}"


# 新增：根据函数名和反编译的代码片段提取对应的 hex
@mcp.tool()
def get_hex_by_address_range(elf_file_path: str, start_addr: str, end_addr: str) -> str:
    """
    获取指定地址范围内的原始十六进制字节。
    """
    script_content = f"""
    START_ADDR = {start_addr!r}
    END_ADDR = {end_addr!r}

    def main():
        idaapi.auto_wait()
        try:
            s_addr = parse_addr(START_ADDR)
            e_addr = parse_addr(END_ADDR)
        except Exception as e:
            write_json_atomic("Error: 地址格式错误: " + str(e), OUT_JSON)
            return

        if e_addr <= s_addr:
            write_json_atomic("Error: 结束地址必须大于起始地址", OUT_JSON)
            return

        data = idc.get_bytes(s_addr, e_addr - s_addr)
        if not data:
            write_json_atomic("Error: 无法获取字节数据", OUT_JSON)
            return

        hex_str = " ".join(f"{{b:02X}}" for b in data)
        write_json_atomic(hex_str, OUT_JSON)
    """
    result = _run_ida_script(elf_file_path, script_content, "get_hex_range")
    if isinstance(result, str):
        return result
    return f"Error: {result.get('message', '未知错误')}"


@mcp.tool()
def get_hex_by_decompiled_snippet(
    elf_file_path: str, function_name: str, code_snippet: str
) -> str:
    """
    根据函数名和一段反编译后的 C 代码片段（伪代码），在函数中匹配该片段并提取对应的 hex。
    """
    script_content = f"""
    TARGET_FUNC = {function_name!r}
    SNIPPET = {code_snippet!r}

    def main():
        idaapi.auto_wait()
        res = {{"status": "error", "message": "unknown"}}
        ea = resolve_function_ea(TARGET_FUNC)

        # 尝试模糊匹配遍历查找
        if ea == idc.BADADDR:
            for func_ea in idautils.Functions():
                name = idc.get_func_name(func_ea) or ""
                if TARGET_FUNC in name:
                    ea = func_ea
                    break

        if ea == idc.BADADDR:
            res = {{"status": "error", "message": "找不到函数: " + TARGET_FUNC}}
        elif not idaapi.init_hexrays_plugin():
            res = {{"status": "error", "message": "Hex-Rays 插件不可用"}}
        else:
            cf = idaapi.decompile(ea)
            if not cf:
                res = {{"status": "error", "message": "反编译失败"}}
            else:
                lines_data = []
                sv = cf.get_pseudocode()
                for sl in sv:
                    line_text = sl.line
                    clean_text = normalize_line(line_text)
                    row_eas = get_line_eas(cf, line_text)
                    if clean_text:
                        lines_data.append({{"text": clean_text, "eas": list(row_eas)}})

                target_norm = normalize_line(SNIPPET)
                matched_indices = []
                # 1. 尝试单行完全/部分匹配
                for i, l in enumerate(lines_data):
                    if target_norm in l["text"]:
                        matched_indices.append(i)

                # 2. 如果单行没匹配上，尝试跨行匹配
                if not matched_indices:
                    full_text = ""
                    line_start_pos = []
                    for l in lines_data:
                        line_start_pos.append(len(full_text))
                        full_text += l["text"]

                    start_idx = full_text.find(target_norm)
                    if start_idx != -1:
                        end_idx = start_idx + len(target_norm)
                        for i, pos in enumerate(line_start_pos):
                            line_end = line_start_pos[i+1] if i+1 < len(line_start_pos) else len(full_text)
                            # 如果该行在匹配范围内 (重合)
                            if not (line_end <= start_idx or pos >= end_idx):
                                matched_indices.append(i)

                if matched_indices:
                    all_eas = []
                    for idx in matched_indices:
                        all_eas.extend(lines_data[idx]["eas"])

                    if all_eas:
                        target_start = min(all_eas)
                        last_ea = max(all_eas)
                        func_end = idc.get_func_attr(ea, idc.FUNCATTR_END)
                        target_end = idc.next_head(last_ea, func_end)

                        size = target_end - target_start
                        buf = idc.get_bytes(target_start, size)
                        if buf:
                            hex_str = " ".join(f"{{b:02X}}" for b in buf)
                            res = {{
                                "status": "success",
                                "hex": hex_str,
                                "start": hex(target_start),
                                "end": hex(target_end)
                            }}
                        else:
                            res = {{"status": "error", "message": "提取 hex 失败"}}
                    else:
                        res = {{"status": "error", "message": "匹配成功但无法精确定位地址"}}
                else:
                    res = {{"status": "error", "message": "未找到匹配的代码片段"}}
        write_json_atomic(res, OUT_JSON)
    """
    result = _run_ida_script(elf_file_path, script_content, "get_hex_snippet")
    if result.get("status") == "success":
        return (
            f"匹配成功！\n"
            f"范围: {result.get('start')} - {result.get('end')}\n"
            f"Hex: {result.get('hex')}"
        )
    return f"Error: {result.get('message', '未知错误')}"


@mcp.tool()
def get_hex_by_code_snippet(
    elf_file_path: str, function_name: str, code_snippet: str
) -> str:
    """
    根据函数名和一段代码片段（反汇编文本），在函数中匹配该片段并提取对应的 hex。
    """
    script_content = f"""
    TARGET_FUNC = {function_name!r}
    SNIPPET = {code_snippet!r}

    def normalize(s):
        # 去掉注释
        s = s.split(';')[0].strip()
        # 规范化空格
        s = " ".join(s.split())
        return s.lower()

    def main():
        res = {{"status": "error", "message": "unknown"}}
        ea = resolve_function_ea(TARGET_FUNC)
        if ea == idc.BADADDR:
            res = {{"status": "error", "message": "找不到函数: " + TARGET_FUNC}}
        else:
            start_ea = ea
            end_ea = idc.get_func_attr(ea, idc.FUNCATTR_END)

            snippet_lines = [normalize(line) for line in SNIPPET.splitlines() if normalize(line)]
            if not snippet_lines:
                res = {{"status": "error", "message": "代码片段为空"}}
            else:
                # 提取函数内的所有指令
                all_insts = []
                curr = start_ea
                while curr < end_ea:
                    disasm = idc.generate_disasm_line(curr, 0)
                    all_insts.append((curr, normalize(disasm)))
                    curr = idc.next_head(curr, end_ea)

                # 匹配
                found = False
                for i in range(len(all_insts) - len(snippet_lines) + 1):
                    match = True
                    for j in range(len(snippet_lines)):
                        # 子串匹配，增加容错性
                        if snippet_lines[j] not in all_insts[i+j][1]:
                            match = False
                            break
                    if match:
                        matched_start = all_insts[i][0]
                        last_inst_ea = all_insts[i + len(snippet_lines) - 1][0]
                        matched_end = idc.next_head(last_inst_ea, end_ea)

                        data = idc.get_bytes(matched_start, matched_end - matched_start)
                        if data:
                            hex_str = " ".join(f"{{b:02X}}" for b in data)
                            res = {{
                                "status": "success",
                                "hex": hex_str,
                                "start": hex(matched_start),
                                "end": hex(matched_end),
                                "func_name": TARGET_FUNC
                            }}
                            found = True
                            break
                if not found:
                    res = {{"status": "error", "message": "在函数中未找到匹配的代码片段"}}
        write_json_atomic(res, OUT_JSON)
    """
    result = _run_ida_script(elf_file_path, script_content, "get_hex_snippet_disasm")
    if result.get("status") == "success":
        return (
            f"匹配成功！\n"
            f"范围: {result.get('start')} - {result.get('end')}\n"
            f"Hex: {result.get('hex')}"
        )
    return f"Error: {result.get('message', '未知错误')}"


@mcp.tool()
def get_code_details(
    elf_file_path: str,
    function_name: str,
    code_snippet: str = "",
    type: str = "c",
) -> str:
    """
    合成提取功能：给定函数名和可选的代码片段，同时返回对应的反编译 C 代码、汇编代码和 Hex。
    参数:
        elf_file_path: ELF 文件路径
        function_name: 函数名
        code_snippet: (可选) 目标代码片段 (C 或 ASM)
        type: (可选) 代码片段类型 ('c' 或 'asm')，默认为 'c'
    """
    script_content = f"""
TARGET_FUNC = {function_name!r}
SNIPPET = {code_snippet!r}
TYPE = {type!r}

def main():
    res = {{"status": "error", "message": "unknown"}}
    ea = resolve_function_ea(TARGET_FUNC)
    if ea == idc.BADADDR:
        res = {{"status": "error", "message": "找不到函数: " + TARGET_FUNC}}
        write_json_atomic(res, OUT_JSON)
        return

    start_ea = ea
    end_ea = idc.get_func_attr(ea, idc.FUNCATTR_END)
    target_start = start_ea
    target_end = end_ea
    note = ""
    matched_c = []
    should_continue = True

    if SNIPPET:
        if TYPE == "c":
            if not idaapi.init_hexrays_plugin():
                res = {{"status": "error", "message": "Hex-Rays 插件不可用"}}
                should_continue = False
            else:
                cf = idaapi.decompile(ea)
                if not cf:
                    res = {{"status": "error", "message": "反编译失败"}}
                    should_continue = False
                else:
                    lines_data = []
                    sv = cf.get_pseudocode()
                    for sl in sv:
                        line_text = sl.line
                        clean_text = normalize_line(line_text)
                        row_eas = get_line_eas(cf, line_text)
                        if clean_text:
                            lines_data.append({{"text": clean_text, "raw": line_text, "eas": list(row_eas)}})

                    target_norm = normalize_line(SNIPPET)
                    matched_indices = []
                    for i, l in enumerate(lines_data):
                        if target_norm in l["text"]:
                            matched_indices.append(i)

                    if not matched_indices:
                        full_text = ""
                        line_start_pos = []
                        for l in lines_data:
                            line_start_pos.append(len(full_text))
                            full_text += l["text"]
                        start_idx = full_text.find(target_norm)
                        if start_idx != -1:
                            end_idx = start_idx + len(target_norm)
                            for i, pos in enumerate(line_start_pos):
                                line_end = line_start_pos[i+1] if i+1 < len(line_start_pos) else len(full_text)
                                if not (line_end <= start_idx or pos >= end_idx):
                                    matched_indices.append(i)

                    if matched_indices:
                        all_eas = []
                        for idx in matched_indices:
                            all_eas.extend(lines_data[idx]["eas"])
                            matched_c.append(idaapi.tag_remove(lines_data[idx]["raw"]).strip())
                        if all_eas:
                            target_start = min(all_eas)
                            last_ea = max(all_eas)
                            target_end = idc.next_head(last_ea, end_ea)
                        else:
                            note = "匹配成功但无法精确定位地址，返回整个函数"
                    else:
                        res = {{"status": "error", "message": "未找到 C 片段"}}
                        should_continue = False
        else:
            target_norm = normalize_line(SNIPPET)
            curr = start_ea
            found_ea = idc.BADADDR
            while curr < end_ea:
                dis = normalize_line(idc.generate_disasm_line(curr, 0))
                if target_norm in dis:
                    found_ea = curr
                    break
                curr = idc.next_head(curr, end_ea)
            if found_ea != idc.BADADDR:
                target_start = found_ea
                target_end = idc.next_head(found_ea, end_ea)
            else:
                res = {{"status": "error", "message": "未找到 ASM 片段"}}
                should_continue = False

    if should_continue:
        size = target_end - target_start
        buf = idc.get_bytes(target_start, size)
        hex_str = " ".join(f"{{b:02X}}" for b in buf) if buf else ""
        asm_lines = []
        curr = target_start
        while curr < target_end:
            dis = idc.generate_disasm_line(curr, 0)
            if dis:
                asm_lines.append(f"{{hex(curr)}}: {{dis}}")
            curr = idc.next_head(curr, target_end)
        if not matched_c:
            if idaapi.init_hexrays_plugin():
                cf = idaapi.decompile(ea)
                if cf:
                    sv = cf.get_pseudocode()
                    for sl in sv:
                        matched_c.append(idaapi.tag_remove(sl.line).strip())
        res = {{
            "status": "success",
            "func_name": TARGET_FUNC,
            "range": f"{{hex(target_start)}} - {{hex(target_end)}}",
            "c_code": "\\n".join(matched_c),
            "asm_code": "\\n".join(asm_lines),
            "hex": hex_str,
            "note": note
        }}
    write_json_atomic(res, OUT_JSON)
"""
    result = _run_ida_script(elf_file_path, script_content, "details")
    if result.get("status") == "success":
        return (
            f"### **函数信息: {result.get('func_name')}**\n"
            f"- **范围**: `{result.get('range')}`\n"
            f"- **备注**: {result.get('note') if result.get('note') else '无'}\n\n"
            f"#### **反编译 C 代码**\n```c\n{result.get('c_code')}\n```\n\n"
            f"#### **汇编代码**\n```asm\n{result.get('asm_code')}\n```\n\n"
            f"#### **Hex 数据**\n```\n{result.get('hex')}\n```"
        )
    return f"Error: {result.get('message', '未知错误')}"


@mcp.tool()
def find_function_by_decompiled_snippet(elf_file_path: str, code_snippet: str) -> str:
    """
    在整个 ELF 文件中搜索包含指定反编译代码片段的函数名。
    """
    script_content = f"""
    TARGET = normalize_line({code_snippet!r})

    def main():
        res = {{"status": "error", "message": "未找到匹配函数"}}
        if not TARGET:
            res = {{"status": "error", "message": "搜索片段为空"}}
        elif not idaapi.init_hexrays_plugin():
            res = {{"status": "error", "message": "Hex-Rays 插件不可用"}}
        else:
            found_funcs = []
            # 遍历所有函数
            for ea in idautils.Functions():
                try:
                    cf = idaapi.decompile(ea)
                    if not cf: continue
                    sv = cf.get_pseudocode()
                    for sl in sv:
                        if TARGET in normalize_line(sl.line):
                            name = idc.get_func_name(ea)
                            if name not in found_funcs:
                                found_funcs.append(name)
                            break # 该函数已匹配
                except:
                    continue

            if found_funcs:
                res = {{"status": "success", "functions": found_funcs}}
            else:
                res = {{"status": "error", "message": "在所有函数中均未找到匹配的代码片段"}}
        write_json_atomic(res, OUT_JSON)
    """
    result = _run_ida_script(elf_file_path, script_content, "find_func")
    if result.get("status") == "success":
        funcs = result.get("functions", [])
        return f"找到匹配函数: {', '.join(funcs)}"
    return f"未找到匹配函数: {result.get('message', '未知错误')}"


if __name__ == "__main__":
    # 在启动 MCP 之前恢复原来的 stdout，否则客户端无法接收到 JSON-RPC 响应
    sys.stdout = _original_stdout
    mcp.run(transport="stdio")
