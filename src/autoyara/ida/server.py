# ida_mcp_server.py

# 标准库
import json
import os
import subprocess
import sys
import time
import traceback

# ruff: noqa: E402
# 需要先把 src 加入 sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
src_path = os.path.join(project_root, "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# 第三方库
from mcp.server.fastmcp import FastMCP  # noqa: I001

# 内部模块
from autoyara.configs.config import (
    get_ida_path,
    get_log_dir,
    get_python_path,
    get_tmp_dir,
)


mcp = FastMCP("IDA_Pro_Analyzer")

LOG_DIR = get_log_dir()
IDA_PATH = get_ida_path()
PYTHON_PATH = get_python_path()
TEMP_DIR = get_tmp_dir()


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


@mcp.tool()
def get_hex_from_ida(elf_file_path: str, function_name: str) -> str:
    if not os.path.exists(elf_file_path):
        return f"Error: 文件不存在: {elf_file_path}"

    if not os.path.exists(IDA_PATH):
        return f"Error: IDA 路径不存在: {IDA_PATH}"

    # 设定储存日志、脚本、结果的目录
    ts = int(time.time() * 1000)
    uniq = f"{ts}_{os.getpid()}"
    log_path = os.path.join(LOG_DIR, f"ida_mcp_{uniq}.log")

    temp_subdir = os.path.join(TEMP_DIR, uniq)
    os.makedirs(temp_subdir, exist_ok=True)
    script_path = os.path.join(temp_subdir, "script.py")
    stage_path = os.path.join(temp_subdir, "stage.txt")
    done_path = os.path.join(temp_subdir, "done.txt")
    output_json_path = os.path.join(temp_subdir, "output.json")

    processed_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../../data/processed")
    )
    os.makedirs(processed_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(elf_file_path))[0]
    i64_path = os.path.join(processed_dir, base_name + ".i64")
    idb_path = os.path.join(processed_dir, base_name + ".idb")

    append_log(log_path, "=== START ===")
    append_log(log_path, f"elf={elf_file_path}")
    append_log(log_path, f"target_function={function_name}")

    fn_literal = json.dumps(function_name, ensure_ascii=False)
    script_content = f"""# -*- coding: utf-8 -*-
import os
import json
import traceback

import idautils
import idaapi
import idc
import ida_pro

STAGE_PATH = {stage_path!r}
OUT_JSON = {output_json_path!r}
DONE_PATH = {done_path!r}
TARGET_NAME = {fn_literal}

def write_stage(s):
    try:
        with open(STAGE_PATH, "a", encoding="utf-8") as f:
            f.write(s + "\\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass

def write_json_atomic(obj, path):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def get_function_hex():
    def find_and_extract():
        ea = idc.get_name_ea_simple(TARGET_NAME)
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
        return None


    # 等待分析
    write_stage("before auto_wait")
    idaapi.auto_wait()
    write_stage("after auto_wait")

    # 尝试精确查找
    res = find_and_extract()
    if res:
        return res

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
    result = {{"status": "error", "message": "unknown"}}
    try:
        write_stage("main entered")
        result = get_function_hex()
        write_stage("get_function_hex done")
    except Exception as e:
        result = {{
            "status": "error",
            "message": "exception: " + str(e),
            "trace": traceback.format_exc()
        }}
        write_stage("exception: " + str(e))
    finally:
        try:
            write_json_atomic(result, OUT_JSON)
            write_stage("json dumped")

            with open(DONE_PATH, "w", encoding="utf-8") as f:
                f.write("ok")
                f.flush()
                os.fsync(f.fileno())
            write_stage("done written")
        except Exception as e:
            write_stage("finalize error: " + str(e))
        finally:
            write_stage("qexit")
            ida_pro.qexit(0)

main()
"""

    # 写idaapi需要的脚本
    try:
        with open(script_path, "w", encoding="utf-8") as sf:
            sf.write(script_content)
    except Exception as e:
        return f"Error: 写脚本失败: {e}"

    # 优先从 /data/processed 目录读取 i64/idb 数据库文件
    if os.path.exists(i64_path):
        ida_input = i64_path
        append_log(log_path, f"reuse_ida_db={ida_input}")
    elif os.path.exists(idb_path):
        ida_input = idb_path
        append_log(log_path, f"reuse_ida_db={ida_input}")
    else:
        ida_input = elf_file_path
        append_log(log_path, f"no_db_found, use_elf={ida_input}")

    ida_cmd = [IDA_PATH, "-A", f"-S{script_path}", ida_input]
    append_log(log_path, "CMD: " + " ".join(ida_cmd))
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    creationflags |= getattr(subprocess, "DETACHED_PROCESS", 0x00000008)

    try:
        p = subprocess.Popen(
            ida_cmd,
            stdin=subprocess.DEVNULL,
            stdout=None,
            stderr=None,
            close_fds=True,
            creationflags=creationflags,
        )
        append_log(log_path, f"popen ok, pid={p.pid}")
    except Exception as e:
        return f"Error: 启动 IDA 失败: {e} (log={log_path})"

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
                        append_log(log_path, "json parsed after done")
                        # 分析完成后移动i64/idb文件到/data/processed
                        for orig, dst in [
                            (os.path.splitext(elf_file_path)[0] + ".i64", i64_path),
                            (os.path.splitext(elf_file_path)[0] + ".idb", idb_path),
                        ]:
                            if os.path.exists(orig):
                                os.replace(orig, dst)
                        break
                    except Exception as e:
                        append_log(log_path, f"json parse after done failed: {e}")

            # 3) 进程提前退出
            rc = p.poll()
            if rc is not None:
                append_log(log_path, f"process exited rc={rc}")
                time.sleep(0.4)
                txt = read_text(output_json_path).strip()
                if txt:
                    result = json.loads(txt)
                    append_log(log_path, "json parsed after process exit")
                    # 分析完成后移动i64/idb文件到/data/processed
                    for orig, dst in [
                        (os.path.splitext(elf_file_path)[0] + ".i64", i64_path),
                        (os.path.splitext(elf_file_path)[0] + ".idb", idb_path),
                    ]:
                        if os.path.exists(orig):
                            os.replace(orig, dst)
                break

            time.sleep(0.25)

        # 拿到结果
        if result is not None:
            finalize_process(p, log_path)

            if result.get("status") == "success":
                return (
                    f"函数 {result.get('func_name')} 的 Hex:\n"
                    f"{result.get('hex')}\n"
                    f"(ida_log={log_path})"
                )
            return f"IDA 失败: {result}\n(ida_log={log_path})"

        # 超时
        finalize_process(p, log_path)
        append_log(
            log_path, f"stage={os.path.exists(stage_path)} returncode={p.poll()}"
        )
        return (
            "Error: 等待结果超时。\n"
            f"log={log_path}\n"
            f"script={script_path}\n"
            f"stage={stage_path}"
        )

    except Exception as e:
        finalize_process(p, log_path)
        append_log(log_path, "host exception:\n" + traceback.format_exc())
        return (
            f"Error: 宿主异常: {e}\n"
            f"log={log_path}\n"
            f"script={script_path}\n"
            f"stage={stage_path}"
        )


if __name__ == "__main__":
    mcp.run(transport="stdio")
