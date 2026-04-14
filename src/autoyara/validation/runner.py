# /tmp/cve_id/cve_id.json
# /tmp/cve_id/cve_id.yara
import os
import subprocess
import sys
from pathlib import Path

# 需要先把 src 加入 sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# 内部模块
from configs.config import settings  # noqa: E402

from autoyara.models import ValidationResult  # noqa: E402

yara_path = Path(project_root) / "tools" / "yara64.exe"

FIXED_ELF_PATH = settings.fixed_elf_path
UNFIXED_ELF_PATH = settings.unfixed_elf_path


def checkcve(cve_id):
    cve_json_path = Path(settings.data_dir) / "processed" / cve_id / f"{cve_id}.json"
    cve_yara_path = Path(settings.data_dir) / "processed" / cve_id / f"{cve_id}.yara"

    if not cve_json_path.exists() or not cve_yara_path.exists():
        raise FileNotFoundError(f"未找到 {cve_id} 的 JSON 或 YARA 文件,{project_root}")
    if not Path(FIXED_ELF_PATH).exists():
        raise FileNotFoundError(f"未找到修复后的 ELF 文件: {FIXED_ELF_PATH}")
    if not Path(UNFIXED_ELF_PATH).exists():
        raise FileNotFoundError(f"未找到未修复的 ELF 文件: {UNFIXED_ELF_PATH}")

    # 检测 fixed 文件
    fixed_cmd = [str(yara_path), str(cve_yara_path), str(FIXED_ELF_PATH)]
    fixed_result = subprocess.run(fixed_cmd, capture_output=True, text=True)
    fixed_output = fixed_result.stdout.strip()
    fixed_matched = bool(fixed_output)

    # 检测 unfixed 文件
    unfixed_cmd = [str(yara_path), str(cve_yara_path), str(UNFIXED_ELF_PATH)]
    unfixed_result = subprocess.run(unfixed_cmd, capture_output=True, text=True)
    unfixed_output = unfixed_result.stdout.strip()
    unfixed_matched = bool(unfixed_output)

    # 结果判断
    if fixed_matched and not unfixed_matched:
        message = f"{cve_id} testcase pass (fixed通过, unfixed不通过)"
        return_code = 0
    elif fixed_matched and unfixed_matched:
        message = f"{cve_id} testcase fail (fixed和unfixed都通过)"
        return_code = 1
    elif not fixed_matched and not unfixed_matched:
        message = f"{cve_id} testcase fail (fixed和unfixed都不通过)"
        return_code = 2
    elif not fixed_matched and unfixed_matched:
        message = f"{cve_id} testcase fail (unfixed通过, fixed不通过)"
        return_code = 3
    else:
        message = f"{cve_id} testcase unknown error"
        return_code = -1

    return ValidationResult(
        cve_id=cve_id,
        fixed_matched=fixed_matched,
        unfixed_matched=unfixed_matched,
        return_code=return_code,
        message=message,
    )
