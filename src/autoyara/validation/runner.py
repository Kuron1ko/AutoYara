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

from autoyara.models import YaraValidationResult  # noqa: E402

yara_path = Path(project_root) / "tools" / "yara64.exe"

FIXED_ELF_PATH = settings.fixed_elf_path
UNFIXED_ELF_PATH = settings.unfixed_elf_path


def checkcve(
    cve_id,
    artifact_id: str | None = None,
    fixed_elf_path: str | None = None,
    unfixed_elf_path: str | None = None,
):
    target_id = artifact_id or cve_id
    cve_yara_path = (
        Path(settings.data_dir) / "processed" / target_id / f"{target_id}.yara"
    )

    # Validation depends on the generated YARA rule only.
    if not cve_yara_path.exists():
        return YaraValidationResult(
            cve_id=cve_id,
            fixed_matched=0,
            unfixed_matched=0,
            return_code=-1,
            message=f"missing YARA file for {target_id}",
        )

    # 检测 fixed 文件
    fixed_target = fixed_elf_path or FIXED_ELF_PATH
    unfixed_target = unfixed_elf_path or UNFIXED_ELF_PATH
    if not Path(fixed_target).exists():
        return YaraValidationResult(
            cve_id=cve_id,
            fixed_matched=0,
            unfixed_matched=0,
            return_code=-1,
            message=f"missing fixed ELF: {fixed_target}",
        )
    if not Path(unfixed_target).exists():
        return YaraValidationResult(
            cve_id=cve_id,
            fixed_matched=0,
            unfixed_matched=0,
            return_code=-1,
            message=f"missing unfixed ELF: {unfixed_target}",
        )

    fixed_cmd = [str(yara_path), str(cve_yara_path), str(fixed_target)]
    fixed_result = subprocess.run(fixed_cmd, capture_output=True, text=True)
    fixed_output = fixed_result.stdout.strip()
    fixed_matched = bool(fixed_output)

    # 检测 unfixed 文件
    unfixed_cmd = [str(yara_path), str(cve_yara_path), str(unfixed_target)]
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

    return YaraValidationResult(
        cve_id=cve_id,
        fixed_matched=fixed_matched,
        unfixed_matched=unfixed_matched,
        return_code=return_code,
        message=message,
    )
