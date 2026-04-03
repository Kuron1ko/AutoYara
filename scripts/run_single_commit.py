#!/usr/bin/env python3
"""
示例：仅处理一条 Gitee/GitCode commit 链接（可选本地补丁文件）。

在仓库根目录::

    pip install -e .
    python scripts/run_single_commit.py

请编辑下方 ``COMMIT_URL``；若需跳过在线拉 patch，设置 ``PATCH_PATH`` 为 .diff/.patch 路径。
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from autoyara.collector import CollectorConfig, collect_cve_items  # noqa: E402

# --- 按你的目标修改 ---
# 支持 gitee / gitcode / github commit URL，例如：
#   "https://gitcode.com/openharmony/kernel_linux_5.10/commit/<sha>"
#   "https://github.com/openharmony/kernel_linux_5.10/commit/<sha>"
COMMIT_URL = "https://gitcode.com/openharmony/kernel_linux_5.10/commit/0000000"
PATCH_PATH: str | None = None  # 例: str(REPO_ROOT / "local.patch")
CVE_LABEL = "MANUAL"


def main() -> None:
    cfg = CollectorConfig(
        commit_url=COMMIT_URL,
        cve_override=CVE_LABEL,
        local_patch_path=PATCH_PATH,
        http_timeout_sec=30,
    )
    result = collect_cve_items(cfg, delay_between_links_sec=0.0)
    items = result if isinstance(result, list) else [result]
    out_dir = REPO_ROOT / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "single_commit.json"
    path.write_text(
        json.dumps([asdict(x) for x in items], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"写入 {path}，共 {len(items)} 条 CVEItem")


if __name__ == "__main__":
    main()
