#!/usr/bin/env python3
"""
示例：按公告年月采集 CVE 条目，并将 ``CVEItem`` 序列化为 JSON。

在仓库根目录执行（需已安装依赖 requests / urllib3）::

    pip install -e .
    python scripts/run_bulletin_month.py

或临时加入路径::

    set PYTHONPATH=src
    python scripts/run_bulletin_month.py
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

# 未安装包时自动把 src/ 加入路径（pip install -e . 后此段无副作用）
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from autoyara.collector import CollectorConfig, collect_cve_items  # noqa: E402


def main() -> None:
    # 按需修改：也可从环境变量或 argparse 读取
    cfg = CollectorConfig(
        year=2026,
        month=3,
        max_links=100,
        github_token="",
        gitcode_token="xXp9CZyMdrnj9gpzV7dNYFKR",
        http_timeout_sec=25,
    )
    result = collect_cve_items(cfg, delay_between_links_sec=1.0)
    items = result if isinstance(result, list) else [result]
    out_dir = REPO_ROOT / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "bulletin_sample.json"
    path.write_text(
        json.dumps([asdict(x) for x in items], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"写入 {path}，共 {len(items)} 条 CVEItem")


if __name__ == "__main__":
    main()
