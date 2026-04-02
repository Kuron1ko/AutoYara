"""公共数据接口定义。"""

from __future__ import annotations

from typing import TypedDict


class CrawlerItem(TypedDict, total=False):
    """爬虫流程输入条目接口。"""

    cve: str
    repo: str
    severity: str
    version_label: str
    url: str
    url_type: str
    fix_sha: str
    patch_body: str
