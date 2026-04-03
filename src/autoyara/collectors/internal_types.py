"""采集流水线内部使用的结构化输入，不对外暴露。"""

from __future__ import annotations

from typing import TypedDict


class CrawlerLink(TypedDict, total=False):
    """单条公告/CLI 解析出的链接条目（原 TypedDict CrawlerItem，仅在本包内使用）。"""

    cve: str
    repo: str
    severity: str
    version_label: str
    url: str
    url_type: str
    fix_sha: str
    patch_body: str
