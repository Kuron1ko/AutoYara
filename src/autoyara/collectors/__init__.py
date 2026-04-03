"""
OpenHarmony 安全公告 CVE 链接解析与补丁/函数提取。

其他模块请从 ``autoyara.collector`` 导入；典型用法::

    from autoyara.collector import CollectorConfig, collect_cve_items

    cfg = CollectorConfig(year=2026, month=3, max_links=10)
    items = collect_cve_items(cfg)
"""

from autoyara.models import CVEResult

from .analysis import (
    extract_function,
    fetch_source,
    fetch_vuln_description,
    get_parent_sha,
    get_upstream_commit_from_patch,
    parse_vuln_desc_from_patch_text,
)
from .diff_utils import fetch_diff_text, parse_diff_full, pick_best_pr_commit_diff
from .discovery import UPSTREAM, classify_url, fetch_bulletin, parse_all_links
from .gitcode import (
    fetch_gitcode_commit_diff,
    fetch_gitcode_file_blob,
    gitcode_private_token,
    normalize_gitcode_diff_body,
)
from .http_client import get
from .orchestrate import collect_cve_items, links_from_config
from .pipeline import process_item
from .runtime_config import apply_collector_config

__all__ = [
    "CVEResult",
    "apply_collector_config",
    "collect_cve_items",
    "links_from_config",
    "get",
    "fetch_bulletin",
    "parse_all_links",
    "classify_url",
    "UPSTREAM",
    "fetch_diff_text",
    "pick_best_pr_commit_diff",
    "parse_diff_full",
    "process_item",
    "fetch_source",
    "get_parent_sha",
    "get_upstream_commit_from_patch",
    "fetch_vuln_description",
    "parse_vuln_desc_from_patch_text",
    "extract_function",
    "gitcode_private_token",
    "normalize_gitcode_diff_body",
    "fetch_gitcode_commit_diff",
    "fetch_gitcode_file_blob",
]
