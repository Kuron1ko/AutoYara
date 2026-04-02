"""
OpenHarmony 安全公告 CVE 链接解析与补丁/函数提取。

下游推荐用法::

    from oh_crawler import fetch_bulletin, parse_all_links, process_item

    md = fetch_bulletin(2026, 3)
    items = parse_all_links(md)
    rows = process_item(items[0])
"""

from .analysis import (
    extract_function,
    fetch_source,
    fetch_vuln_description,
    get_parent_sha,
    get_upstream_commit_from_patch,
    parse_vuln_desc_from_patch_text,
)
from .cli import main, print_result
from .diff_utils import fetch_diff_text, parse_diff_full, pick_best_pr_commit_diff
from .discovery import UPSTREAM, classify_url, fetch_bulletin, parse_all_links
from .gitcode import (
    fetch_gitcode_commit_diff,
    fetch_gitcode_file_blob,
    gitcode_private_token,
    normalize_gitcode_diff_body,
)
from .http_client import get
from .pipeline import process_item

__all__ = [
    "main",
    "get",
    "fetch_bulletin",
    "parse_all_links",
    "classify_url",
    "UPSTREAM",
    "fetch_diff_text",
    "pick_best_pr_commit_diff",
    "parse_diff_full",
    "process_item",
    "print_result",
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
