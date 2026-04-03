from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from ..analysis import fetch_vuln_description
from ..diff_utils import fetch_diff_text, parse_diff_full
from ..internal_types import CrawlerLink


@dataclass
class DiffPipelineContext:
    """单条 CrawlerLink 在拉取 diff 并解析 hunks 之后的共享状态。"""

    item: CrawlerLink
    url: str
    diff: str
    oh_repo: str
    fix_sha: str | None
    vuln_meta: dict[str, str]
    hunks: list[dict[str, Any]]
    gh_owner: str


def gh_owner_from_item_url(url: str) -> str:
    gh_owner = "openharmony"
    url_m = re.match(r"https?://(?:gitee|gitcode)\.com/([^/]+)/", url, re.I)
    if url_m and url_m.group(1) != "openharmony":
        gh_owner = url_m.group(1)
    return gh_owner


def group_hunks_by_file(hunks: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    file_hunks = defaultdict(list)
    for h in hunks:
        file_hunks[h["file"]].append(h)
    return file_hunks


def build_diff_pipeline_context(item: CrawlerLink) -> DiffPipelineContext | None:
    url = item.get("url", "")
    if not url:
        return None
    diff, repo, fix_sha = fetch_diff_text(item)
    if not diff or not repo:
        return None
    vuln_meta: dict[str, str] = fetch_vuln_description(item, diff)
    hunks = parse_diff_full(diff)
    if not hunks:
        return None
    gh_owner = gh_owner_from_item_url(url)
    return DiffPipelineContext(
        item=item,
        url=url,
        diff=diff,
        oh_repo=repo,
        fix_sha=fix_sha,
        vuln_meta=vuln_meta,
        hunks=hunks,
        gh_owner=gh_owner,
    )
