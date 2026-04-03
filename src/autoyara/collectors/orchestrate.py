"""根据 ``CollectorConfig`` 组装待处理链接并可选地跑完整采集（供下游与 scripts 调用）。"""

import re
import time
from pathlib import Path

from autoyara.models import CollectorConfig, CVEItem, CVEResult

from .discovery import fetch_bulletin, parse_all_links
from .internal_types import CrawlerLink
from .pipeline import process_item
from .runtime_config import apply_collector_config


def _bulletin_months_spanned(
    y: int, m: int, end_y: int | None, end_m: int | None
) -> list[tuple[int, int]]:
    """从 (y,m) 到 (end_y,end_m) 的闭区间月份列表；未给结束月则仅 [(y,m)]。"""
    if end_y is None and end_m is None:
        return [(y, m)]
    if end_y is None or end_m is None:
        raise ValueError("end_year 与 end_month 须同时设置或同时省略")
    if not (2020 <= end_y <= 2030) or not (1 <= end_m <= 12):
        raise ValueError("end_year/end_month 无效")
    months: list[tuple[int, int]] = []
    cy, cm = y, m
    while (cy, cm) <= (end_y, end_m):
        months.append((cy, cm))
        cm += 1
        if cm > 12:
            cm = 1
            cy += 1
    if not months:
        raise ValueError("结束年月须不早于起始年月")
    return months


def links_from_config(config: CollectorConfig) -> list[CrawlerLink]:
    """
    由配置生成 ``process_item`` 所需的 ``CrawlerLink`` 列表。

    - 若设置了 ``commit_url``：单条 commit 模式（可选 ``local_patch_path`` 读入补丁正文）。
    - 否则：按 ``year``/``month``（及可选 ``end_year``/``end_month`` 日期范围）拉公告并
      ``parse_all_links`` 合并，再按 ``max_links`` 截断。
    """
    cu = (config.commit_url or "").strip()
    if cu:
        patch_body = None
        pf = (config.local_patch_path or "").strip()
        if pf:
            p = Path(pf)
            patch_body = p.read_text(encoding="utf-8", errors="replace")
            if "diff --git" not in patch_body:
                raise ValueError(
                    "local_patch_path 文件须为 unified diff（含 diff --git）"
                )
        clean_url = re.sub(r"[?#].*$", "", cu)
        # 支持 gitee/gitcode（直接采集） 与 github（仅做镜像 diff 拉取）
        m = re.match(
            r"https?://(?:gitee|gitcode|github)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
            clean_url,
            re.I,
        )
        if not m:
            raise ValueError(
                "commit_url 须为 gitee/gitcode/github 的 .../owner/repo/commit/<sha> 形式"
            )
        _owner, repo, sha = m.group(1), m.group(2), m.group(3)
        return [
            {
                "cve": (config.cve_override or "MANUAL").strip() or "MANUAL",
                "repo": repo,
                "severity": "",
                "version_label": "manual",
                "url": cu,
                "url_type": "commit",
                "fix_sha": sha,
                "patch_body": patch_body,
            }
        ]

    if config.year is None or config.month is None:
        raise ValueError("非 commit 模式时必须提供 year 与 month")
    y, mo = config.year, config.month
    if not (2020 <= y <= 2030):
        raise ValueError("year 须在 2020–2030")
    if not (1 <= mo <= 12):
        raise ValueError("month 须在 1–12")
    links: list[CrawlerLink] = []
    for by, bm in _bulletin_months_spanned(y, mo, config.end_year, config.end_month):
        md = fetch_bulletin(by, bm)
        if not md:
            raise RuntimeError(f"无法拉取公告: {by}-{bm:02d}")
        links.extend(parse_all_links(md))
    mx = config.max_links
    if mx is not None and mx > 0:
        links = links[:mx]
    return links


def collect_cve_items(
    config: CollectorConfig, *, delay_between_links_sec: float = 1.0
) -> CVEResult:
    """
    应用配置（令牌、超时等），解析链接并对每条链接执行 ``process_item``，汇总 ``CVEItem``。

    同一 URL 在公告里可能针对多个版本各出现一次（4.0.x / 4.1.x / 5.0.x 等），
    对 URL 去重后只处理一次，避免重复网络请求与重复条目。

    返回值：单条结果时为 ``CVEItem``，多条结果时为 ``list[CVEItem]``。
    """
    apply_collector_config(config)
    items: list[CVEItem] = []
    links = links_from_config(config)
    seen_urls: set[str] = set()
    deduped: list[CrawlerLink] = []
    for link in links:
        u = link.get("url", "")
        if u and u in seen_urls:
            continue
        if u:
            seen_urls.add(u)
        deduped.append(link)
    for i, link in enumerate(deduped):
        items.extend(process_item(link))
        if delay_between_links_sec > 0 and i + 1 < len(deduped):
            time.sleep(delay_between_links_sec)

    # 按 (cve_id, file_path, function_name, vulnerable_code前64字符) 去重
    # 同一 CVE 的同一函数可能因多个 issue 号生成多条相同记录
    seen_items: set[tuple[str, ...]] = set()
    unique: list[CVEItem] = []
    for it in items:
        key = (
            it.cve_id,
            it.file_path,
            it.function_name,
            (it.vulnerable_code or "")[:64],
        )
        if key in seen_items:
            continue
        seen_items.add(key)
        unique.append(it)
    if len(unique) == 1:
        return unique[0]
    return unique
