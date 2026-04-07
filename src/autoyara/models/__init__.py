"""对外数据模型：仅此两个类；其余结构见 ``autoyara.collectors`` 内部定义（如 ``CrawlerLink``）。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class CollectorConfig:
    """爬虫输入配置：令牌、超时、公告日期与单 commit 模式等。"""

    # --- 公告日期：单月 ---
    # 起始年月（OpenHarmony security-disclosure Markdown，与 commit_url 二选一）
    year: int | None = None
    month: int | None = None
    # 结束年月（含）；若均为 None，则只拉取 year/month 所在单月；若设置须 >= 起始年月
    end_year: int | None = None
    end_month: int | None = None
    # 合并多个月公告后，最多保留的链接条数（None 不截断）
    max_links: int | None = None
    # --- API 令牌（非空时由 apply_collector_config 写入环境变量）---
    github_token: str = ""
    gitcode_token: str = ""
    http_timeout_sec: int = 20
    # --- 单条 commit（与公告模式二选一）---
    commit_url: str | None = None
    cve_override: str = "MANUAL"
    local_patch_path: str | None = None


@dataclass(slots=True)
class CVEItem:
    """单条采集输出（同一 CVE 可能对应多条）。"""

    # 必填语义字段
    cve_id: str
    vulnerable_code: str
    fixed_code: str
    description: str
    # 其它常用元数据
    title: str = ""
    repository: str = ""
    file_path: str = ""
    function_name: str = ""
    severity: str = ""
    affected_version: str = ""
    reference_url: str = ""
    cve_hint: str = ""
    hunk_headers: list[str] = field(default_factory=list)
    added_lines: list[dict[str, Any]] = field(default_factory=list)
    removed_lines: list[dict[str, Any]] = field(default_factory=list)
    changed_hunks_count: int = 0
    # True = 成功从完整源文件提取出两个不同版本的函数体
    # False = 源文件不可用，代码内容仅来自 diff 上下文窗口
    is_complete: bool = True

# YARA规则验证结果
@dataclass(slots=True)
class ValidationResult:
    """YARA规则验证结果模型。"""
    cve_id: str
    # fixed文件是否正确（通过则正确）
    fixed_matched: bool
    # unfixed文件是否正确（不通过则正确）
    unfixed_matched: bool
    return_code: int
    # 0: 均正确
    # 1: 仅有fixed正确
    # 2: 仅有unfixed正确
    # 3: 均不正确
    message: str = ""


# 采集器对外输出的统一类型别名：单条或多条 CVEItem
CVEResult = CVEItem | list[CVEItem]

__all__ = ["CollectorConfig", "CVEItem", "CVEResult","ValidationResult"]
