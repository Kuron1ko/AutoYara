"""AutoYara 数据模型包。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .pipeline_models import (
    AutoYaraDataModel,
    DiffAnalysisResult,
    FunctionLocationResult,
    GenerationResult,
    ValidationResult,
    VulnerabilityInfo,
    from_legacy_result_dict,
    sync_function_line_arrays,
    to_legacy_result_dict,
)


@dataclass(slots=True)
class CollectorConfig:
    """爬虫输入配置：令牌、超时、公告日期与单 commit 模式等。"""

    year: int | None = None
    month: int | None = None
    end_year: int | None = None
    end_month: int | None = None
    max_links: int | None = None
    github_token: str = ""
    gitcode_token: str = ""
    http_timeout_sec: int = 20
    commit_url: str | None = None
    cve_override: str = "MANUAL"
    local_patch_path: str | None = None


@dataclass(slots=True)
class YaraValidationResult:
    """yara文件测试结果。"""

    cve_id: str
    fixed_matched: bool
    unfixed_matched: bool
    return_code: int
    message: str = ""


@dataclass(slots=True)
class CVEItem:
    """单条采集输出（同一 CVE 可能对应多条）。"""

    cve_id: str
    vulnerable_code: str
    fixed_code: str
    description: str
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
    is_complete: bool = True


CVEResult = CVEItem | list[CVEItem]

# CrawlerItem: cli.py / pipeline.py 传递的原始链接字典类型别名
CrawlerItem = dict[str, Any]

__all__ = [
    "CollectorConfig",
    "CVEItem",
    "CVEResult",
    "CrawlerItem",
    "AutoYaraDataModel",
    "DiffAnalysisResult",
    "FunctionLocationResult",
    "GenerationResult",
    "ValidationResult",
    "VulnerabilityInfo",
    "to_legacy_result_dict",
    "from_legacy_result_dict",
    "sync_function_line_arrays",
    "YaraValidationResult",
]
