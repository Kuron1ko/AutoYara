"""AutoYara 核心数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class VulnerabilityInfo:
    """漏洞元信息。"""

    cve: str = ""
    repository: str = ""
    severity: str = ""
    affected_version: str = ""
    title: str = ""
    description: str = ""
    reference_url: str = ""
    cve_hint: str = ""
    #: 漏洞描述（公告表格中的简短类型标签，如"LiteOS_a内存泄露漏洞"；三方库由 LLM 生成）
    vuln_type: str = ""
    #: 漏洞影响（公告表格中的简短影响说明，如"本地攻击者可造成DOS"；三方库由 LLM 生成）
    vuln_impact: str = ""


@dataclass(slots=True)
class FunctionLocationResult:
    """函数定位结果。"""

    file_path: str = ""
    function_name: str = ""
    hunk_headers: list[str] = field(default_factory=list)
    vulnerable_function: str | None = None
    fixed_function: str | None = None


@dataclass(slots=True)
class DiffAnalysisResult:
    """Diff 分析结果。"""

    added_lines: list[dict[str, Any]] = field(default_factory=list)
    removed_lines: list[dict[str, Any]] = field(default_factory=list)
    changed_files_count: int = 0
    changed_hunks_count: int = 0


@dataclass(slots=True)
class ValidationResult:
    """质量审查结果。"""

    is_valid: bool = True
    #: ``None`` 表示 LLM 未成功返回评分（如鉴权失败），非「内容得分为零」
    score: float | None = None
    passed_checks: list[str] = field(default_factory=list)
    failed_checks: list[str] = field(default_factory=list)
    details: str = ""


@dataclass(slots=True)
class GenerationResult:
    """YARA 规则生成结果。"""

    rule_text: str = ""
    rule_name: str = ""
    rule_version: str = ""
    generated_at: str = ""


@dataclass(slots=True)
class AutoYaraDataModel:
    """AutoYara 完整数据模型，贯穿采集→生成→验证全流程。"""

    vulnerability: VulnerabilityInfo = field(default_factory=VulnerabilityInfo)
    function_location: FunctionLocationResult = field(
        default_factory=FunctionLocationResult
    )
    diff_analysis: DiffAnalysisResult = field(default_factory=DiffAnalysisResult)
    validation: ValidationResult | None = None
    generation: GenerationResult | None = None


def sync_function_line_arrays(item: dict[str, Any]) -> None:
    """根据 ``vulnerable_function`` / ``fixed_function`` 字符串同步按行数组，便于在 JSON 中直接阅读代码。"""
    vf = item.get("vulnerable_function") or item.get("vulnerable_code") or ""
    ff = item.get("fixed_function") or item.get("fixed_code") or ""
    if not isinstance(vf, str):
        vf = str(vf)
    if not isinstance(ff, str):
        ff = str(ff)
    item["vulnerable_function_lines"] = vf.splitlines()
    item["fixed_function_lines"] = ff.splitlines()


def to_legacy_result_dict(m: AutoYaraDataModel) -> dict[str, Any]:
    """将 AutoYaraDataModel 转换为 cli.py / gen_report.py 所期望的扁平字典。"""
    v = m.vulnerability
    fl = m.function_location
    da = m.diff_analysis
    row: dict[str, Any] = {
        "cve": v.cve,
        "repo": v.repository,
        "severity": v.severity,
        "version": v.affected_version,
        "vuln_title": v.title,
        "vuln_description": v.description,
        "vuln_type": v.vuln_type,
        "vuln_impact": v.vuln_impact,
        "vuln_cve_hint": v.cve_hint,
        "reference_url": v.reference_url,
        "file": fl.file_path,
        "function_name": fl.function_name,
        "hunk_headers": fl.hunk_headers,
        "vulnerable_function": fl.vulnerable_function or "",
        "fixed_function": fl.fixed_function or "",
        "removed_lines": da.removed_lines,
        "added_lines": da.added_lines,
    }
    sync_function_line_arrays(row)
    return row


def from_legacy_result_dict(d: dict[str, Any]) -> AutoYaraDataModel:
    """从扁平字典反向构建 AutoYaraDataModel（兼容旧格式）。"""
    return AutoYaraDataModel(
        vulnerability=VulnerabilityInfo(
            cve=d.get("cve", d.get("cve_id", "")),
            repository=d.get("repo", d.get("repository", "")),
            severity=d.get("severity", ""),
            affected_version=d.get("version", d.get("affected_version", "")),
            title=d.get("vuln_title", d.get("title", "")),
            description=d.get("vuln_description", d.get("description", "")),
            reference_url=d.get("reference_url", ""),
            cve_hint=d.get("vuln_cve_hint", d.get("cve_hint", "")),
            vuln_type=d.get("vuln_type", ""),
            vuln_impact=d.get("vuln_impact", ""),
        ),
        function_location=FunctionLocationResult(
            file_path=d.get("file", d.get("file_path", "")),
            function_name=d.get("function_name", ""),
            hunk_headers=d.get("hunk_headers", []),
            vulnerable_function=d.get("vulnerable_function", d.get("vulnerable_code")),
            fixed_function=d.get("fixed_function", d.get("fixed_code")),
        ),
        diff_analysis=DiffAnalysisResult(
            added_lines=d.get("added_lines", []),
            removed_lines=d.get("removed_lines", []),
            changed_hunks_count=d.get("changed_hunks_count", 0),
        ),
    )
