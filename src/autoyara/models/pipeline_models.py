"""统一数据结构定义。

该文件用于约束采集、分析、特征提取、验证、生成等阶段的数据传递，
避免模块之间直接传递零散字典。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class CandidateType(str, Enum):
    """特征候选类型。"""

    STRING = "string"
    HEX = "hex"
    REGEX = "regex"
    BEHAVIOR = "behavior"
    OTHER = "other"


@dataclass(slots=True)
class VulnerabilityInfo:
    """漏洞信息。"""

    cve: str
    repository: str
    severity: str = ""
    affected_version: str = ""
    title: str = ""
    description: str = ""
    reference_url: str = ""
    cve_hint: str = ""


@dataclass(slots=True)
class FunctionLocationResult:
    """函数定位结果。"""

    file_path: str
    function_name: str = ""
    hunk_headers: list[str] = field(default_factory=list)
    vulnerable_function: str = ""
    fixed_function: str = ""


@dataclass(slots=True)
class DiffAnalysisResult:
    """差异分析结果。"""

    added_lines: list[dict[str, Any]] = field(default_factory=list)
    removed_lines: list[dict[str, Any]] = field(default_factory=list)
    changed_files_count: int = 0
    changed_hunks_count: int = 0
    risk_notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FeatureCandidate:
    """特征候选。"""

    candidate_id: str
    candidate_type: CandidateType
    content: str
    source: str = ""
    confidence: float = 0.0
    reason: str = ""


@dataclass(slots=True)
class ValidationResult:
    """验证结果。"""

    is_valid: bool
    score: float = 0.0
    passed_checks: list[str] = field(default_factory=list)
    failed_checks: list[str] = field(default_factory=list)
    details: str = ""


@dataclass(slots=True)
class GenerationResult:
    """生成结果。"""

    generated: bool
    rule_name: str = ""
    rule_text: str = ""
    target_family: str = ""
    generator: str = ""
    notes: str = ""


@dataclass(slots=True)
class AutoYaraDataModel:
    """统一数据模型（贯穿漏洞到规则生成全流程）。"""

    vulnerability: VulnerabilityInfo
    function_location: FunctionLocationResult
    diff_analysis: DiffAnalysisResult
    feature_candidates: list[FeatureCandidate] = field(default_factory=list)
    validation: ValidationResult | None = None
    generation: GenerationResult | None = None

    def to_dict(self) -> dict[str, Any]:
        """转换为字典，便于序列化或持久化。"""
        return asdict(self)


def to_legacy_result_dict(model: AutoYaraDataModel) -> dict[str, Any]:
    """将统一模型转换为旧版结果字典，便于兼容历史调用方。"""
    return {
        "cve": model.vulnerability.cve,
        "repo": model.vulnerability.repository,
        "severity": model.vulnerability.severity,
        "version": model.vulnerability.affected_version,
        "file": model.function_location.file_path,
        "function_name": model.function_location.function_name,
        "hunk_headers": model.function_location.hunk_headers,
        "removed_lines": model.diff_analysis.removed_lines,
        "added_lines": model.diff_analysis.added_lines,
        "vuln_title": model.vulnerability.title,
        "vuln_description": model.vulnerability.description,
        "vuln_cve_hint": model.vulnerability.cve_hint,
        "vulnerable_function": model.function_location.vulnerable_function,
        "fixed_function": model.function_location.fixed_function,
    }


def from_legacy_result_dict(data: Mapping[str, Any]) -> AutoYaraDataModel:
    """将旧版结果字典转换为统一模型。"""
    return AutoYaraDataModel(
        vulnerability=VulnerabilityInfo(
            cve=str(data.get("cve", "")),
            repository=str(data.get("repo", "")),
            severity=str(data.get("severity", "")),
            affected_version=str(data.get("version", "")),
            title=str(data.get("vuln_title", "")),
            description=str(data.get("vuln_description", "")),
            cve_hint=str(data.get("vuln_cve_hint", "")),
        ),
        function_location=FunctionLocationResult(
            file_path=str(data.get("file", "")),
            function_name=str(data.get("function_name", "")),
            hunk_headers=list(data.get("hunk_headers", [])),
            vulnerable_function=str(data.get("vulnerable_function", "")),
            fixed_function=str(data.get("fixed_function", "")),
        ),
        diff_analysis=DiffAnalysisResult(
            removed_lines=list(data.get("removed_lines", [])),
            added_lines=list(data.get("added_lines", [])),
            changed_files_count=1,
            changed_hunks_count=len(list(data.get("hunk_headers", []))),
        ),
    )
