"""AutoYara 对外公共 API。"""

from .collectors import (
    classify_url,
    extract_function,
    fetch_bulletin,
    fetch_diff_text,
    parse_all_links,
    parse_diff_full,
    process_item,
)
from .models import (
    AutoYaraDataModel,
    CandidateType,
    CrawlerItem,
    DiffAnalysisResult,
    FeatureCandidate,
    FunctionLocationResult,
    GenerationResult,
    ValidationResult,
    VulnerabilityInfo,
    from_legacy_result_dict,
    to_legacy_result_dict,
)

__all__ = [
    "fetch_bulletin",
    "parse_all_links",
    "classify_url",
    "fetch_diff_text",
    "parse_diff_full",
    "extract_function",
    "process_item",
    "CrawlerItem",
    "AutoYaraDataModel",
    "VulnerabilityInfo",
    "FunctionLocationResult",
    "DiffAnalysisResult",
    "FeatureCandidate",
    "CandidateType",
    "ValidationResult",
    "GenerationResult",
    "to_legacy_result_dict",
    "from_legacy_result_dict",
]
