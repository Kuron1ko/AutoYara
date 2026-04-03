from __future__ import annotations

from autoyara.models import CVEItem

from ..internal_types import CrawlerLink
from .context import build_diff_pipeline_context, group_hunks_by_file
from .file_workflow import process_file_hunks


def process_item(item: CrawlerLink) -> list[CVEItem]:
    ctx = build_diff_pipeline_context(item)
    if not ctx:
        return []
    results: list[CVEItem] = []
    for filepath, fhunks in group_hunks_by_file(ctx.hunks).items():
        results.extend(process_file_hunks(ctx, filepath, fhunks))
    return results
