import re
from collections import defaultdict

from autoyara.models import (
    AutoYaraDataModel,
    CrawlerItem,
    DiffAnalysisResult,
    FunctionLocationResult,
    VulnerabilityInfo,
)

from .analysis import (
    derive_vulnerable,
    extract_function,
    fetch_source,
    fetch_source_upstream,
    fetch_vuln_description,
    get_parent_sha,
    get_parent_sha_upstream,
    get_upstream_commit_from_patch,
    patch_snippet,
    reconstruct_old_from_new,
)
from .diff_utils import fetch_diff_text, parse_diff_full


def process_item(item: CrawlerItem) -> list[AutoYaraDataModel]:
    url = item.get("url", "")
    if not url:
        return []
    diff, repo, fix_sha = fetch_diff_text(item)
    if not diff or not repo:
        return []
    vuln_meta = fetch_vuln_description(item, diff)
    hunks = parse_diff_full(diff)
    if not hunks:
        return []
    oh_repo = repo
    gh_owner = "openharmony"
    url_m = re.match(r"https?://(?:gitee|gitcode)\.com/([^/]+)/", url, re.I)
    if url_m and url_m.group(1) != "openharmony":
        gh_owner = url_m.group(1)
    file_hunks = defaultdict(list)
    for h in hunks:
        file_hunks[h["file"]].append(h)
    results = []
    for filepath, fhunks in file_hunks.items():
        new_src = fetch_source(oh_repo, filepath, fix_sha, gh_owner)
        parent_sha = get_parent_sha(oh_repo, fix_sha, gh_owner=gh_owner)
        old_src = (
            fetch_source(oh_repo, filepath, parent_sha, gh_owner)
            if parent_sha
            else None
        )

        upstream_sha = get_upstream_commit_from_patch(diff) if diff else None
        if upstream_sha:
            print("  [upstream] commit: " + upstream_sha[:12])
            if not old_src:
                up_parent, up_repo = get_parent_sha_upstream(upstream_sha)
                if up_parent:
                    old_src = fetch_source_upstream(
                        filepath, up_parent, up_repo or "torvalds/linux"
                    )
            if not new_src:
                new_src = fetch_source_upstream(
                    filepath, upstream_sha, "torvalds/linux"
                )
        if new_src and not old_src:
            old_src = reconstruct_old_from_new(new_src, fhunks)
            if old_src:
                print("  [reconstruct] 已从 new+diff 恢复父版本全文")
        func_hunks = defaultdict(list)
        for h in fhunks:
            func_hunks[h["function_hint"]].append(h)
        for func_hint, fh_list in func_hunks.items():
            old_start = fh_list[0]["old_start"]
            new_start = fh_list[0]["new_start"]
            fixed_func = extract_function(new_src, func_hint, new_start)
            vuln_func = extract_function(old_src, func_hint, old_start)
            if not vuln_func:
                if fixed_func:
                    print("  [derive] reversing patch...")
                    vuln_func = derive_vulnerable(fixed_func, fh_list)
                    if vuln_func:
                        print("  [derive] OK")
                if not vuln_func:
                    vuln_func = patch_snippet(fh_list, "old")
            if not fixed_func:
                fixed_func = patch_snippet(fh_list, "new")
            all_removed = [r for h in fh_list for r in h["removed"]]
            all_added = [a for h in fh_list for a in h["added"]]
            results.append(
                AutoYaraDataModel(
                    vulnerability=VulnerabilityInfo(
                        cve=item.get("cve", ""),
                        repository=oh_repo,
                        severity=item.get("severity", ""),
                        affected_version=item.get("version_label", ""),
                        title=vuln_meta.get("title", ""),
                        description=vuln_meta.get("description", ""),
                        reference_url=url,
                        cve_hint=vuln_meta.get("cve", ""),
                    ),
                    function_location=FunctionLocationResult(
                        file_path=filepath,
                        function_name=func_hint,
                        hunk_headers=[h["hunk_header"] for h in fh_list],
                        vulnerable_function=vuln_func,
                        fixed_function=fixed_func,
                    ),
                    diff_analysis=DiffAnalysisResult(
                        added_lines=all_added,
                        removed_lines=all_removed,
                        changed_files_count=1,
                        changed_hunks_count=len(fh_list),
                    ),
                )
            )
    return results
