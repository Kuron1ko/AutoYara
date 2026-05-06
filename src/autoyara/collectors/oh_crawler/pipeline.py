import re
from collections import defaultdict

from autoyara.collectors.analysis import (
    build_versions_from_diff,
    diff_hunk_lines_embedded,
    extract_function_by_lineno,
    extract_function_for_hunks,
    parent_source_from_diff,
    realign_hunks_new_starts,
)
from autoyara.llm.quality_check import (
    QualityCheckResult,
    check_quality,
    summarize_bulletin_fields,
)
from autoyara.llm.sync_client import SyncLLMClient
from autoyara.models import (
    AutoYaraDataModel,
    CrawlerItem,
    DiffAnalysisResult,
    FunctionLocationResult,
    ValidationResult,
    VulnerabilityInfo,
)

from .analysis import (
    derive_vulnerable,
    fetch_source,
    fetch_source_upstream,
    fetch_vuln_description,
    get_parent_sha,
    get_parent_sha_upstream,
    get_upstream_commit_from_patch,
    patch_snippet,
)
from .diff_utils import fetch_diff_text, merge_version_label_from_patch, parse_diff_full
from .discovery import UPSTREAM
from .nvd_fallback import nvd_supplement, prefill_description_from_nvd


def process_item(
    item: CrawlerItem,
    *,
    quality_check: bool = False,
    llm_client: SyncLLMClient | None = None,
) -> list[AutoYaraDataModel]:
    """处理单条 CVE 链接，提取漏洞函数并构建 AutoYaraDataModel。

    推荐流程（与 GitCode 安全披露 ``2026-03.md`` 等公告一致）：
    1. 入口 URL 来自公告解析出的 commit/patch，拉取 diff 与源码，得到描述与修复前/后函数。
    2. ``quality_check=True`` 时 **第 1 轮 LLM**：审查描述与两段函数是否完整。
    3. 若任一项不完整：调用 NVD JSON API（与
       ``https://nvd.nist.gov/vuln/detail/<CVE>`` 页 References 同源）及 GitHub commit 补全。
    4. **第 2 轮 LLM（终审）**：对最终写入结果的描述与修复前/后函数再做完整性与正确性审查；
       返回的 ``validation`` 仅反映本轮结论。

    Args:
        item: 爬虫输入条目。
        quality_check: 是否启用第 1、2 轮 LLM 及第 3 步 NVD 兜底。
        llm_client: 可复用的 SyncLLMClient；为 None 且 quality_check=True 时自动创建。

    Returns:
        AutoYaraDataModel 列表；quality_check=True 时每条附带基于 **终审** 的 validation。
    """
    url = item.get("url", "")
    if not url:
        return []
    diff, oh_repo, fix_sha = fetch_diff_text(item)
    if not diff or not oh_repo:
        return []
    affected_version = merge_version_label_from_patch(item.get("version_label"), diff)
    vuln_meta = fetch_vuln_description(item, diff)
    hunks = parse_diff_full(diff)
    if not hunks:
        return []

    # url_repo: URL 中的实际仓库名（用于拉源码请求）
    # gh_owner: GitHub/Gitee 的组织名
    url_m = re.match(r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/", url, re.I)
    gh_owner = "openharmony"
    url_repo = oh_repo
    if url_m:
        if url_m.group(1) != "openharmony":
            gh_owner = url_m.group(1)
        url_repo = url_m.group(2)

    file_hunks = defaultdict(list)
    for h in hunks:
        file_hunks[h["file"]].append(h)

    _own_client = False
    if quality_check and llm_client is None:
        llm_client = SyncLLMClient()
        _own_client = True

    # 从 item 读取公告表格提供的短标签（非三方库 CVE 已有；三方库/upstream CVE 为空，后面 LLM 生成）
    _item_vuln_type = (item.get("vuln_type") or "").strip()
    _item_vuln_impact = (item.get("vuln_impact") or "").strip()
    # 标记：是否已调用 LLM 提炼过（避免同一 CVE 多函数重复调用）
    _vuln_meta_done = bool(_item_vuln_type and _item_vuln_impact)

    # 只处理代码文件，跳过文档/配置/AUTHORS等
    _CODE_EXTS = {
        ".c",
        ".h",
        ".cpp",
        ".cc",
        ".cxx",
        ".hpp",
        ".hxx",
        ".java",
        ".py",
        ".go",
        ".rs",
        ".js",
        ".ts",
        ".cs",
        ".kt",
        ".s",
        ".asm",
        ".S",
    }
    # 头文件扩展名 —— 只在没有从 .c 实现文件中拿到结果时才处理
    _HEADER_EXTS = {".h", ".hpp", ".hxx"}

    # 对文件列表排序：.c/.cpp 实现文件优先，.h 头文件放后面
    def _file_sort_key(fp: str) -> int:
        e = "." + fp.rsplit(".", 1)[-1].lower() if "." in fp else ""
        return 1 if e in _HEADER_EXTS else 0

    sorted_file_hunks = sorted(file_hunks.items(), key=lambda kv: _file_sort_key(kv[0]))

    results = []
    has_impl_results = False  # 是否已从 .c 实现文件获得有效函数
    try:
        for filepath, fhunks in sorted_file_hunks:
            ext = "." + filepath.rsplit(".", 1)[-1].lower() if "." in filepath else ""
            if ext not in _CODE_EXTS:
                print(f"  [skip] 跳过非代码文件: {filepath}")
                continue
            # 如果已经从实现文件拿到结果，跳过纯头文件（声明/include 变更）
            if ext in _HEADER_EXTS and has_impl_results:
                print(f"  [skip] 已有实现文件结果，跳过头文件: {filepath}")
                continue
            # new_src（fix 后）：先不允许 fallback 到 master，避免拿到错误版本
            new_src = fetch_source(
                url_repo, filepath, fix_sha, gh_owner, allow_upstream_fallback=False
            )
            # 若 compare diff 已确定了 PR 的 base commit，直接用它；
            # 否则用 fix_sha 的 parent（单 commit 情况）
            pr_base_sha = item.get("pr_base_sha")
            if pr_base_sha:
                parent_sha = pr_base_sha
                print(f"  [pr-base] 使用 compare base {parent_sha[:12]} 作为修复前基准")
            else:
                parent_sha = get_parent_sha(url_repo, fix_sha, gh_owner=gh_owner)
            # old_src（fix 前）：禁止 fallback 到 upstream master，避免新旧版本相同
            old_src = (
                fetch_source(
                    url_repo,
                    filepath,
                    parent_sha,
                    gh_owner,
                    allow_upstream_fallback=False,
                )
                if parent_sha
                else None
            )

            upstream_sha = get_upstream_commit_from_patch(diff) if diff else None
            if upstream_sha:
                print("  [upstream] commit: " + upstream_sha[:12])
                # 先确定上游 owner/repo（从 UPSTREAM 表查，fallback 到 torvalds/linux）
                up_info = UPSTREAM.get(oh_repo) or UPSTREAM.get(url_repo)
                if up_info:
                    up_repo_full = f"{up_info[0]}/{up_info[1]}"
                else:
                    _up_parent_tmp, _up_repo_tmp = get_parent_sha_upstream(upstream_sha)
                    up_repo_full = _up_repo_tmp or "torvalds/linux"
                up_parent, _ = get_parent_sha_upstream(upstream_sha)
                if not old_src and up_parent:
                    old_src = fetch_source_upstream(filepath, up_parent, up_repo_full)
                # new_src 优先用上游对应 commit（精确版本），而非 master，避免版本错位
                if not new_src:
                    new_src = fetch_source_upstream(
                        filepath, upstream_sha, up_repo_full
                    )
            # 最后兜底：允许 fallback 到 master（仅当上游 commit 也拿不到时）
            if not new_src:
                new_src = fetch_source(
                    url_repo, filepath, fix_sha, gh_owner, allow_upstream_fallback=True
                )

            # old_src 与 new_src 内容相同 → upstream fallback 导致版本错误，丢弃 old_src
            if old_src and new_src and old_src.strip() == new_src.strip():
                print(
                    "  [warn] old_src == new_src，内容相同，丢弃 old_src 改用逆向重建"
                )
                old_src = None

            # @@ 行号常与 fix_sha 源文件不一致，先按正文对齐 new_start 再逆向父本
            fh_use = (
                realign_hunks_new_starts(new_src, fhunks)
                if (new_src and fhunks)
                else fhunks
            )
            reconstructed: str | None = None
            if new_src and fh_use:
                reconstructed = parent_source_from_diff(new_src, fh_use)

            if new_src and not old_src and reconstructed:
                old_src = reconstructed

            old_from_diff = reconstructed

            func_hunks: dict = defaultdict(list)
            for h in fh_use:
                func_hunks[h["function_hint"]].append(h)

            for func_hint, fh_list in func_hunks.items():
                # 跳过无函数上下文的 hunk（文件头部 #include 区、全局变量区等）
                # 这类 hunk 的 function_hint 为空字符串，无法提取函数体
                if not func_hint or not func_hint.strip():
                    print(
                        f"  [skip] function_hint 为空，跳过无函数上下文的 hunk: {filepath} hunk@{fh_list[0]['new_start']}"
                    )
                    continue
                old_ref = max(h["old_start"] for h in fh_list)
                new_ref = max(h["new_start"] for h in fh_list)
                old_src_eff = old_from_diff if old_from_diff else old_src
                fixed_func = extract_function_for_hunks(
                    new_src, func_hint, new_ref, fh_list, fixed_side=True
                )
                vuln_func = (
                    extract_function_for_hunks(
                        old_src_eff, func_hint, old_ref, fh_list, fixed_side=False
                    )
                    if old_src_eff
                    else None
                )
                if (
                    fixed_func
                    and vuln_func
                    and not diff_hunk_lines_embedded(vuln_func, fixed_func, fh_list)
                ):
                    v_all, f_all = build_versions_from_diff(
                        fh_list, full_src=new_src, mode_src="new"
                    )
                    if (
                        v_all
                        and f_all
                        and not v_all.lstrip().startswith("/* patch context")
                        and diff_hunk_lines_embedded(v_all, f_all, fh_list)
                    ):
                        v2 = extract_function_for_hunks(
                            v_all, func_hint, old_ref, fh_list, fixed_side=False
                        )
                        f2 = extract_function_for_hunks(
                            f_all, func_hint, new_ref, fh_list, fixed_side=True
                        )
                        if v2 and f2:
                            vuln_func, fixed_func = v2, f2
                    if not diff_hunk_lines_embedded(
                        vuln_func or "", fixed_func or "", fh_list
                    ):
                        print(
                            f"  [warn] hunk 行未落入提取函数: {filepath} {func_hint[:48]}"
                        )
                        # 兜底：按 hunk 行号在源文件中直接找包含该行的函数（不依赖 hint 名称）
                        fixed_by_line = (
                            extract_function_by_lineno(new_src, new_ref)
                            if new_src
                            else None
                        )
                        vuln_by_line = (
                            extract_function_by_lineno(old_src_eff, old_ref)
                            if old_src_eff
                            else None
                        )
                        if (
                            fixed_by_line
                            and vuln_by_line
                            and diff_hunk_lines_embedded(
                                vuln_by_line, fixed_by_line, fh_list
                            )
                        ):
                            print(
                                f"  [recover] 按行号找到正确函数，覆盖 hint 提取结果: {filepath}@{new_ref}"
                            )
                            fixed_func = fixed_by_line
                            vuln_func = vuln_by_line
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
                description = vuln_meta.get("description", "")
                cve_id = item.get("cve", "")
                # 使用 process_item 级别缓存的短标签（避免同一 CVE 多函数重复读取/生成）
                vuln_type = _item_vuln_type
                vuln_impact = _item_vuln_impact
                # 公告表格常只有链接无正文；NVD 常有标准英文描述（与详情页 References 同源数据）
                description = prefill_description_from_nvd(cve_id, description)

                qc_first: QualityCheckResult | None = None
                qc_result: QualityCheckResult | None = None

                if quality_check and llm_client is not None:
                    qc_first = check_quality(
                        description=description,
                        vuln_type=vuln_type,
                        vuln_impact=vuln_impact,
                        vulnerable_function=vuln_func or "",
                        fixed_function=fixed_func or "",
                        cve_id=cve_id,
                        client=llm_client,
                        review_round="第1轮-爬取",
                    )

                # NVD：第 1 轮 LLM 明确判不完整，或 LLM 请求失败但爬取结果仍是补丁窗口
                if (
                    quality_check
                    and qc_first is not None
                    and not qc_first.overall_ok
                    and cve_id
                    and re.match(r"CVE-\d{4}-\d+", cve_id, re.I)
                ):
                    failed = qc_first.failed_fields()
                    if getattr(qc_first, "llm_request_failed", False):
                        _marker = "patch context - source file unavailable"
                        if _marker in (vuln_func or "") or _marker in (
                            fixed_func or ""
                        ):
                            failed = [
                                "vulnerable_function",
                                "fixed_function",
                                "description",
                            ]
                    if failed:
                        print(
                            f"  [nvd-fallback] 第1轮不完整项: {failed}，"
                            "从 NVD API / GitHub References 补全…"
                        )
                    supplement = (
                        nvd_supplement(
                            cve_id=cve_id,
                            failed_fields=failed,
                            current_description=description,
                            current_vuln_func=vuln_func or "",
                            current_fixed_func=fixed_func or "",
                        )
                        if failed
                        else {}
                    )
                    if supplement.get("description"):
                        description = supplement["description"]
                    if supplement.get("vulnerable_function"):
                        vuln_func = supplement["vulnerable_function"]
                    if supplement.get("fixed_function"):
                        fixed_func = supplement["fixed_function"]

                # 若漏洞描述/漏洞影响仍为空（公告无对应列，如三方库/upstream CVE），
                # 用 LLM 从英文描述中提炼一次，并缓存供同 CVE 其余函数复用。
                if (
                    not _vuln_meta_done
                    and (not vuln_type or not vuln_impact)
                    and description
                    and quality_check
                    and llm_client is not None
                ):
                    meta_sum = summarize_bulletin_fields(
                        description, cve_id, client=llm_client
                    )
                    if not vuln_type:
                        vuln_type = meta_sum.get("vuln_type", "")
                    if not vuln_impact:
                        vuln_impact = meta_sum.get("vuln_impact", "")
                    # 回写缓存，同 CVE 后续函数直接使用
                    _item_vuln_type = vuln_type
                    _item_vuln_impact = vuln_impact
                    _vuln_meta_done = True

                # 终审：无论是否经过 NVD，均对最终写入模型的三字段再审查一遍
                if quality_check and llm_client is not None:
                    qc_result = check_quality(
                        description=description,
                        vuln_type=vuln_type,
                        vuln_impact=vuln_impact,
                        vulnerable_function=vuln_func or "",
                        fixed_function=fixed_func or "",
                        cve_id=cve_id,
                        client=llm_client,
                        review_round="第2轮-终审",
                    )

                validation: ValidationResult | None = None
                if qc_result is not None:
                    if getattr(qc_result, "llm_request_failed", False):
                        validation = ValidationResult(
                            is_valid=False,
                            score=None,
                            passed_checks=[],
                            failed_checks=[
                                "LLM 调用失败（未评定内容，非描述/函数不合格）",
                            ],
                            details=qc_result.reason,
                        )
                    else:
                        validation = ValidationResult(
                            is_valid=qc_result.overall_ok,
                            score=qc_result.score,
                            passed_checks=qc_result.passed_fields(),
                            failed_checks=qc_result.failed_fields(),
                            details=qc_result.reason,
                        )

                results.append(
                    AutoYaraDataModel(
                        vulnerability=VulnerabilityInfo(
                            cve=cve_id,
                            repository=oh_repo,
                            severity=item.get("severity", ""),
                            affected_version=affected_version,
                            title=vuln_meta.get("title", ""),
                            description=description,  # 可能已由 NVD 兜底更新
                            reference_url=url,
                            cve_hint=vuln_meta.get("cve", ""),
                            vuln_type=vuln_type,
                            vuln_impact=vuln_impact,
                        ),
                        function_location=FunctionLocationResult(
                            file_path=filepath,
                            function_name=func_hint,
                            hunk_headers=[h["hunk_header"] for h in fh_list],
                            vulnerable_function=vuln_func,  # 可能已由 NVD 兜底更新
                            fixed_function=fixed_func,  # 可能已由 NVD 兜底更新
                        ),
                        diff_analysis=DiffAnalysisResult(
                            added_lines=all_added,
                            removed_lines=all_removed,
                            changed_files_count=1,
                            changed_hunks_count=len(fh_list),
                        ),
                        validation=validation,
                    )
                )
                # 记录实现文件已产生结果（用于后续跳过头文件）
                if ext not in _HEADER_EXTS:
                    has_impl_results = True
    finally:
        if _own_client and llm_client is not None:
            llm_client.close()

    return results
