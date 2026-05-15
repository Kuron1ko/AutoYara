import json
import re

from ..gitee_pr import (
    fetch_gitee_pr_body,
    gitee_pull_api_url,
    parse_oh_pr_description,
    scrape_gitee_pr_head_sha,
    try_gitee_pr_unified_diff,
)
from .gitcode import (
    fetch_gitcode_commit_diff,
    fetch_gitcode_file_blob,
    fetch_gitcode_pr,
    fetch_gitcode_pr_commits,
    gitcode_private_token,
)
from .http_client import get

HUNK_RE = re.compile(r"^@@ -(\d+),\d+ \+(\d+),\d+ @@(.*)$")


def _scrape_gitcode_pr_sha(owner: str, repo: str, pr_num: str) -> list[str]:
    """无 token 时，从 GitCode PR 页面 HTML 中提取所有 commit SHA（去重保序）。

    返回列表，供调用方用 pick_best_pr_commit_diff 从中选最优 commit。
    """
    for url in [
        f"https://gitcode.com/{owner}/{repo}/pulls/{pr_num}",
        f"https://gitcode.com/{owner}/{repo}/pull/{pr_num}",
    ]:
        html = get(url, allow_html=True)
        if not html:
            continue
        # 优先取 /commit/ 路径中出现的 SHA（最可靠）
        commit_shas = list(
            dict.fromkeys(
                re.findall(rf"/{re.escape(repo)}/commit/([0-9a-f]{{40}})", html)
            )
        )
        if commit_shas:
            print(f"  [pr-scrape] 从页面找到 {len(commit_shas)} 个 commit SHA")
            return commit_shas
        # 兜底：全页 40 位 hex 串（可能含噪声，但优于没有）
        shas = list(dict.fromkeys(re.findall(r"\b([0-9a-f]{40})\b", html)))
        if shas:
            print(f"  [pr-scrape] 从页面找到候选 SHA {len(shas)} 个（宽泛匹配）")
            return shas
    return []


def _fetch_pr_shas_from_github(owner: str, repo: str, pr_num: str) -> list[str]:
    """当 GitCode 不可访问时，通过 GitHub API 抓取该仓库近期提交，
    筛选出与该 PR 相关的 commit SHA（通过提交信息中的 PR 号/IssueNo 字段识别）。

    返回 SHA 列表（可能为空）。
    """
    import time as _time

    from .analysis import _github_api_headers

    # 尝试 GitHub PR commits 直接接口（仅当 GitHub 也有同号 PR 时有效）
    for gh_owner in [owner, "openharmony"]:
        url = f"https://api.github.com/repos/{gh_owner}/{repo}/pulls/{pr_num}/commits"
        try:
            from .http_client import SESSION

            r = SESSION.get(
                url, headers=_github_api_headers(), timeout=20, verify=False
            )
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list) and data:
                    shas = [c["sha"] for c in data if c.get("sha")]
                    if shas:
                        print(f"  [gh-pr] GitHub PR {pr_num} → {len(shas)} commits")
                        return shas
        except Exception:
            pass

    # 回退：扫描仓库近期 commit 列表，找提交信息匹配该 PR 号的 SHA
    for gh_owner in [owner, "openharmony"]:
        for page in range(1, 4):
            url = f"https://api.github.com/repos/{gh_owner}/{repo}/commits"
            try:
                r = SESSION.get(
                    url,
                    headers=_github_api_headers(),
                    params={"per_page": 100, "page": page},
                    timeout=20,
                    verify=False,
                )
                if r.status_code != 200:
                    break
                data = r.json()
                if not data:
                    break
                matched = []
                for c in data:
                    msg = (c.get("commit", {}).get("message") or "").lower()
                    # 识别 OpenHarmony PR 格式：commit 消息中含 PR 号或 issue 号
                    if (
                        f"#{pr_num}" in msg
                        or f"pull/{pr_num}" in msg
                        or f"pulls/{pr_num}" in msg
                    ):
                        sha = c.get("sha")
                        if sha:
                            matched.append(sha)
                if matched:
                    print(
                        f"  [gh-search] 通过提交消息找到 {len(matched)} 个 PR-{pr_num} 相关 commit"
                    )
                    return matched
                _time.sleep(0.2)
            except Exception:
                break
    return []


def _scrape_gitcode_pr_body(owner: str, repo: str, pr_num: str) -> str:
    """无 token 时，从 GitCode PR 讨论页 HTML 中提取 PR body（OpenHarmony PR 模板内容）。"""
    from .analysis import strip_html_to_text

    for url in [
        f"https://gitcode.com/{owner}/{repo}/pulls/{pr_num}",
        f"https://gitcode.com/{owner}/{repo}/pull/{pr_num}",
    ]:
        html = get(url, allow_html=True)
        if not html:
            continue
        # 尝试找 JSON 内嵌的 body 字段（AtomGit / GitCode 常见做法）
        body_m = re.search(r'"body"\s*:\s*"((?:[^"\\]|\\.)*)"', html)
        if body_m:
            try:
                body_txt = body_m.group(1).encode().decode("unicode_escape")
                if "原因" in body_txt or "描述" in body_txt or len(body_txt) > 80:
                    print(
                        f"  [gitcode-pr] 从 HTML JSON 提取 PR body ({len(body_txt)} chars)"
                    )
                    return body_txt
            except Exception:
                pass
        # Fallback：从正文文本中抓「原因/描述」段落
        txt = strip_html_to_text(html)
        if "原因" in txt and "描述" in txt:
            print("  [gitcode-pr] 从 HTML 文本提取 PR body (scrape)")
            return txt
    return ""


_IMPL_EXTS = re.compile(r"\.(c|cpp|cc|cxx|java|py|go|rs|js|ts|cs|kt|s|asm)$", re.I)
_HEADER_EXTS_RE = re.compile(r"\.(h|hpp|hxx)$", re.I)
# 识别有函数上下文的 hunk 行（@@ -N,N +N,N @@ 函数名）
_HUNK_WITH_FUNC_RE = re.compile(r"^@@ [^@]+ @@ \S", re.M)


def _diff_score(diff_text):
    """评估补丁信息量，优先选有函数上下文且净增加代码量大的实现文件（.c/.cpp）提交。

    评分策略（大项优先级降序）：
    1. 实现文件净新增行数 ≥ 5    → +200000（安全修复通常是净增加代码，类型重命名净增为 0）
    2. 实现文件中含函数上下文 hunk → +50000/个 hunk
    3. 实现文件中有任何 hunk      → +5000/个文件
    4. 头文件中含函数上下文 hunk  → +500/个 hunk
    5. 总 hunk 数 × 200
    6. 实现文件净新增行数 × 500
    7. 总改动行数
    """
    if not diff_text:
        return -1

    score = 0
    total_changed = diff_text.count("\n+") + diff_text.count("\n-")
    score += total_changed

    current_is_impl = False
    current_is_header = False
    impl_added = 0
    impl_removed = 0
    in_hunk = False

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            m = re.search(r" b/(.+)$", line)
            if m:
                fname = m.group(1)
                current_is_impl = bool(_IMPL_EXTS.search(fname))
                current_is_header = bool(_HEADER_EXTS_RE.search(fname))
                if current_is_impl:
                    score += 5000
            in_hunk = False
        elif line.startswith("@@ "):
            has_func_ctx = bool(re.match(r"^@@ [^@]+ @@ \S", line))
            if has_func_ctx:
                if current_is_impl:
                    score += 50000
                elif current_is_header:
                    score += 500
            score += 200
            in_hunk = True
        elif in_hunk and len(line) > 1:
            if current_is_impl and line[0] == "+":
                impl_added += 1
            elif current_is_impl and line[0] == "-":
                impl_removed += 1

    net_impl_adds = impl_added - impl_removed
    # 安全修复 commit 的典型特征：净增加少量代码（3~5 行逻辑/检查/释放），而非仅做等量重命名
    # "甜点范围" 3~5：典型安全 patch（加 free/check/guard 逻辑）→ 大奖励
    # net > 5：可能是引入新工具函数或多文件重构，降低奖励避免压过"甜点"提交
    if 3 <= net_impl_adds <= 5:
        score += 200000
    elif net_impl_adds > 5:
        score += 40000  # 仍有奖励，但不压过甜点提交
    score += max(0, net_impl_adds) * 500
    return score


def pick_best_pr_commit_diff(owner, repo, candidate_shas):
    """
    针对 PR 多提交，逐个拉 diff 并按分数选"主修复提交"。
    返回 (best_diff, best_sha, all_diffs)。
    all_diffs: {sha: diff_text}，包含成功拉到 diff 的所有候选提交。
    """
    seen = set()
    best_diff, best_sha, best_score = None, None, -1
    all_diffs: dict[str, str] = {}
    for sha in candidate_shas:
        if not sha or sha in seen:
            continue
        seen.add(sha)
        diff_text = None
        for try_owner in [owner, "openharmony"]:
            for u in [
                f"https://github.com/{try_owner}/{repo}/commit/{sha}.diff",
                f"https://github.com/{try_owner}/{repo}/commit/{sha}.patch",
            ]:
                print("  [diff] " + u[:90])
                t = get(u)
                if t and "diff --git" in t:
                    diff_text = t
                    break
            if diff_text:
                break
        if not diff_text:
            diff_text = fetch_gitcode_commit_diff(owner, repo, sha)
        if not diff_text:
            continue
        all_diffs[sha] = diff_text
        sc = _diff_score(diff_text)
        print(f"  [pr-commit] sha={sha[:12]} score={sc}")
        if sc > best_score:
            best_diff, best_sha, best_score = diff_text, sha, sc
    return best_diff, best_sha, all_diffs


def fetch_diff_text(item):
    """获取 diff 文本，返回 (diff, repo, sha)。

    repo 始终取自 item["repo"]（公告里解析出的 OH 仓库名），
    不从 URL 覆盖，避免跨项目污染。sha 从 URL 解析。
    """
    url, ltype, oh_repo = item["url"], item["url_type"], item["repo"]
    pb = item.get("patch_body")
    if pb and "diff --git" in pb:
        m = re.match(
            r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
            url,
            re.I,
        )
        sha = item.get("fix_sha")
        if m:
            sha = m.group(3)
        print(f"  [diff] 本地 patch {len(pb.strip())} bytes")
        return pb.strip(), oh_repo, sha
    if ltype == "commit":
        m = re.match(
            r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
            url,
            re.I,
        )
        if not m:
            return None, oh_repo, None
        owner, url_repo, sha = m.group(1), m.group(2), m.group(3)
        # url_repo 仅用于拼接 GitHub/GitCode 请求路径，不替换 oh_repo
        for try_owner in ["openharmony", owner]:
            for u in [
                f"https://github.com/{try_owner}/{url_repo}/commit/{sha}.patch",
                f"https://github.com/{try_owner}/{url_repo}/commit/{sha}.diff",
            ]:
                print("  [diff] " + u[:90])
                t = get(u)
                if t and "diff --git" in t:
                    print(f"  [OK] {len(t)} bytes")
                    return t, oh_repo, sha
        if owner and url_repo and sha:
            gd = fetch_gitcode_commit_diff(owner, url_repo, sha)
            if gd:
                return gd, oh_repo, sha
            if "gitcode.com" in url.lower() and not gitcode_private_token():
                print(
                    "  [hint] GitCode 提交需设置环境变量 GITCODE_PRIVATE_TOKEN 后重试，或使用 --patch 指定本地 .diff/.patch"
                )
        return None, oh_repo, sha
    if ltype == "patch":
        m = re.match(
            r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/blob/([0-9a-f]+)/(.+)",
            url,
            re.I,
        )
        if not m:
            return None, oh_repo, None
        owner, url_repo, sha, fpath = m.group(1), m.group(2), m.group(3), m.group(4)
        for u in [
            f"https://github.com/openharmony/{url_repo}/raw/{sha}/{fpath}",
            f"https://raw.githubusercontent.com/openharmony/{url_repo}/{sha}/{fpath}",
        ]:
            print("  [patch] " + u[:90])
            t = get(u)
            if t and ("diff --git" in t or "@@" in t):
                print(f"  [OK] {len(t)} bytes")
                return t, oh_repo, sha
        # OH 仓库往往不在 GitHub raw 上；改走 GitCode raw（匿名可试）与 contents API
        gc_raw = f"https://gitcode.com/{owner}/{url_repo}/raw/{sha}/{fpath}"
        print("  [patch] " + gc_raw[:90])
        t = get(gc_raw)
        if t and ("diff --git" in t or "@@" in t):
            print(f"  [OK] gitcode raw {len(t)} bytes")
            return t.strip(), oh_repo, sha
        t_blob = fetch_gitcode_file_blob(owner, url_repo, sha, fpath)
        if t_blob and ("diff --git" in t_blob or "@@" in t_blob):
            print(f"  [OK] gitcode API contents {len(t_blob)} bytes")
            return t_blob.strip(), oh_repo, sha
        return None, oh_repo, sha
    if ltype == "pr":
        m = re.match(
            r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/(?:pulls|pull|merge_requests)/(\d+)",
            url,
            re.I,
        )
        if not m:
            return None, oh_repo, None
        owner, url_repo, num = m.group(1), m.group(2), m.group(3)
        sha = None
        candidate_shas = []
        # Gitee：优先匿名拉 PR 统一 .diff（不走 Open API，避免批量任务触发 403 Rate Limit）
        if "gitee.com" in url.lower():
            # 顺便抓 PR body（含「原因/描述」结构化字段），供后续描述提取使用
            pr_body = fetch_gitee_pr_body(owner, url_repo, num)
            if pr_body:
                item["pr_body"] = pr_body
                item["pr_description_parsed"] = parse_oh_pr_description(pr_body)
                print(f"  [gitee-pr] 获取到 PR body ({len(pr_body)} chars)")
            tdiff = try_gitee_pr_unified_diff(owner, url_repo, num)
            if tdiff:
                sha_hint = scrape_gitee_pr_head_sha(owner, url_repo, num)
                return tdiff, oh_repo, sha_hint
        if "gitcode.com" in url.lower() and gitcode_private_token():
            pr = fetch_gitcode_pr(owner, url_repo, num)
            if isinstance(pr, dict):
                # 提取 GitCode PR body（同样包含 OpenHarmony PR 模板）
                gc_body = (pr.get("body") or "").strip()
                if gc_body:
                    item["pr_body"] = gc_body
                    item["pr_description_parsed"] = parse_oh_pr_description(gc_body)
                    print(f"  [gitcode-pr] 获取到 PR body ({len(gc_body)} chars)")
                sha = (
                    pr.get("merge_commit_sha")
                    or pr.get("merge_commit_id")
                    or pr.get("merge_commit")
                    or pr.get("merge_commit_sha".upper())
                )
                if isinstance(sha, dict):
                    sha = sha.get("sha") or sha.get("id")
                if sha:
                    candidate_shas.append(sha)
            if not sha:
                commits = fetch_gitcode_pr_commits(owner, url_repo, num)
                if isinstance(commits, list) and commits:
                    for c in commits:
                        s = c.get("sha") or c.get("id")
                        if s:
                            candidate_shas.append(s)
                    last = commits[-1]
                    sha = last.get("sha") or last.get("id")
        for api_owner in [owner, "openharmony"]:
            t = get(gitee_pull_api_url(api_owner, url_repo, num))
            if t:
                try:
                    gitee_sha = json.loads(t).get("merge_commit_sha")
                    # 不覆盖已从 GitCode 获取到的有效 sha
                    if gitee_sha:
                        sha = sha or gitee_sha
                        candidate_shas.append(gitee_sha)
                        break
                except Exception:
                    pass
        if not sha:
            if "gitcode.com" in url.lower() and not gitcode_private_token():
                print("  [hint] GitCode PR 无 token，优先尝试 PR 统一 diff...")
                # ── 优先：PR 统一 diff（合并所有 commit 的完整变化，最准确）──
                for suf in (f"pull/{num}.diff", f"pulls/{num}.diff"):
                    pu = f"https://gitcode.com/{owner}/{url_repo}/{suf}"
                    print("  [pr-unified] " + pu[:100])
                    t = get(pu)
                    if t and "diff --git" in t:
                        print(
                            f"  [OK] PR unified diff {len(t)} bytes（合并所有 commit）"
                        )
                        # 同时抓 PR body 描述
                        if not item.get("pr_body"):
                            gc_body = _scrape_gitcode_pr_body(owner, url_repo, num)
                            if gc_body:
                                item["pr_body"] = gc_body
                                item["pr_description_parsed"] = parse_oh_pr_description(
                                    gc_body
                                )
                        # 用最后一个 commit SHA 作为 fix_sha（用于拉取 fix 后源码）
                        scraped_shas = _scrape_gitcode_pr_sha(owner, url_repo, num)
                        head_sha = scraped_shas[-1] if scraped_shas else None
                        return t.strip(), oh_repo, head_sha
                # ── 兜底：逐 commit 比较（PR unified diff 不可访问时使用）──
                scraped_shas = _scrape_gitcode_pr_sha(owner, url_repo, num)
                if not scraped_shas:
                    # GitCode SPA 无法抓 SHA，改走 GitHub PR/搜索 API
                    scraped_shas = _fetch_pr_shas_from_github(owner, url_repo, num)
                for s in scraped_shas:
                    if s not in candidate_shas:
                        candidate_shas.append(s)
                if scraped_shas:
                    sha = scraped_shas[-1]
                # 同时抓 PR body 描述（如果还没有）
                if not item.get("pr_body"):
                    gc_body = _scrape_gitcode_pr_body(owner, url_repo, num)
                    if gc_body:
                        item["pr_body"] = gc_body
                        item["pr_description_parsed"] = parse_oh_pr_description(gc_body)
            if not sha:
                return None, oh_repo, None
        if sha and sha not in candidate_shas:
            candidate_shas.append(sha)
        best_diff, best_sha, all_diffs = pick_best_pr_commit_diff(
            owner, url_repo, candidate_shas
        )
        if best_diff and best_sha:
            print(
                f"  [pr-commit] choose sha={best_sha[:12]} from {len(candidate_shas)} candidates"
            )
            # ── 尝试 GitHub compare diff：拓扑排序找 PR 首/尾 commit ──
            # 目标：获得整个 PR（所有 commit）的合并 diff，而不仅限于单 commit
            from .analysis import get_parent_sha as _get_parent_sha_local

            # 对成功拉到 diff 的所有候选 SHA 进行拓扑排序
            fetched_shas = list(all_diffs.keys())
            sha_parent: dict[str, str | None] = {}
            for s in fetched_shas:
                p = _get_parent_sha_local(url_repo, s, gh_owner=owner)
                if not p:
                    p = _get_parent_sha_local(url_repo, s, gh_owner="openharmony")
                sha_parent[s] = p

            fetched_set = set(fetched_shas)
            # PR HEAD = 没有被任何其他 PR commit 当作 parent 的那个
            parent_vals = set(sha_parent.values()) - {None}
            pr_head_candidates = [s for s in fetched_shas if s not in parent_vals]
            # PR FIRST = 其 parent 不在 PR commit 集合里的那个
            pr_first_candidates = [
                s for s in fetched_shas if sha_parent.get(s) not in fetched_set
            ]
            pr_head_sha = pr_head_candidates[0] if pr_head_candidates else best_sha
            pr_first_sha = pr_first_candidates[0] if pr_first_candidates else best_sha
            base_sha = sha_parent.get(pr_first_sha)
            if not base_sha:
                # fallback: parent of best commit
                base_sha = sha_parent.get(best_sha)

            print(
                f"  [pr-topo] first={pr_first_sha[:12]} head={pr_head_sha[:12]} "
                f"base={(base_sha or 'None')[:12]}"
            )

            if base_sha and pr_head_sha and base_sha != pr_head_sha:
                for try_owner in [owner, "openharmony"]:
                    compare_url = (
                        f"https://github.com/{try_owner}/{url_repo}"
                        f"/compare/{base_sha}...{pr_head_sha}.diff"
                    )
                    print(f"  [pr-compare] {compare_url[:100]}")
                    cmp_diff = get(compare_url)
                    if cmp_diff and "diff --git" in cmp_diff:
                        print(
                            f"  [OK] compare diff {len(cmp_diff)} bytes "
                            f"({base_sha[:8]}...{pr_head_sha[:8]})"
                        )
                        item["pr_base_sha"] = base_sha
                        item["pr_head_sha"] = pr_head_sha
                        return cmp_diff.strip(), oh_repo, pr_head_sha
            # compare diff 不可用，使用单 commit diff
            return best_diff, oh_repo, best_sha
        # 兜底：GitCode / Gitee PR 统一 diff 直链（不依赖 merge SHA 解析）
        for host in (
            f"https://gitcode.com/{owner}/{url_repo}",
            f"https://gitee.com/{owner}/{url_repo}",
        ):
            for suf in (
                f"pulls/{num}.diff",
                f"pull/{num}.diff",
                f"merge_requests/{num}.diff",
            ):
                pu = f"{host}/{suf}"
                print("  [pr] " + pu[:100])
                t = get(pu)
                if t and "diff --git" in t:
                    print(f"  [OK] PR unified diff {len(t)} bytes")
                    sha_fb = sha
                    if not sha_fb and "gitee.com" in host:
                        sha_fb = scrape_gitee_pr_head_sha(owner, url_repo, num)
                    return t.strip(), oh_repo, sha_fb
        return None, oh_repo, sha
    return None, oh_repo, None


def merge_version_label_from_patch(existing: str | None, diff_text: str | None) -> str:
    """从补丁/PR diff 正文中提取 OpenHarmony 常见版本号（如 ``6.0.x``、``5.1.0.x``），与公告列合并。"""
    ex = (existing or "").strip()
    if not diff_text:
        return ex
    triple_x = re.findall(r"\b\d+\.\d+\.\d+\.x\b", diff_text)
    double_x = re.findall(r"\b\d+\.\d+\.x\b", diff_text)
    found: list[str] = []
    seen: set[str] = set()
    for p in triple_x + double_x:
        if p not in seen:
            seen.add(p)
            found.append(p)
    if not found:
        return ex
    parts = [x.strip() for x in re.split(r"[/;、，]", ex) if x.strip()]
    for v in found:
        if v not in parts:
            parts.append(v)
    return " / ".join(parts)


def parse_diff_full(diff):
    results = []
    cur_file = ""
    for sec in re.split(r"^diff --git ", diff, flags=re.M):
        if not sec.strip():
            continue
        fm = re.match(r"a/(\S+)\s+b/(\S+)", sec)
        if fm:
            cur_file = fm.group(2)
        for hm in re.finditer(
            r"(@@ [^\n]+@@[^\n]*\n)((?:[+\- \\][^\n]*\n?)*)", sec, re.M
        ):
            hdr = hm.group(1).rstrip()
            body = hm.group(2)
            m = HUNK_RE.match(hdr.strip())
            if not m:
                continue
            old_s, new_s = int(m.group(1)), int(m.group(2))
            func = m.group(3).strip()
            added, removed, ctx = [], [], []
            ol, nl = old_s, new_s
            for raw in body.splitlines():
                if raw.startswith("\\"):
                    # "\ No newline at end of file" 等元数据行，跳过
                    continue
                if raw.startswith("+"):
                    added.append({"lineno": nl, "code": raw[1:]})
                    nl += 1
                elif raw.startswith("-"):
                    removed.append({"lineno": ol, "code": raw[1:]})
                    ol += 1
                else:
                    code = raw[1:] if raw.startswith(" ") else raw
                    ctx.append({"old": ol, "new": nl, "code": code})
                    ol += 1
                    nl += 1
            results.append(
                {
                    "file": cur_file,
                    "function_hint": func,
                    "hunk_header": hdr.strip(),
                    "old_start": old_s,
                    "new_start": new_s,
                    "added": added,
                    "removed": removed,
                    "context": ctx,
                    "body": body,
                }
            )
    return results
