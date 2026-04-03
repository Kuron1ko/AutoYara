import json
import re
from typing import Any

from .gitcode import (
    fetch_gitcode_commit_diff,
    fetch_gitcode_pr,
    fetch_gitcode_pr_commits,
    gitcode_private_token,
)
from .http_client import get
from .internal_types import CrawlerLink

HUNK_RE = re.compile(r"^@@ -(\d+),\d+ \+(\d+),\d+ @@(.*)$")
_SHA_RE = re.compile(r"\b([0-9a-f]{40})\b")


def _sha_from_gitcode_pr_html(owner: str, repo: str, num: str) -> str | None:
    """从 GitCode PR 页面 HTML 中提取 merge commit SHA（匿名可访问的公开仓库）。

    GitCode PR 页面会在 <meta>、data 属性或 JSON 内嵌中出现完整 40 位 SHA。
    取出现次数最多的那个（merge commit 通常被多处引用）。
    """
    from .http_client import HTTP_TIMEOUT_SEC, SESSION

    for url in [
        f"https://gitcode.com/{owner}/{repo}/pulls/{num}",
        f"https://gitcode.com/{owner}/{repo}/merge_requests/{num}",
    ]:
        try:
            r = SESSION.get(
                url,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
                timeout=HTTP_TIMEOUT_SEC,
                verify=False,
            )
            if r.status_code != 200:
                continue
            text = r.content.decode("utf-8", errors="replace")
        except Exception:
            continue
        # 统计所有 40 位 SHA 出现次数，取最高频的（merge commit 会被多处引用）
        counts: dict[str, int] = {}
        for s in _SHA_RE.findall(text):
            counts[s] = counts.get(s, 0) + 1
        if counts:
            best = max(counts, key=lambda k: counts[k])
            if counts[best] >= 2:
                print(
                    f"  [pr-html] GitCode merge sha={best[:12]} (freq={counts[best]})"
                )
                return best
    return None


def _diff_score(diff_text):
    """粗略评估补丁信息量，优先选真正修复提交而不是“修复错误”小提交。"""
    if not diff_text:
        return -1
    hunks = diff_text.count("\n@@ ")
    files = diff_text.count("\ndiff --git ")
    changed = diff_text.count("\n+") + diff_text.count("\n-")
    return files * 10000 + hunks * 200 + changed


def pick_best_pr_commit_diff(owner, repo, candidate_shas):
    """
    针对 PR 多提交，逐个拉 diff 并按分数选“主修复提交”。
    返回 (best_diff, best_sha)。
    """
    seen = set()
    best_diff, best_sha, best_score = None, None, -1
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
        sc = _diff_score(diff_text)
        print(f"  [pr-commit] sha={sha[:12]} score={sc}")
        if sc > best_score:
            best_diff, best_sha, best_score = diff_text, sha, sc
    return best_diff, best_sha


def fetch_diff_text(item: CrawlerLink):
    url, ltype, oh_repo = item["url"], item["url_type"], item["repo"]
    pb = item.get("patch_body")
    if pb and "diff --git" in pb:
        m = re.match(
            r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
            url,
            re.I,
        )
        repo, sha = oh_repo, item.get("fix_sha")
        if m:
            repo = m.group(2)
            sha = m.group(3)
        print(f"  [diff] 本地 patch {len(pb.strip())} bytes")
        return pb.strip(), repo, sha
    if ltype == "commit":
        # 支持 gitee/gitcode/github commit URL
        m = re.match(
            r"https?://(?:gitee|gitcode|github)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
            url,
            re.I,
        )
        if not m:
            return None, oh_repo, None
        owner, repo, sha = m.group(1), m.group(2), m.group(3)
        is_github_url = "github.com" in url.lower()
        # 对 github URL，直接尝试 openharmony 镜像与原 owner；对 gitee/gitcode 也先走 github 镜像
        try_owners = [owner, "openharmony"] if is_github_url else ["openharmony", owner]
        for try_owner in try_owners:
            for u in [
                f"https://github.com/{try_owner}/{repo}/commit/{sha}.patch",
                f"https://github.com/{try_owner}/{repo}/commit/{sha}.diff",
            ]:
                print("  [diff] " + u[:90])
                t = get(u)
                if t and "diff --git" in t:
                    print(f"  [OK] {len(t)} bytes")
                    return t, repo, sha
        if not is_github_url and owner and repo and sha:
            gd = fetch_gitcode_commit_diff(owner, repo, sha)
            if gd:
                return gd, repo, sha
            if "gitcode.com" in url.lower() and not gitcode_private_token():
                print(
                    "  [hint] GitCode 提交需设置环境变量 GITCODE_PRIVATE_TOKEN 后重试，或使用 --patch 指定本地 .diff/.patch"
                )
        return None, repo, sha
    if ltype == "patch":
        m = re.match(
            r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/blob/([0-9a-f]+)/(.+)",
            url,
            re.I,
        )
        if not m:
            return None, oh_repo, None
        owner, repo, sha, fpath = m.group(1), m.group(2), m.group(3), m.group(4)
        for u in [
            f"https://github.com/openharmony/{repo}/raw/{sha}/{fpath}",
            f"https://raw.githubusercontent.com/openharmony/{repo}/{sha}/{fpath}",
        ]:
            print("  [patch] " + u[:90])
            t = get(u)
            if t and ("diff --git" in t or "@@" in t):
                print(f"  [OK] {len(t)} bytes")
                return t, repo, sha
        return None, repo, sha
    if ltype == "pr":
        m = re.match(
            r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/(?:pulls|pull|merge_requests)/(\d+)",
            url,
            re.I,
        )
        if not m:
            return None, oh_repo, None
        owner, repo, num = m.group(1), m.group(2), m.group(3)
        sha = None
        candidate_shas = []
        is_gitcode = "gitcode.com" in url.lower()

        if is_gitcode:
            # 1. 有 token 时走 GitCode PR API 取 merge commit
            if gitcode_private_token():
                pr = fetch_gitcode_pr(owner, repo, num)
                if isinstance(pr, dict):
                    sha = (
                        pr.get("merge_commit_sha")
                        or pr.get("merge_commit_id")
                        or pr.get("merge_commit")
                        or pr.get("MERGE_COMMIT_SHA")
                    )
                    if isinstance(sha, dict):
                        sha = sha.get("sha") or sha.get("id")
                    if sha:
                        candidate_shas.append(sha)
            # 2. 无 token / 无 merge SHA：尝试匿名获取 PR commits 列表（公开仓库可用）
            if not sha:
                commits = fetch_gitcode_pr_commits(owner, repo, num)
                if isinstance(commits, list) and commits:
                    for c in commits:
                        s = c.get("sha") or c.get("id")
                        if s:
                            candidate_shas.append(s)
                    last = commits[-1]
                    sha = last.get("sha") or last.get("id")
            # 3. 仍无结果：解析 GitCode PR HTML 页面抓 merge commit
            if not sha:
                sha = _sha_from_gitcode_pr_html(owner, repo, num)
                if sha:
                    candidate_shas.append(sha)

        # 4. Gitee 镜像 API（openharmony 仓库在 gitee 也有镜像）
        for api_owner in [owner, "openharmony"]:
            t = get(f"https://gitee.com/api/v5/repos/{api_owner}/{repo}/pulls/{num}")
            if t:
                try:
                    s = json.loads(t).get("merge_commit_sha")
                    if s:
                        candidate_shas.append(s)
                        if not sha:
                            sha = s
                        break
                except Exception:
                    pass

        if not sha:
            if is_gitcode and not gitcode_private_token():
                print(
                    "  [hint] GitCode PR 无法获取 commit，"
                    "可设置 GITCODE_PRIVATE_TOKEN 提升成功率"
                )
            return None, repo, None
        if sha and sha not in candidate_shas:
            candidate_shas.append(sha)
        best_diff, best_sha = pick_best_pr_commit_diff(owner, repo, candidate_shas)
        if best_diff and best_sha:
            print(
                f"  [pr-commit] choose sha={best_sha[:12]} from {len(candidate_shas)} candidates"
            )
            return best_diff, repo, best_sha
        return None, repo, sha
    return None, oh_repo, None


def parse_diff_full(diff: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
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
