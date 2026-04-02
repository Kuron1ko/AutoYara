import json
import re

from .gitcode import (
    fetch_gitcode_commit_diff,
    fetch_gitcode_pr,
    fetch_gitcode_pr_commits,
    gitcode_private_token,
)
from .http_client import get

HUNK_RE = re.compile(r"^@@ -(\d+),\d+ \+(\d+),\d+ @@(.*)$")


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


def fetch_diff_text(item):
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
        m = re.match(
            r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
            url,
            re.I,
        )
        if not m:
            return None, oh_repo, None
        owner, repo, sha = m.group(1), m.group(2), m.group(3)
        for try_owner in ["openharmony", owner]:
            for u in [
                f"https://github.com/{try_owner}/{repo}/commit/{sha}.patch",
                f"https://github.com/{try_owner}/{repo}/commit/{sha}.diff",
            ]:
                print("  [diff] " + u[:90])
                t = get(u)
                if t and "diff --git" in t:
                    print(f"  [OK] {len(t)} bytes")
                    return t, repo, sha
        if owner and repo and sha:
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
        if "gitcode.com" in url.lower() and gitcode_private_token():
            pr = fetch_gitcode_pr(owner, repo, num)
            if isinstance(pr, dict):
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
                commits = fetch_gitcode_pr_commits(owner, repo, num)
                if isinstance(commits, list) and commits:
                    for c in commits:
                        s = c.get("sha") or c.get("id")
                        if s:
                            candidate_shas.append(s)
                    last = commits[-1]
                    sha = last.get("sha") or last.get("id")
        for api_owner in [owner, "openharmony"]:
            t = get(f"https://gitee.com/api/v5/repos/{api_owner}/{repo}/pulls/{num}")
            if t:
                try:
                    sha = json.loads(t).get("merge_commit_sha")
                    if sha:
                        candidate_shas.append(sha)
                        break
                except Exception:
                    pass
        if not sha:
            if "gitcode.com" in url.lower() and not gitcode_private_token():
                print(
                    "  [hint] GitCode PR 接口需要 GITCODE_PRIVATE_TOKEN；否则无法从 PR 跳转到修复提交"
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
