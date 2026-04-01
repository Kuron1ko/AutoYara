import argparse
import base64
import json
import os
import re
import ssl
import sys
import time
import urllib.request
from collections import defaultdict
from urllib.parse import quote

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
H = {"User-Agent": "Mozilla/5.0"}


def get(url, allow_html=False):
    try:
        req = urllib.request.Request(url, headers=H)
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            t = r.read().decode("utf-8", errors="replace")
            if not allow_html and ("<html" in t[:300] or t.lstrip().startswith("<!")):
                return None
            return t
    except Exception as e:
        print("  [err] " + str(e)[:80])
        return None


def fetch_bulletin(year, month):
    for url in [
        f"https://gitee.com/openharmony/security/raw/master/zh/security-disclosure/{year}/{year}-{month:02d}.md",
        f"https://raw.githubusercontent.com/openharmony/security/master/zh/security-disclosure/{year}/{year}-{month:02d}.md",
    ]:
        print("[bulletin] " + url)
        t = get(url)
        if t and len(t) > 200 and ("CVE" in t or "|" in t):
            print("[OK] %d bytes" % len(t))
            return t
    return None


def _gitcode_private_token():
    """GitCode API 需 private-token；见环境变量 GITCODE_PRIVATE_TOKEN 或 GITCODE_TOKEN。"""
    return (
        os.environ.get("GITCODE_PRIVATE_TOKEN") or os.environ.get("GITCODE_TOKEN") or ""
    ).strip()


def _gitcode_auth_headers():
    h = dict(H)
    tok = _gitcode_private_token()
    if tok:
        h["private-token"] = tok
    h.setdefault("Accept", "application/json, text/plain, */*")
    return h


def normalize_gitcode_diff_body(body):
    """将 GitCode API 返回的 JSON 或纯文本统一为 unified diff 字符串。"""
    if not body or not isinstance(body, str):
        return None
    s = body.strip()
    if s.startswith("diff --git"):
        return body
    try:
        data = json.loads(body)
    except Exception:
        return None
    if isinstance(data, str) and "diff --git" in data:
        return data
    if isinstance(data, dict):
        for k in ("diff", "patch", "data"):
            v = data.get(k)
            if isinstance(v, str) and "diff --git" in v:
                return v
        lst = data.get("files") or data.get("diffs") or data.get("items")
        if isinstance(lst, list):
            parts = []
            for it in lst:
                if isinstance(it, dict):
                    d = it.get("diff") or it.get("patch") or ""
                    if d:
                        parts.append(d)
            if parts:
                return "\n".join(parts)
    if isinstance(data, list):
        parts = []
        for it in data:
            if isinstance(it, dict):
                d = it.get("diff") or it.get("patch") or ""
                if d:
                    parts.append(d)
            elif isinstance(it, str) and "diff --git" in it:
                parts.append(it)
        if parts:
            return "\n".join(parts)
    return None


def fetch_gitcode_commit_diff(owner, repo, sha):
    """
    GET https://gitcode.com/api/v5/repos/:owner/:repo/commit/:sha/diff
    需设置 GITCODE_PRIVATE_TOKEN（响应要求 private-token 头）。
    """
    tok = _gitcode_private_token()
    if not tok:
        return None
    url = "https://gitcode.com/api/v5/repos/%s/%s/commit/%s/diff" % (owner, repo, sha)
    try:
        req = urllib.request.Request(url, headers=_gitcode_auth_headers())
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            raw = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print("  [gitcode diff] " + str(e)[:100])
        return None
    out = normalize_gitcode_diff_body(raw)
    if out and "diff --git" in out:
        print("  [OK] gitcode API diff %d bytes" % len(out))
        return out
    if raw and "diff --git" in raw:
        print("  [OK] gitcode API diff (raw) %d bytes" % len(raw))
        return raw
    print("  [gitcode diff] 无法解析为 unified diff")
    return None


def fetch_gitcode_pr(owner, repo, number):
    """GitCode PR 详情（需要 private-token）。"""
    tok = _gitcode_private_token()
    if not tok:
        return None
    url = "https://gitcode.com/api/v5/repos/%s/%s/pulls/%s" % (owner, repo, number)
    try:
        req = urllib.request.Request(url, headers=_gitcode_auth_headers())
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            t = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print("  [gitcode pr] " + str(e)[:100])
        return None
    try:
        return json.loads(t)
    except Exception:
        return None


def fetch_gitcode_pr_commits(owner, repo, number):
    """GitCode PR commits 列表（需要 private-token）。返回 commits JSON 列表。"""
    tok = _gitcode_private_token()
    if not tok:
        return None
    # GitCode v5 API 沿用 Gitee 风格：/pulls/:number/commits
    url = "https://gitcode.com/api/v5/repos/%s/%s/pulls/%s/commits" % (
        owner,
        repo,
        number,
    )
    try:
        req = urllib.request.Request(url, headers=_gitcode_auth_headers())
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            t = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print("  [gitcode pr commits] " + str(e)[:100])
        return None
    try:
        data = json.loads(t)
    except Exception:
        return None
    return data if isinstance(data, list) else None


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
                "https://github.com/%s/%s/commit/%s.diff" % (try_owner, repo, sha),
                "https://github.com/%s/%s/commit/%s.patch" % (try_owner, repo, sha),
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
        print("  [pr-commit] sha=%s score=%d" % (sha[:12], sc))
        if sc > best_score:
            best_diff, best_sha, best_score = diff_text, sha, sc
    return best_diff, best_sha


def fetch_gitcode_file_blob(owner, repo, ref, filepath):
    """
    GET /api/v5/repos/:owner/:repo/contents/:path?ref=:ref
    返回文件全文（GitCode 风格 JSON，content 为 base64）。
    """
    tok = _gitcode_private_token()
    if not tok or not ref or not filepath:
        return None
    enc = quote(filepath, safe="")
    url = "https://gitcode.com/api/v5/repos/%s/%s/contents/%s?ref=%s" % (
        owner,
        repo,
        enc,
        quote(str(ref), safe=""),
    )
    try:
        req = urllib.request.Request(url, headers=_gitcode_auth_headers())
        with urllib.request.urlopen(req, timeout=35, context=ctx) as r:
            t = r.read().decode("utf-8", errors="replace")
    except Exception:
        return None
    try:
        data = json.loads(t)
    except Exception:
        return None
    if isinstance(data, dict) and data.get("content") is not None:
        b64 = data.get("content", "").replace("\n", "")
        try:
            decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
        except Exception:
            return None
        if len(decoded) > 10:
            print("  [src-gitcode] OK %d bytes" % len(decoded))
            return decoded
    return None


def get_parent_sha_gitcode(owner, repo, sha):
    """GET .../commits/:sha，取第一个 parent。"""
    tok = _gitcode_private_token()
    if not tok:
        return None
    url = "https://gitcode.com/api/v5/repos/%s/%s/commits/%s" % (owner, repo, sha)
    try:
        req = urllib.request.Request(url, headers=_gitcode_auth_headers())
        with urllib.request.urlopen(req, timeout=25, context=ctx) as r:
            t = r.read().decode("utf-8", errors="replace")
    except Exception:
        return None
    try:
        data = json.loads(t)
    except Exception:
        return None
    parents = data.get("parents") or []
    if parents:
        p = parents[0].get("id") or parents[0].get("sha") or ""
        if p:
            print("  [parent] " + p[:12] + " (gitcode)")
            return p
    return None


def classify_url(url):
    if re.search(r"/commit/[0-9a-f]{7,40}", url, re.I):
        return "commit"
    if re.search(r"/(pulls|pull|merge_requests)/\d+", url, re.I):
        return "pr"
    if re.search(r"/blob/[0-9a-f]{7,40}/.*\.patch", url, re.I):
        return "patch"
    return "other"


def parse_all_links(md):
    results = []
    for line in md.splitlines():
        if not line.strip().startswith("|"):
            continue
        cve_m = re.search(r"\b(CVE-[\d-]+)\b", line)
        if not cve_m:
            continue
        cve = cve_m.group(1)
        # 仓库名可能含版本号点号，如 kernel_linux_5.10（\w+ 会在点处截断）
        repo_m = re.search(
            r"(third_party_[\w.]+|kernel_[\w.]+|arkcompiler_[\w.]+|security_[\w.]+|communication_[\w.]+)",
            line,
        )
        repo = repo_m.group(1) if repo_m else ""
        sev_m = re.search(r"(严重|高危|中危|低危|无)", line)
        severity = sev_m.group(1) if sev_m else ""
        for label_raw, url_raw in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", line):
            for url in re.split(r"[;；]", url_raw):
                url = url.strip().rstrip(".,;)")
                if not url.startswith("http"):
                    continue
                t = classify_url(url)
                if t != "other":
                    results.append(
                        {
                            "cve": cve,
                            "repo": repo,
                            "severity": severity,
                            "version_label": label_raw.strip(),
                            "url": url,
                            "url_type": t,
                        }
                    )
    return results


UPSTREAM = {
    "third_party_libpng": ("pnggroup", "libpng", "master"),
    "third_party_libexif": ("libexif", "libexif", "master"),
    "third_party_curl": ("curl", "curl", "master"),
    "third_party_zlib": ("madler", "zlib", "master"),
    "third_party_openssl": ("openssl", "openssl", "master"),
    "third_party_expat": ("libexpat", "libexpat", "master"),
    "third_party_libwebp": ("webmproject", "libwebp", "main"),
}


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
        print("  [diff] 本地 patch %d bytes" % len(pb.strip()))
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
                "https://github.com/%s/%s/commit/%s.diff" % (try_owner, repo, sha),
                "https://github.com/%s/%s/commit/%s.patch" % (try_owner, repo, sha),
            ]:
                print("  [diff] " + u[:90])
                t = get(u)
                if t and "diff --git" in t:
                    print("  [OK] %d bytes" % len(t))
                    return t, repo, sha
        # GitCode 仅托管仓库：GitHub 无镜像时需用 API（需 GITCODE_PRIVATE_TOKEN）
        if owner and repo and sha:
            gd = fetch_gitcode_commit_diff(owner, repo, sha)
            if gd:
                return gd, repo, sha
            if "gitcode.com" in url.lower() and not _gitcode_private_token():
                print(
                    "  [hint] GitCode 提交需设置环境变量 GITCODE_PRIVATE_TOKEN 后重试，或使用 --patch 指定本地 .diff/.patch"
                )
        return None, repo, sha
    elif ltype == "patch":
        m = re.match(
            r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/blob/([0-9a-f]+)/(.+)",
            url,
            re.I,
        )
        if not m:
            return None, oh_repo, None
        owner, repo, sha, fpath = m.group(1), m.group(2), m.group(3), m.group(4)
        for u in [
            "https://github.com/openharmony/%s/raw/%s/%s" % (repo, sha, fpath),
            "https://raw.githubusercontent.com/openharmony/%s/%s/%s"
            % (repo, sha, fpath),
        ]:
            print("  [patch] " + u[:90])
            t = get(u)
            if t and ("diff --git" in t or "@@" in t):
                print("  [OK] %d bytes" % len(t))
                return t, repo, sha
        return None, repo, sha
    elif ltype == "pr":
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
        # GitCode PR：需要 token，通过 API 获取 PR commits / merge sha
        if "gitcode.com" in url.lower() and _gitcode_private_token():
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
                    # 保底：沿用旧逻辑（最后一条）
                    last = commits[-1]
                    sha = last.get("sha") or last.get("id")
        for api_owner in [owner, "openharmony"]:
            t = get(
                "https://gitee.com/api/v5/repos/%s/%s/pulls/%s" % (api_owner, repo, num)
            )
            if t:
                try:
                    sha = json.loads(t).get("merge_commit_sha")
                    if sha:
                        candidate_shas.append(sha)
                        break
                except Exception:
                    pass
        if not sha:
            if "gitcode.com" in url.lower() and not _gitcode_private_token():
                print(
                    "  [hint] GitCode PR 接口需要 GITCODE_PRIVATE_TOKEN；否则无法从 PR 跳转到修复提交"
                )
            return None, repo, None
        # PR 可能有多个提交：逐个评估，挑出“主修复提交”
        if sha and sha not in candidate_shas:
            candidate_shas.append(sha)
        best_diff, best_sha = pick_best_pr_commit_diff(owner, repo, candidate_shas)
        if best_diff and best_sha:
            print(
                "  [pr-commit] choose sha=%s from %d candidates"
                % (best_sha[:12], len(candidate_shas))
            )
            return best_diff, repo, best_sha
        return None, repo, sha
    return None, oh_repo, None


HUNK_RE = re.compile(r"^@@ -(\d+),\d+ \+(\d+),\d+ @@(.*)$")


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


_src_cache = {}


def fetch_source(oh_repo, filepath, ref, gh_owner="openharmony"):
    if not ref:
        return None
    key = (gh_owner, oh_repo, ref, filepath)
    if key in _src_cache:
        return _src_cache[key]
    for u in [
        "https://raw.githubusercontent.com/%s/%s/%s/%s"
        % (gh_owner, oh_repo, ref, filepath),
        "https://raw.githubusercontent.com/openharmony/%s/%s/%s"
        % (oh_repo, ref, filepath),
    ]:
        print("  [src] " + u[:90])
        t = get(u)
        if t and len(t) > 500:
            print("  [OK] %d bytes" % len(t))
            _src_cache[key] = t
            return t
    if oh_repo in UPSTREAM:
        up_owner, up_repo, up_branch = UPSTREAM[oh_repo]
        for up_ref in [up_branch, "master", "main"]:
            u = "https://raw.githubusercontent.com/%s/%s/%s/%s" % (
                up_owner,
                up_repo,
                up_ref,
                filepath,
            )
            print("  [src-upstream] " + u[:90])
            t = get(u)
            if t and len(t) > 500:
                print("  [OK] %d bytes" % len(t))
                _src_cache[key] = t
                return t
    # GitCode 托管仓库：raw 页面为 SPA，需 API + GITCODE_PRIVATE_TOKEN
    if _gitcode_private_token() and gh_owner:
        print("  [src-gitcode] " + filepath[:60])
        t = fetch_gitcode_file_blob(gh_owner, oh_repo, ref, filepath)
        if t and len(t) > 10:
            _src_cache[key] = t
            return t
    _src_cache[key] = None
    return None


_parent_cache = {}


def _github_api_headers():
    """可选 GITHUB_TOKEN / GITHUB_API_TOKEN，降低 API 限流失败概率。"""
    h = dict(H)
    tok = (
        os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_API_TOKEN") or ""
    ).strip()
    if tok:
        h["Authorization"] = "Bearer " + tok
    return h


def get_parent_sha(oh_repo, sha, gh_owner=None):
    if not sha:
        return None
    key = (oh_repo, sha, gh_owner or "")
    if key in _parent_cache:
        return _parent_cache[key]
    # 0. GitCode API（与 fetch_gitcode_file_blob 同源，需 token）
    if gh_owner and _gitcode_private_token():
        pg = get_parent_sha_gitcode(gh_owner, oh_repo, sha)
        if pg:
            _parent_cache[key] = pg
            return pg
    # 1. GitHub API 优先（与 raw.githubusercontent.com 同源，kernel 等仓库更稳）
    for try_owner in ["openharmony", "openharmony-tpc"]:
        try:
            req = urllib.request.Request(
                "https://api.github.com/repos/%s/%s/commits/%s"
                % (try_owner, oh_repo, sha),
                headers=_github_api_headers(),
            )
            with urllib.request.urlopen(req, timeout=25, context=ctx) as r:
                t = r.read().decode("utf-8", errors="replace")
        except Exception:
            t = None
        if t and "{" in t:
            try:
                data = json.loads(t)
                if "API rate limit" in data.get("message", ""):
                    print("  [parent] GitHub rate limited")
                    break
                parents = data.get("parents", [])
                if parents:
                    p = parents[0]["sha"]
                    print("  [parent] " + p[:12] + " (github)")
                    _parent_cache[key] = p
                    return p
            except Exception:
                pass
    # 2. Gitee API
    t = get("https://gitee.com/api/v5/repos/openharmony/%s/commits/%s" % (oh_repo, sha))
    if t and "{" in t:
        try:
            data = json.loads(t)
            parents = data.get("parents") or []
            if parents:
                p = parents[0].get("sha") or parents[0].get("id", "")
                if p:
                    print("  [parent] " + p[:12] + " (gitee)")
                    _parent_cache[key] = p
                    return p
        except Exception:
            pass
    _parent_cache[key] = None
    return None


def get_upstream_commit_from_patch(diff_text):
    """从 patch 文件的 commit message 里提取上游 mainline commit SHA"""
    import re

    # 格式: "commit 0c76ef3f26d5ef2ac2c21b47e7620cff35809fbb"
    m = re.search(r"^\s*commit\s+([0-9a-f]{40})\s*$", diff_text, re.M | re.I)
    if m:
        return m.group(1)
    # 备用格式: "from mainline-xxx / commit xxxxx"
    m = re.search(r"commit\s+([0-9a-f]{40})", diff_text, re.I)
    if m:
        return m.group(1)
    return None


def get_parent_sha_upstream(upstream_sha):
    """从 torvalds/linux 获取上游 commit 的 parent SHA"""
    if not upstream_sha:
        return None, None
    t = get("https://api.github.com/repos/torvalds/linux/commits/%s" % upstream_sha)
    if t and "{" in t:
        try:
            data = json.loads(t)
            if "API rate limit" in data.get("message", ""):
                print("  [upstream] GitHub rate limited")
                return None, None
            parents = data.get("parents", [])
            if parents:
                p = parents[0]["sha"]
                print("  [upstream parent] " + p[:12])
                return p, "torvalds/linux"
        except Exception:
            pass
    return None, None


def fetch_source_upstream(filepath, ref, repo="torvalds/linux"):
    """从上游仓库（如 torvalds/linux）获取源文件"""
    u = "https://raw.githubusercontent.com/%s/%s/%s" % (repo, ref, filepath)
    print("  [src-upstream2] " + u[:90])
    t = get(u)
    if t and len(t) > 500:
        print("  [OK] %d bytes" % len(t))
        return t
    return None


def parse_fname_from_hint(func_hint):
    """
    从 diff hunk 的 @@ ... @@ 提示里取出 C 函数名。
    常见形式: 'static void kill_kprobe(struct kprobe *p)' —— 不能取第一个词 static。
    """
    if not func_hint:
        return ""
    hint = func_hint.strip()
    # 取「紧邻形参列表的左括号」前的标识符（最后一个匹配），适配 static/inline 等前缀
    matches = re.findall(r"([a-zA-Z_]\w*)\s*\(", hint)
    if matches:
        return matches[-1]
    return re.split(r"[(\s]", hint)[0].strip()


def extend_signature_start(lines, sig_idx):
    """把签名起始行向上扩展，包含 static void 等多行声明里、函数名之上的行。"""
    while sig_idx > 0:
        prev_raw = lines[sig_idx - 1]
        if not prev_raw.strip():
            sig_idx -= 1
            continue
        if prev_raw[0] in (" ", "\t"):
            break
        pl = prev_raw.lstrip()
        if pl.startswith(("#", "/*", "*", "//")):
            break
        pr = prev_raw.rstrip()
        if pr.endswith("}"):
            break
        if pr.endswith(";"):
            break
        sig_idx -= 1
    return sig_idx


def extract_function(source, func_hint, target_lineno):
    if not source:
        return None
    lines = source.splitlines()
    n = len(lines)
    target_idx = min(max(target_lineno - 1, 0), n - 1)
    fname = parse_fname_from_hint(func_hint)
    sig_idx = None
    # 大文件里 hunk 行号与函数头可能相距很远，200 行不够
    lookback = min(target_idx + 1, 8000)
    if fname:
        for i in range(target_idx, max(target_idx - lookback, -1), -1):
            line = lines[i]
            if not line or line[0] in (" ", "\t"):
                continue
            s = line.lstrip()
            if s.startswith(("/*", "*", "//", "#")):
                continue
            if fname in line:
                sig_idx = i
                break
    if sig_idx is None and fname:
        cands = []
        for i, line in enumerate(lines):
            if not line or line[0] in (" ", "\t"):
                continue
            s = line.lstrip()
            if s.startswith(("/*", "*", "//", "#")):
                continue
            if fname in line:
                cands.append(i)
        if cands:
            sig_idx = min(cands, key=lambda i: abs(i - target_idx))
    if sig_idx is None:
        return None
    sig_idx = extend_signature_start(lines, sig_idx)
    depth, found_open, end_idx = 0, False, None
    for i in range(sig_idx, min(sig_idx + 5000, n)):
        if not found_open and i > sig_idx + 8:
            line = lines[i]
            if (
                line
                and line[0] not in (" ", "\t")
                and not line.lstrip().startswith(("/*", "*", "//", "#", "}"))
                and fname not in line
                and "{" not in line
            ):
                break
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                found_open = True
            elif ch == "}":
                depth -= 1
                if found_open and depth == 0:
                    end_idx = i
                    break
        if end_idx is not None:
            break
    if end_idx is None:
        return None
    return "\n".join(lines[sig_idx : end_idx + 1])


def hunk_sequences_from_body(body):
    """从 unified diff 的 hunk body 拆出「旧文件片段」与「新文件片段」行序列（不含前缀 +/-）。"""
    old_seq, new_seq = [], []
    for raw in body.splitlines():
        if not raw:
            continue
        kind = raw[0]
        if kind not in " +-":
            continue
        code = raw[1:]
        if kind == " ":
            old_seq.append(code)
            new_seq.append(code)
        elif kind == "+":
            new_seq.append(code)
        elif kind == "-":
            old_seq.append(code)
    return old_seq, new_seq


def _lines_equal_seq(chunk, new_seq):
    if len(chunk) != len(new_seq):
        return False
    for a, b in zip(chunk, new_seq, strict=False):
        if a.rstrip("\r") != b.rstrip("\r"):
            return False
    return True


def reconstruct_old_from_new(new_src, hunks):
    """
    用修复后的完整 new_src + 本文件全部 hunk 的 body，自下而上按 new_start 反向替换，
    合成父提交中的文件内容（不依赖 Gitee/GitHub 父 blob 拉取）。
    适用于「代码块移动」类补丁：derive_vulnerable 按行配对会失败。
    """
    if not new_src or not hunks:
        return None
    lines = list(new_src.splitlines())
    for h in sorted(hunks, key=lambda x: x.get("new_start", 0), reverse=True):
        body = h.get("body")
        if not body:
            continue
        old_seq, new_seq = hunk_sequences_from_body(body)
        if not new_seq and not old_seq:
            continue
        start = h["new_start"] - 1
        end = start + len(new_seq)
        if start < 0 or end > len(lines):
            print(
                "  [reconstruct] 行号越界 new_start=%s need [%d,%d) len=%d"
                % (h.get("new_start"), start, end, len(lines))
            )
            return None
        chunk = lines[start:end]
        if not _lines_equal_seq(chunk, new_seq):
            if not _lines_equal_seq(
                [x.rstrip() for x in chunk], [x.rstrip() for x in new_seq]
            ):
                print(
                    "  [reconstruct] 与 diff 中新侧行不一致 new_start=%s"
                    % h.get("new_start")
                )
                return None
        lines[start:end] = old_seq
    return "\n".join(lines)


def derive_vulnerable(fixed_func, all_hunks):
    if not fixed_func:
        return None
    result = fixed_func
    for hunk in all_hunks:
        added, removed = hunk["added"], hunk["removed"]
        for i, add_item in enumerate(added):
            code = add_item["code"]
            if code in result:
                if i < len(removed):
                    result = result.replace(code, removed[i]["code"], 1)
                else:
                    result = re.sub(re.escape(code) + r"\n?", "", result, count=1)
    return result


def patch_snippet(hunk_list, mode):
    lines = ["/* patch context - source file unavailable */"]
    for h in hunk_list:
        start = h["old_start"] if mode == "old" else h["new_start"]
        lines.append("/* ... line %d ... */" % start)
        if mode == "old":
            items = sorted(
                [(c["old"], c["code"]) for c in h["context"]]
                + [(r["lineno"], r["code"]) for r in h["removed"]],
                key=lambda x: x[0],
            )
        else:
            items = sorted(
                [(c["new"], c["code"]) for c in h["context"]]
                + [(a["lineno"], a["code"]) for a in h["added"]],
                key=lambda x: x[0],
            )
        for lineno, code in items:
            lines.append("%5d  %s" % (lineno, code))
    return "\n".join(lines)


def process_item(item):
    diff, repo, fix_sha = fetch_diff_text(item)
    if not diff or not repo:
        return []
    hunks = parse_diff_full(diff)
    if not hunks:
        return []
    # 必须用 commit URL 里解析出的仓库名（含 kernel_linux_5.10），不能用表格列正则截断的 item["repo"]
    oh_repo = repo
    gh_owner = "openharmony"
    url_m = re.match(r"https?://(?:gitee|gitcode)\.com/([^/]+)/", item["url"], re.I)
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

        # fallback: 从 patch 提取上游 commit，去 torvalds/linux 拿源文件
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
        # 父提交 blob 拉取失败时：用「修复后全文 + diff hunk」反向合成旧版本（支持整块移动）
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
                {
                    "cve": item["cve"],
                    "repo": oh_repo,
                    "severity": item["severity"],
                    "version": item["version_label"],
                    "file": filepath,
                    "function_name": func_hint,
                    "hunk_headers": [h["hunk_header"] for h in fh_list],
                    "removed_lines": all_removed,
                    "added_lines": all_added,
                    "vulnerable_function": vuln_func,
                    "fixed_function": fixed_func,
                }
            )
    return results


def print_result(r):
    sep = "=" * 65
    print()
    print(sep)
    print("[3] CVE      : " + r["cve"])
    print("    Repo     : " + r["repo"])
    print("    File     : " + r["file"])
    print("    Function : " + r["function_name"])
    print("    Version  : " + r["version"])
    print("    Severity : " + r["severity"])
    for hdr in r.get("hunk_headers", []):
        print("    Hunk     : " + hdr)
    if r["removed_lines"]:
        print("\n    Key change (removed):")
        for x in r["removed_lines"]:
            if x["code"].strip() not in ("", "-", "- "):
                print("      %4d-  %s" % (x["lineno"], x["code"]))
    if r["added_lines"]:
        print("    Key change (added):")
        for x in r["added_lines"]:
            print("      %4d+  %s" % (x["lineno"], x["code"]))
    print("\n[1] VULNERABLE FUNCTION (before fix):")
    print(r["vulnerable_function"])
    print("\n[2] FIXED FUNCTION (after fix):")
    print(r["fixed_function"])
    print(sep)


if __name__ == "__main__":
    print("=" * 60)
    print("  OpenHarmony CVE Crawler v16")
    print("  GitCode：GITCODE_PRIVATE_TOKEN + API 拉取 commit diff / 源码 blob")
    print("  父提交优先 GitHub API；无旧源码时用 new+diff 反向合成父文件")
    print("  @@ hint 函数名解析：取 kill_kprobe 而非 static")
    print("=" * 60)

    ap = argparse.ArgumentParser(
        description="爬取 OpenHarmony 安全公告中的 CVE 链接并提取漏洞/修复函数"
    )
    ap.add_argument("--year", type=int, help="年份，如 2026")
    ap.add_argument("--month", type=int, help="月份 1-12")
    ap.add_argument("--json", metavar="FILE", help="导出 JSON，如 result.json")
    ap.add_argument("--txt", metavar="FILE", help="导出 TXT 报告（可选）")
    ap.add_argument("--max", type=int, help="最多处理几条链接（默认全部）")
    ap.add_argument(
        "--commit-url",
        metavar="URL",
        help="只处理一条 commit 链接（如 GitCode 某次提交，可配 --patch）",
    )
    ap.add_argument(
        "--patch",
        metavar="FILE",
        help="本地 unified diff（.patch/.diff），与 --commit-url 一起用可跳过在线拉取 patch",
    )
    ap.add_argument(
        "--cve",
        default="MANUAL",
        help="与 --commit-url 联用时的 CVE 标识（默认 MANUAL）",
    )
    cli = ap.parse_args()
    use_cli = (cli.year is not None and cli.month is not None) or (
        (cli.commit_url or "").strip() != ""
    )

    if use_cli and (cli.commit_url or "").strip():
        year, month = 2026, 1
        json_out = (cli.json or "").strip() or None
        txt_out = (cli.txt or "").strip() or None
        mx = 1
        cu = (cli.commit_url or "").strip()
        patch_body = None
        pf = (cli.patch or "").strip()
        if pf:
            try:
                with open(pf, encoding="utf-8", errors="replace") as f:
                    patch_body = f.read()
            except Exception as e:
                print("ERROR: cannot read --patch: " + str(e))
                sys.exit(1)
            if "diff --git" not in patch_body:
                print("ERROR: --patch file must contain unified diff (diff --git)")
                sys.exit(1)
        m = re.match(
            r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
            re.sub(r"[?#].*$", "", cu),
            re.I,
        )
        if not m:
            print(
                "ERROR: --commit-url must be gitee/gitcode .../owner/repo/commit/<sha>"
            )
            sys.exit(1)
        owner, repo, sha = m.group(1), m.group(2), m.group(3)
        all_links = [
            {
                "cve": (cli.cve or "MANUAL").strip() or "MANUAL",
                "repo": repo,
                "severity": "",
                "version_label": "manual",
                "url": cu,
                "url_type": "commit",
                "fix_sha": sha,
                "patch_body": patch_body,
            }
        ]
        cve_set = set(x["cve"] for x in all_links)
        print(
            "\n[CLI] commit-url mode owner=%s repo=%s sha=%s patch_file=%s"
            % (owner, repo, sha[:12], pf or "(none)")
        )
    elif use_cli:
        year, month = cli.year, cli.month
        if not (2020 <= year <= 2030):
            print("ERROR: year must be 2020-2030")
            sys.exit(1)
        if not (1 <= month <= 12):
            print("ERROR: month must be 1-12")
            sys.exit(1)
        json_out = (cli.json or "").strip() or None
        txt_out = (cli.txt or "").strip() or None
        mx = cli.max
        print(
            "\n[CLI] year=%d month=%d json=%s txt=%s max=%s"
            % (year, month, json_out, txt_out, mx)
        )
    else:
        while True:
            try:
                year = int(input("\nYear (e.g. 2025): "))
                if 2020 <= year <= 2030:
                    break
                print("  Please enter 2020-2030")
            except ValueError:
                print("  Invalid number")

        while True:
            try:
                month = int(input("Month (1-12): "))
                if 1 <= month <= 12:
                    break
                print("  Please enter 1-12")
            except ValueError:
                print("  Invalid number")

        print("\n[Optional] Output files (press Enter to skip)")
        json_out = input("  JSON (e.g. result.json): ").strip() or None
        txt_out = input("  TXT  (e.g. report.txt):  ").strip() or None
        mx_input = input("\nMax CVE links to process (Enter=all): ").strip()
        mx = int(mx_input) if mx_input.isdigit() else None

    commit_url_mode = use_cli and (cli.commit_url or "").strip() != ""

    if not commit_url_mode:
        md = fetch_bulletin(year, month)
        if not md:
            print("ERROR: cannot fetch bulletin")
            sys.exit(1)

        all_links = parse_all_links(md)
        cve_set = set(x["cve"] for x in all_links)
        print("\n== Found %d links across %d CVEs ==" % (len(all_links), len(cve_set)))
        for x in all_links:
            print(
                "  %-20s [%-7s] %-8s -> %s"
                % (x["cve"], x["url_type"], x["version_label"][:8], x["url"][:60])
            )
    else:
        print("\n== Single commit mode: %d link(s) ==" % len(all_links))
        for x in all_links:
            print(
                "  %-20s [%-7s] %-8s -> %s"
                % (x["cve"], x["url_type"], x["version_label"][:8], x["url"][:60])
            )

    if mx:
        all_links = all_links[:mx]

    all_results = []
    for i, item in enumerate(all_links, 1):
        print(
            "\n[%d/%d] %s [%s] %s"
            % (i, len(all_links), item["cve"], item["url_type"], item["version_label"])
        )
        funcs = process_item(item)
        if funcs:
            for f in funcs:
                print_result(f)
                all_results.append(f)
        else:
            placeholder = {
                "cve": item["cve"],
                "repo": item["repo"],
                "severity": item["severity"],
                "version": item["version_label"],
                "file": "(unavailable)",
                "function_name": "(unavailable)",
                "hunk_headers": [],
                "removed_lines": [],
                "added_lines": [],
                "vulnerable_function": "(diff fetch failed - %s: %s)"
                % (item["url_type"], item["url"]),
                "fixed_function": "(diff fetch failed)",
            }
            print("  [!] no diff - saved as placeholder")
            all_results.append(placeholder)
        if i < len(all_links):
            time.sleep(1.0)

    if txt_out:
        import io

        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        for r in all_results:
            print_result(r)
        sys.stdout = old
        with open(txt_out, "w", encoding="utf-8") as f:
            f.write(buf.getvalue())
        print("\n[OK] TXT: " + txt_out)

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "year": year,
                    "month": month,
                    "total": len(all_results),
                    "items": all_results,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
        print("[OK] JSON: " + json_out)

    print(
        "\nDone. %d functions, %d CVEs."
        % (len(all_results), len(set(r["cve"] for r in all_results)))
    )
