import base64
import json
import os
from urllib.parse import quote

from .http_client import SESSION, H


def gitcode_private_token():
    """可选 GitCode private-token；见环境变量 GITCODE_PRIVATE_TOKEN 或 GITCODE_TOKEN。"""
    return (
        os.environ.get("GITCODE_PRIVATE_TOKEN") or os.environ.get("GITCODE_TOKEN") or ""
    ).strip()


def gitcode_auth_headers():
    h = dict(H)
    tok = gitcode_private_token()
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
    公开仓库可匿名访问；受限仓库/限流场景建议设置 GITCODE_PRIVATE_TOKEN。
    """
    url = f"https://gitcode.com/api/v5/repos/{owner}/{repo}/commit/{sha}/diff"
    try:
        r = SESSION.get(url, headers=gitcode_auth_headers(), timeout=30, verify=False)
        r.raise_for_status()
        raw = r.content.decode("utf-8", errors="replace")
    except Exception as e:
        print("  [gitcode diff] " + str(e)[:100])
        return None
    out = normalize_gitcode_diff_body(raw)
    if out and "diff --git" in out:
        print(f"  [OK] gitcode API diff {len(out)} bytes")
        return out
    if raw and "diff --git" in raw:
        print(f"  [OK] gitcode API diff (raw) {len(raw)} bytes")
        return raw
    print("  [gitcode diff] 无法解析为 unified diff")
    return None


def fetch_gitcode_pr(owner, repo, number):
    """GitCode PR 详情（公开仓库可匿名访问，建议配置 token 提升稳定性）。"""
    url = f"https://gitcode.com/api/v5/repos/{owner}/{repo}/pulls/{number}"
    try:
        r = SESSION.get(url, headers=gitcode_auth_headers(), timeout=30, verify=False)
        r.raise_for_status()
        t = r.content.decode("utf-8", errors="replace")
    except Exception as e:
        print("  [gitcode pr] " + str(e)[:100])
        return None
    try:
        return json.loads(t)
    except Exception:
        return None


def fetch_gitcode_pr_commits(owner, repo, number):
    """GitCode PR commits 列表（公开仓库可匿名访问）。返回 commits JSON 列表。"""
    url = f"https://gitcode.com/api/v5/repos/{owner}/{repo}/pulls/{number}/commits"
    try:
        r = SESSION.get(url, headers=gitcode_auth_headers(), timeout=30, verify=False)
        r.raise_for_status()
        t = r.content.decode("utf-8", errors="replace")
    except Exception as e:
        print("  [gitcode pr commits] " + str(e)[:100])
        return None
    try:
        data = json.loads(t)
    except Exception:
        return None
    return data if isinstance(data, list) else None


def fetch_gitcode_file_blob(owner, repo, ref, filepath):
    """
    GET /api/v5/repos/:owner/:repo/contents/:path?ref=:ref
    返回文件全文（GitCode 风格 JSON，content 为 base64）。
    """
    if not ref or not filepath:
        return None
    enc = quote(filepath, safe="")
    url = "https://gitcode.com/api/v5/repos/{}/{}/contents/{}?ref={}".format(
        owner,
        repo,
        enc,
        quote(str(ref), safe=""),
    )
    try:
        r = SESSION.get(url, headers=gitcode_auth_headers(), timeout=35, verify=False)
        r.raise_for_status()
        t = r.content.decode("utf-8", errors="replace")
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
            print(f"  [src-gitcode] OK {len(decoded)} bytes")
            return decoded
    return None


def get_parent_sha_gitcode(owner, repo, sha):
    """GET .../commits/:sha，取第一个 parent。"""
    url = f"https://gitcode.com/api/v5/repos/{owner}/{repo}/commits/{sha}"
    try:
        r = SESSION.get(url, headers=gitcode_auth_headers(), timeout=25, verify=False)
        r.raise_for_status()
        t = r.content.decode("utf-8", errors="replace")
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
