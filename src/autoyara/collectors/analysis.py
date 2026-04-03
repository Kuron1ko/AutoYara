import json
import os
import re
from typing import Any

from .discovery import UPSTREAM
from .gitcode import (
    fetch_gitcode_file_blob,
    get_parent_sha_gitcode,
    gitcode_auth_headers,
    gitcode_private_token,
)
from .http_client import SESSION, H, get
from .internal_types import CrawlerLink

_src_cache = {}
_parent_cache = {}


def _github_api_headers():
    h = dict(H)
    tok = (
        os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_API_TOKEN") or ""
    ).strip()
    if tok:
        h["Authorization"] = "Bearer " + tok
    return h


def fetch_source(oh_repo, filepath, ref, gh_owner="openharmony"):
    if not ref:
        return None
    key = (gh_owner, oh_repo, ref, filepath)
    if key in _src_cache:
        return _src_cache[key]
    for u in [
        f"https://raw.githubusercontent.com/{gh_owner}/{oh_repo}/{ref}/{filepath}",
        f"https://raw.githubusercontent.com/openharmony/{oh_repo}/{ref}/{filepath}",
    ]:
        print("  [src] " + u[:90])
        t = get(u)
        if t and len(t) > 500:
            print(f"  [OK] {len(t)} bytes")
            _src_cache[key] = t
            return t
    if oh_repo in UPSTREAM:
        up_owner, up_repo, up_branch = UPSTREAM[oh_repo]
        for up_ref in [up_branch, "master", "main"]:
            u = f"https://raw.githubusercontent.com/{up_owner}/{up_repo}/{up_ref}/{filepath}"
            print("  [src-upstream] " + u[:90])
            t = get(u)
            if t and len(t) > 500:
                print(f"  [OK] {len(t)} bytes")
                _src_cache[key] = t
                return t
    if gitcode_private_token() and gh_owner:
        print("  [src-gitcode] " + filepath[:60])
        t = fetch_gitcode_file_blob(gh_owner, oh_repo, ref, filepath)
        if t and len(t) > 10:
            _src_cache[key] = t
            return t
    _src_cache[key] = None
    return None


def get_parent_sha(oh_repo, sha, gh_owner=None):
    if not sha:
        return None
    key = (oh_repo, sha, gh_owner or "")
    if key in _parent_cache:
        return _parent_cache[key]
    if gh_owner and gitcode_private_token():
        pg = get_parent_sha_gitcode(gh_owner, oh_repo, sha)
        if pg:
            _parent_cache[key] = pg
            return pg
    for try_owner in ["openharmony", "openharmony-tpc"]:
        try:
            r = SESSION.get(
                f"https://api.github.com/repos/{try_owner}/{oh_repo}/commits/{sha}",
                headers=_github_api_headers(),
                timeout=25,
                verify=False,
            )
            r.raise_for_status()
            t = r.content.decode("utf-8", errors="replace")
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
    t = get(f"https://gitee.com/api/v5/repos/openharmony/{oh_repo}/commits/{sha}")
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
    m = re.search(r"^\s*commit\s+([0-9a-f]{40})\s*$", diff_text, re.M | re.I)
    if m:
        return m.group(1)
    m = re.search(r"commit\s+([0-9a-f]{40})", diff_text, re.I)
    if m:
        return m.group(1)
    return None


def get_parent_sha_upstream(upstream_sha):
    """从 torvalds/linux 获取上游 commit 的 parent SHA。

    无 GITHUB_TOKEN 时 API 限流严重（匿名 60 次/小时），限流直接跳过而不重试。
    """
    if not upstream_sha:
        return None, None
    try:
        r = SESSION.get(
            f"https://api.github.com/repos/torvalds/linux/commits/{upstream_sha}",
            headers=_github_api_headers(),
            timeout=20,
            verify=False,
        )
        if r.status_code in (403, 429):
            print("  [upstream] GitHub API rate limited, skipping parent lookup")
            return None, None
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict):
            msg = data.get("message", "")
            if "rate limit" in msg.lower():
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
    u = f"https://raw.githubusercontent.com/{repo}/{ref}/{filepath}"
    print("  [src-upstream2] " + u[:90])
    t = get(u)
    if t and len(t) > 500:
        print(f"  [OK] {len(t)} bytes")
        return t
    return None


def strip_html_to_text(html):
    """简单 HTML -> 文本，便于从 commit 页面兜底提取描述。"""
    if not html:
        return ""
    t = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", html)
    t = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", t)
    t = re.sub(r"(?is)<[^>]+>", " ", t)
    t = re.sub(r"&nbsp;", " ", t)
    t = re.sub(r"&amp;", "&", t)
    t = re.sub(r"&#39;|&apos;", "'", t)
    t = re.sub(r"&quot;", '"', t)
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def _clean_desc_line(line):
    s = (line or "").strip()
    if not s:
        return ""
    if s.startswith(("Signed-off-by:", "Reviewed-by:", "Tested-by:", "Acked-by:")):
        return ""
    if s.startswith("Cc:"):
        return ""
    if s.startswith("Fixes:"):
        return ""
    if s.startswith("Link:"):
        return ""
    return s


def parse_vuln_desc_from_patch_text(diff_text):
    if not diff_text or not isinstance(diff_text, str):
        return {"title": "", "description": "", "cve": ""}
    title = ""
    m = re.search(r"(?im)^Subject:\s*(?:\[[^\]]+\]\s*)?(.+)$", diff_text)
    if m:
        title = m.group(1).strip()
    cve = ""
    cve_m = re.search(r"\b(CVE-\d{4}-\d+)\b", diff_text, re.I)
    if cve_m:
        cve = cve_m.group(1).upper()
    desc = ""
    body_m = re.search(
        r"(?is)^Subject:.*?\n\n(.*?)(?:\n---\n|\ndiff --git |\nIndex: )",
        diff_text,
        re.M,
    )
    if body_m:
        body = body_m.group(1)
        lines = []
        for ln in body.splitlines():
            x = _clean_desc_line(ln)
            if x:
                lines.append(x)
        if lines:
            desc = "\n".join(lines[:12]).strip()
    # GitCode 等返回的 unified diff 可能没有 From:/Subject:，仅在 diff --git 前有说明与 CVE 行
    if (not title or not desc) and "diff --git" in diff_text:
        head = diff_text.split("diff --git", 1)[0].strip()
        if len(head) > 15:
            if not cve:
                cm2 = re.search(r"\b(CVE-\d{4}-\d+)\b", head, re.I)
                if cm2:
                    cve = cm2.group(0).upper()
            hlines = []
            for ln in head.splitlines():
                x = _clean_desc_line(ln)
                if x:
                    hlines.append(x)
            if hlines:
                if not title:
                    title = hlines[0][:240]
                if not desc:
                    rest = hlines[1:] if title == hlines[0] else hlines
                    desc = "\n".join(rest).strip()[:8000]
    return {"title": title, "description": desc, "cve": cve}


def _commit_message_from_api_json(data: dict) -> str:
    """解析 GitHub/Gitee/GitCode 等返回的 commit JSON，取出完整提交说明。"""
    if not isinstance(data, dict):
        return ""
    c = data.get("commit")
    if isinstance(c, dict):
        msg = c.get("message")
        if isinstance(msg, str) and msg.strip():
            return msg.strip()
        title = c.get("title")
        body = c.get("body")
        parts = []
        if isinstance(title, str) and title.strip():
            parts.append(title.strip())
        if isinstance(body, str) and body.strip():
            parts.append(body.strip())
        if parts:
            return "\n".join(parts)
    for k in ("message", "title"):
        v = data.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def fetch_commit_meta_from_api(owner, repo, sha):
    """尝试从 GitHub/Gitee/GitCode API 获取 commit message（GitCode 公开仓可无 token）。"""
    if not (owner and repo and sha):
        return ""
    for try_owner in [owner, "openharmony"]:
        try:
            r = SESSION.get(
                f"https://api.github.com/repos/{try_owner}/{repo}/commits/{sha}",
                headers=_github_api_headers(),
                timeout=25,
                verify=False,
            )
            r.raise_for_status()
            data = r.json()
            if isinstance(data, dict):
                msg = _commit_message_from_api_json(data)
                if msg:
                    return msg
        except Exception:
            pass
    try:
        t = get(f"https://gitee.com/api/v5/repos/{owner}/{repo}/commits/{sha}")
        if t:
            data = json.loads(t)
            msg = _commit_message_from_api_json(data)
            if msg:
                return msg
    except Exception:
        pass
    try:
        url = f"https://gitcode.com/api/v5/repos/{owner}/{repo}/commits/{sha}"
        r = SESSION.get(url, headers=gitcode_auth_headers(), timeout=25, verify=False)
        r.raise_for_status()
        data = r.json()
        msg = _commit_message_from_api_json(data)
        if msg:
            return msg
    except Exception:
        pass
    return ""


def fetch_vuln_description(item: CrawlerLink, diff_text):
    """
    聚合漏洞描述来源（优先级）：
    1) patch 头 Subject/正文
    2) commit API message
    3) commit 页面文本兜底
    """
    info = parse_vuln_desc_from_patch_text(diff_text)
    title = info.get("title", "")
    desc = info.get("description", "")
    cve = info.get("cve", "")
    url = item.get("url", "")
    # 支持 commit / patch(blob) / github / gitcode / gitee 等各种 URL 格式
    owner: str = "openharmony"
    repo: str = item.get("repo", "")
    sha: str | None = item.get("fix_sha")
    # gitee/gitcode commit URL
    m = re.match(
        r"https?://(?:gitee|gitcode|github)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
        url,
        re.I,
    )
    if m:
        owner, repo, sha = m.group(1), m.group(2), m.group(3)
    else:
        # gitcode/gitee blob patch URL: .../blob/<sha>/filename.patch
        m2 = re.match(
            r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/blob/([0-9a-f]+)/",
            url,
            re.I,
        )
        if m2:
            owner, repo, sha = m2.group(1), m2.group(2), m2.group(3)
        elif not sha:
            # 从 diff_text 里尝试提取 SHA（patch 文件头通常含 From <sha>）
            sha_m = re.search(r"^From ([0-9a-f]{40})\b", diff_text or "", re.M)
            if sha_m:
                sha = sha_m.group(1)
    if not title or not desc or not cve:
        msg = fetch_commit_meta_from_api(owner, repo, sha)
        if msg:
            if not cve:
                cm = re.search(r"\b(CVE-\d{4}-\d+)\b", msg, re.I)
                if cm:
                    cve = cm.group(0).upper()
            lines = [x.strip() for x in msg.splitlines()]
            lines = [x for x in lines if _clean_desc_line(x)]
            if lines:
                first = lines[0]
                if not title:
                    title = first
                if not desc:
                    if title == first:
                        desc = "\n".join(lines[1:]).strip()[:8000]
                    else:
                        desc = "\n".join(lines).strip()[:8000]
            if not desc and msg.strip():
                tail = msg.strip()
                if title and tail.startswith(title):
                    tail = tail[len(title) :].lstrip("\n\r- ")
                desc = tail[:8000].strip()
    if (not title or not desc) and url:
        page = get(url, allow_html=True)
        txt = strip_html_to_text(page or "")
        if txt:
            if not cve:
                c = re.search(r"\b(CVE-\d{4}-\d+)\b", txt, re.I)
                if c:
                    cve = c.group(1).upper()
            if not title:
                tm = re.search(
                    r"(?:commit|提交|修复|fix)\s*[:：]?\s*([^\n.]{10,240})",
                    txt,
                    re.I,
                )
                if tm:
                    title = tm.group(1).strip()
            if not desc:
                dm = re.search(
                    r"CVE\s*[:：]\s*CVE-\d{4}-\d+\s*(.+?)(?=Signed-off-by|---\s*$)",
                    txt,
                    re.I | re.S,
                )
                if dm:
                    desc = re.sub(r"\s+", " ", dm.group(1).strip())[:2000]
                if not desc and len(txt) > 80:
                    cut = txt[:1500]
                    if "Signed-off-by" in cut:
                        cut = cut.split("Signed-off-by")[0]
                    desc = re.sub(r"\s+", " ", cut.strip())[:2000]
    return {"title": title, "description": desc, "cve": cve}


def parse_fname_from_hint(func_hint):
    if not func_hint:
        return ""
    hint = func_hint.strip()
    matches = re.findall(r"([a-zA-Z_]\w*)\s*\(", hint)
    if matches:
        return matches[-1]
    return re.split(r"[(\s]", hint)[0].strip()


def extend_signature_start(lines, sig_idx):
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
        if pr.endswith("}") or pr.endswith(";"):
            break
        sig_idx -= 1
    return sig_idx


def extract_function(
    source: str | None, func_hint: str, target_lineno: int
) -> str | None:
    if not source:
        return None
    lines = source.splitlines()
    n = len(lines)
    target_idx = min(max(target_lineno - 1, 0), n - 1)
    fname = parse_fname_from_hint(func_hint)
    sig_idx = None
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


def _find_seq_in_lines(lines: list[str], seq: list[str], near: int) -> int | None:
    """在 lines 中以 near 为中心，搜索与 seq 完全匹配的起始行索引（允许 ±50 行偏移）。"""
    if not seq:
        return None
    radius = 50
    lo = max(0, near - radius)
    hi = min(len(lines) - len(seq), near + radius)
    best_idx: int | None = None
    best_dist = radius + 1
    for i in range(lo, hi + 1):
        chunk = lines[i : i + len(seq)]
        if _lines_equal_seq(chunk, seq) or _lines_equal_seq(
            [x.rstrip() for x in chunk], [x.rstrip() for x in seq]
        ):
            d = abs(i - near)
            if d < best_dist:
                best_dist = d
                best_idx = i
    return best_idx


def reconstruct_old_from_new(
    new_src: str | None, hunks: list[dict[str, Any]]
) -> str | None:
    """将 new_src + diff hunks 反向推算出旧版本全文。

    - 行号越界或不一致时先尝试在 ±50 行内模糊定位；若仍失败则跳过该 hunk。
    - 所有 hunk 都跳过时返回 None（调用方可降级为 derive_vulnerable）。
    """
    if not new_src or not hunks:
        return None
    lines = list(new_src.splitlines())
    skipped = 0
    for h in sorted(hunks, key=lambda x: x.get("new_start", 0), reverse=True):
        body = h.get("body")
        if not body:
            continue
        old_seq, new_seq = hunk_sequences_from_body(body)
        if not new_seq and not old_seq:
            continue
        start = h["new_start"] - 1
        end = start + len(new_seq)
        # 越界时尝试模糊定位
        if start < 0 or end > len(lines):
            found = _find_seq_in_lines(lines, new_seq, start) if new_seq else None
            if found is not None:
                start, end = found, found + len(new_seq)
            else:
                skipped += 1
                continue
        # 内容不一致时同样尝试模糊定位
        chunk = lines[start:end]
        if not _lines_equal_seq(chunk, new_seq) and not _lines_equal_seq(
            [x.rstrip() for x in chunk], [x.rstrip() for x in new_seq]
        ):
            found = _find_seq_in_lines(lines, new_seq, start) if new_seq else None
            if found is not None:
                start, end = found, found + len(new_seq)
            else:
                skipped += 1
                continue
        lines[start:end] = old_seq
    if skipped == len(hunks):
        return None
    return "\n".join(lines)


def derive_vulnerable(
    fixed_func: str | None, all_hunks: list[dict[str, Any]]
) -> str | None:
    """从修复后函数反推漏洞函数：将 added 行替换回 removed 行。

    若没有发生任何实质替换（结果与输入完全相同），返回 None 而非相同内容，
    避免 vulnerable_code == fixed_code 的无效爬取。
    """
    if not fixed_func:
        return None
    result = fixed_func
    changed = False
    for hunk in all_hunks:
        added, removed = hunk["added"], hunk["removed"]
        for i, add_item in enumerate(added):
            code = add_item["code"]
            if code in result:
                if i < len(removed):
                    new_result = result.replace(code, removed[i]["code"], 1)
                else:
                    new_result = re.sub(re.escape(code) + r"\n?", "", result, count=1)
                if new_result != result:
                    changed = True
                result = new_result
    if not changed:
        return None
    return result


def build_versions_from_diff(
    hunk_list: list[dict[str, Any]],
    full_src: str | None = None,
    mode_src: str = "new",
) -> tuple[str, str]:
    """从 diff hunk 直接构造修复前/后两个版本的代码片段。

    逻辑：
    - 修复前（vulnerable）：context 行 + `-` 行，去掉 `+` 行
    - 修复后（fixed）：context 行 + `+` 行，去掉 `-` 行

    当提供了 full_src（完整函数体）时，将 diff 窗口内的变更区域精确替换到函数体中，
    得到完整的两个函数版本。否则仅返回 diff 上下文窗口（带行号注释）。

    Returns:
        (vulnerable_code, fixed_code) — 两者保证不同（若 diff 无变更则均为空串）。
    """
    vuln_lines: list[str] = []
    fixed_lines: list[str] = []

    for h in hunk_list:
        body = h.get("body", "")
        for raw in body.splitlines():
            if not raw:
                continue
            kind = raw[0] if raw else " "
            code = raw[1:] if kind in ("+", "-", " ") else raw
            if kind == " ":
                vuln_lines.append(code)
                fixed_lines.append(code)
            elif kind == "-":
                vuln_lines.append(code)
                # 不加入 fixed
            elif kind == "+":
                # 不加入 vuln
                fixed_lines.append(code)

    vuln_window = "\n".join(vuln_lines)
    fixed_window = "\n".join(fixed_lines)

    if not full_src:
        # 无完整源文件：直接返回 diff 窗口，附行号注释
        vuln_snippet = patch_snippet(hunk_list, "old")
        fixed_snippet = patch_snippet(hunk_list, "new")
        return vuln_snippet, fixed_snippet

    # 有完整源文件：将 diff 窗口替换进函数体
    # 以 mode_src 对应侧的窗口内容在 full_src 中定位并替换
    src_window = fixed_window if mode_src == "new" else vuln_window
    other_window = vuln_window if mode_src == "new" else fixed_window

    if src_window and src_window in full_src:
        if mode_src == "new":
            # full_src 是修复后：替换出修复前
            vuln_full = full_src.replace(src_window, other_window, 1)
            fixed_full = full_src
        else:
            # full_src 是修复前：替换出修复后
            vuln_full = full_src
            fixed_full = full_src.replace(src_window, other_window, 1)
        if vuln_full.strip() != fixed_full.strip():
            return vuln_full, fixed_full

    # 定位失败（行内空白等原因）：退回 diff 窗口
    vuln_snippet = patch_snippet(hunk_list, "old")
    fixed_snippet = patch_snippet(hunk_list, "new")
    return vuln_snippet, fixed_snippet


def patch_snippet(hunk_list: list[dict[str, Any]], mode: str) -> str:
    lines = ["/* patch context - source file unavailable */"]
    for h in hunk_list:
        start = h["old_start"] if mode == "old" else h["new_start"]
        lines.append(f"/* ... line {start} ... */")
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
            lines.append(f"{lineno:5d}  {code}")
    return "\n".join(lines)
