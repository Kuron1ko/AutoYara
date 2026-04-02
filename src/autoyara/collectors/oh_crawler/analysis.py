import json
import os
import re

from .discovery import UPSTREAM
from .gitcode import (
    fetch_gitcode_file_blob,
    get_parent_sha_gitcode,
    gitcode_auth_headers,
    gitcode_private_token,
)
from .http_client import SESSION, H, get

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
    """从 torvalds/linux 获取上游 commit 的 parent SHA"""
    if not upstream_sha:
        return None, None
    t = get(f"https://api.github.com/repos/torvalds/linux/commits/{upstream_sha}")
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
    return {"title": title, "description": desc, "cve": cve}


def fetch_commit_meta_from_api(owner, repo, sha):
    """尝试从 GitHub/Gitee/GitCode API 获取 commit message。"""
    msg = ""
    if owner and repo and sha:
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
                    msg = ((data.get("commit") or {}).get("message") or "").strip()
                    if msg:
                        return msg
            except Exception:
                pass
        try:
            t = get(f"https://gitee.com/api/v5/repos/{owner}/{repo}/commits/{sha}")
            if t:
                data = json.loads(t)
                msg = (
                    data.get("commit", {}).get("message")
                    or data.get("message")
                    or data.get("title")
                    or ""
                ).strip()
                if msg:
                    return msg
        except Exception:
            pass
        if gitcode_private_token():
            try:
                url = f"https://gitcode.com/api/v5/repos/{owner}/{repo}/commits/{sha}"
                r = SESSION.get(
                    url, headers=gitcode_auth_headers(), timeout=25, verify=False
                )
                r.raise_for_status()
                data = r.json()
                msg = (
                    data.get("commit", {}).get("message")
                    or data.get("message")
                    or data.get("title")
                    or ""
                ).strip()
                if msg:
                    return msg
            except Exception:
                pass
    return ""


def fetch_vuln_description(item, diff_text):
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
    m = re.match(
        r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)", url, re.I
    )
    owner = m.group(1) if m else "openharmony"
    repo = m.group(2) if m else item.get("repo", "")
    sha = m.group(3) if m else item.get("fix_sha")
    if not (title and desc):
        msg = fetch_commit_meta_from_api(owner, repo, sha)
        if msg:
            lines = [x.strip() for x in msg.splitlines()]
            lines = [x for x in lines if _clean_desc_line(x)]
            if lines:
                if not title:
                    title = lines[0]
                if not desc:
                    desc = "\n".join(lines[1:12]).strip()
    if not (title and desc) and url:
        page = get(url, allow_html=True)
        txt = strip_html_to_text(page or "")
        if txt:
            if not cve:
                c = re.search(r"\b(CVE-\d{4}-\d+)\b", txt, re.I)
                if c:
                    cve = c.group(1).upper()
            if not title:
                tm = re.search(
                    r"(?:commit|修复|fix)\s*[:：]?\s*([^.]{20,200})", txt, re.I
                )
                if tm:
                    title = tm.group(1).strip()
            if not desc:
                dm = re.search(
                    r"(?:Upstream commit.*?)(object_err\(\).*?not crash in the process\.)",
                    txt,
                    re.I,
                )
                if dm:
                    desc = dm.group(1).strip()
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


def extract_function(source, func_hint, target_lineno):
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


def reconstruct_old_from_new(new_src, hunks):
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
                f"  [reconstruct] 行号越界 new_start={h.get('new_start')} "
                f"need [{start},{end}) len={len(lines)}"
            )
            return None
        chunk = lines[start:end]
        if not _lines_equal_seq(chunk, new_seq):
            if not _lines_equal_seq(
                [x.rstrip() for x in chunk], [x.rstrip() for x in new_seq]
            ):
                print(
                    "  [reconstruct] 与 diff 中新侧行不一致 new_start={}".format(
                        h.get("new_start")
                    )
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
