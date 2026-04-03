import re

from .http_client import get

UPSTREAM = {
    "third_party_libpng": ("pnggroup", "libpng", "master"),
    "third_party_libexif": ("libexif", "libexif", "master"),
    "third_party_curl": ("curl", "curl", "master"),
    "third_party_zlib": ("madler", "zlib", "master"),
    "third_party_openssl": ("openssl", "openssl", "master"),
    "third_party_expat": ("libexpat", "libexpat", "master"),
    "third_party_libwebp": ("webmproject", "libwebp", "main"),
}


def fetch_bulletin(year, month):
    for url in [
        f"https://gitee.com/openharmony/security/raw/master/zh/security-disclosure/{year}/{year}-{month:02d}.md",
        f"https://raw.githubusercontent.com/openharmony/security/master/zh/security-disclosure/{year}/{year}-{month:02d}.md",
    ]:
        print("[bulletin] " + url)
        t = get(url)
        if t and len(t) > 200 and ("CVE" in t or "|" in t):
            print(f"[OK] {len(t)} bytes")
            return t
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
