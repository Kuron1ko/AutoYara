import argparse
import io
import json
import re
import sys
import time

from autoyara.models import to_legacy_result_dict

from .discovery import fetch_bulletin, parse_all_links
from .pipeline import process_item


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
    if r.get("vuln_title"):
        print("    VulnTitle: " + r["vuln_title"])
    if r.get("vuln_cve_hint"):
        print("    CVE(Hint): " + r["vuln_cve_hint"])
    if r.get("vuln_description"):
        print("\n    Vulnerability Description:")
        for ln in r["vuln_description"].splitlines():
            print("      " + ln)
    if r["removed_lines"]:
        print("\n    Key change (removed):")
        for x in r["removed_lines"]:
            if x["code"].strip() not in ("", "-", "- "):
                print(f"      {x['lineno']:4d}-  {x['code']}")
    if r["added_lines"]:
        print("    Key change (added):")
        for x in r["added_lines"]:
            print(f"      {x['lineno']:4d}+  {x['code']}")
    print("\n[1] VULNERABLE FUNCTION (before fix):")
    print(r["vulnerable_function"])
    print("\n[2] FIXED FUNCTION (after fix):")
    print(r["fixed_function"])
    print(sep)


def main(argv=None):
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
    cli = ap.parse_args(argv)
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
        print(
            "\n[CLI] commit-url mode owner={} repo={} sha={} patch_file={}".format(
                owner, repo, sha[:12], pf or "(none)"
            )
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
            f"\n[CLI] year={year} month={month} json={json_out} txt={txt_out} max={mx}"
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
        cve_set = {x["cve"] for x in all_links}
        print(f"\n== Found {len(all_links)} links across {len(cve_set)} CVEs ==")
        for x in all_links:
            print(
                f"  {x['cve']:<20} [{x['url_type']:<7}] {x['version_label'][:8]:<8} -> {x['url'][:60]}"
            )
    else:
        print(f"\n== Single commit mode: {len(all_links)} link(s) ==")
        for x in all_links:
            print(
                f"  {x['cve']:<20} [{x['url_type']:<7}] {x['version_label'][:8]:<8} -> {x['url'][:60]}"
            )

    if mx:
        all_links = all_links[:mx]

    all_results = []
    for i, item in enumerate(all_links, 1):
        print(
            f"\n[{i}/{len(all_links)}] {item['cve']} [{item['url_type']}] {item['version_label']}"
        )
        funcs = process_item(item)
        if funcs:
            for f in funcs:
                row = to_legacy_result_dict(f)
                print_result(row)
                all_results.append(row)
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
                "vuln_title": "",
                "vuln_description": "",
                "vuln_cve_hint": "",
                "vulnerable_function": "(diff fetch failed - {}: {})".format(
                    item["url_type"], item["url"]
                ),
                "fixed_function": "(diff fetch failed)",
            }
            print("  [!] no diff - saved as placeholder")
            all_results.append(placeholder)
        if i < len(all_links):
            time.sleep(1.0)

    if txt_out:
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
        f"\nDone. {len(all_results)} functions, {len({r['cve'] for r in all_results})} CVEs."
    )


if __name__ == "__main__":
    main()
