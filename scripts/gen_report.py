#!/usr/bin/env python3
"""
从 output/bulletin_sample.json 生成可读的 Markdown 报告。

用法（仓库根目录）::

    python scripts/gen_report.py
    # 输出到 output/cve_report.md
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

INPUT = REPO_ROOT / "output" / "bulletin_sample.json"
OUTPUT = REPO_ROOT / "output" / "cve_report.md"


def _code_block(code: str, lang: str = "c") -> str:
    code = (code or "").strip()
    if not code:
        return "_（未提取到代码）_\n"
    return f"```{lang}\n{code}\n```\n"


def _guess_lang(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    return {
        ".c": "c",
        ".h": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".py": "python",
        ".rs": "rust",
        ".go": "go",
        ".java": "java",
        ".patch": "diff",
    }.get(ext, "c")


def dedup(items: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out = []
    for it in items:
        key = (
            it.get("cve_id", ""),
            it.get("file_path", ""),
            it.get("function_name", ""),
            (it.get("vulnerable_code") or "")[:64],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out


def main() -> None:
    if not INPUT.exists():
        print(f"找不到 {INPUT}，请先运行 scripts/run_bulletin_month.py")
        sys.exit(1)

    raw: list[dict] = json.loads(INPUT.read_text(encoding="utf-8"))
    items = dedup(raw)

    # 按 CVE 分组
    groups: dict[str, list[dict]] = {}
    for it in items:
        cve = it.get("cve_id") or "UNKNOWN"
        groups.setdefault(cve, []).append(it)

    lines: list[str] = []
    lines.append("# CVE 漏洞采集报告\n")
    lines.append(
        f"> 来源：`{INPUT.name}`  共 **{len(items)}** 条（去重后），"
        f"涉及 **{len(groups)}** 个 CVE\n"
    )
    lines.append("---\n")

    # 目录
    lines.append("## 目录\n")
    for cve, its in groups.items():
        repo = its[0].get("repository", "")
        sev = its[0].get("severity", "")
        anchor = cve.lower().replace("-", "")
        lines.append(f"- [{cve}](#{anchor})  `{repo}` {sev}  （{len(its)} 个函数）")
    lines.append("\n---\n")

    # 每个 CVE 详情
    for cve, its in groups.items():
        anchor = cve.lower().replace("-", "")
        repo = its[0].get("repository", "")
        sev = its[0].get("severity", "")
        ref = its[0].get("reference_url", "")

        lines.append(f'<a id="{anchor}"></a>\n')
        lines.append(f"## {cve}  ·  {repo}  ·  {sev}\n")
        if ref:
            lines.append(f"**参考链接**：<{ref}>\n")

        # 描述（取第一条有内容的）
        title = next((it.get("title", "") for it in its if it.get("title")), "")
        desc = next(
            (it.get("description", "") for it in its if it.get("description")), ""
        )
        if title:
            lines.append(f"**标题**：{title}\n")
        if desc:
            lines.append("**漏洞描述**：\n")
            lines.append(f"> {desc.strip().replace(chr(10), chr(10) + '> ')}\n")
        else:
            lines.append(
                "**漏洞描述**：_（未获取到描述，可能需要 GITCODE_PRIVATE_TOKEN 或 GITHUB_TOKEN）_\n"
            )

        lines.append(f"\n共涉及 **{len(its)}** 个函数／代码区域：\n")

        for j, it in enumerate(its, 1):
            func = it.get("function_name") or "（无函数名）"
            fpath = it.get("file_path", "")
            lang = _guess_lang(fpath)
            hunks = it.get("hunk_headers") or []
            added = len(it.get("added_lines") or [])
            removed = len(it.get("removed_lines") or [])
            is_complete = it.get("is_complete", True)

            # 完整性标记
            completeness = (
                "✅ 完整函数体（源文件已获取）"
                if is_complete
                else "⚠️ 仅 diff 上下文（源文件不可用，代码不完整）"
            )

            lines.append(f"### {j}. `{func}`\n")
            lines.append(
                f"**文件**：`{fpath}`  |  **变更**：+{added} / -{removed} 行  |  {completeness}\n"
            )
            if hunks:
                lines.append(
                    "**Hunk 位置**：" + "、".join(f"`{h}`" for h in hunks) + "\n"
                )

            vuln_code = (it.get("vulnerable_code") or "").strip()
            fixed_code = (it.get("fixed_code") or "").strip()

            if not is_complete:
                # 不完整：将两个 diff 窗口并排展示，用 diff 格式高亮变更
                lines.append("\n#### 代码变更（diff 上下文，源文件不可用）\n")
                removed_lines = it.get("removed_lines") or []
                added_lines = it.get("added_lines") or []
                if removed_lines or added_lines:
                    lines.append("```diff")
                    for r in removed_lines:
                        lines.append(f"- {r.get('code', '')}")
                    for a in added_lines:
                        lines.append(f"+ {a.get('code', '')}")
                    lines.append("```\n")
                    if vuln_code:
                        lines.append(
                            "<details><summary>修复前上下文窗口（展开）</summary>\n"
                        )
                        lines.append(_code_block(vuln_code, lang))
                        lines.append("</details>\n")
                    if fixed_code:
                        lines.append(
                            "<details><summary>修复后上下文窗口（展开）</summary>\n"
                        )
                        lines.append(_code_block(fixed_code, lang))
                        lines.append("</details>\n")
                else:
                    lines.append("_（无行级变更记录）_\n")
            else:
                # 完整：直接展示两个完整函数体
                lines.append("\n#### 漏洞函数（修复前）\n")
                lines.append(_code_block(vuln_code, lang))

                lines.append("\n#### 修复函数（修复后）\n")
                lines.append(_code_block(fixed_code, lang))

                lines.append("\n#### 关键变更行\n")
                removed_lines = it.get("removed_lines") or []
                added_lines = it.get("added_lines") or []
                if removed_lines or added_lines:
                    lines.append("```diff")
                    for r in removed_lines:
                        lines.append(f"- {r.get('code', '')}")
                    for a in added_lines:
                        lines.append(f"+ {a.get('code', '')}")
                    lines.append("```\n")
                else:
                    lines.append("_（无行级变更记录）_\n")

            lines.append("\n---\n")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"报告已生成：{OUTPUT}  （共 {len(items)} 条，{len(groups)} 个 CVE）")


if __name__ == "__main__":
    main()
