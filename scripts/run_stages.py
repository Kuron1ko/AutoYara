#!/usr/bin/env python3
""" """

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr

REPO_ROOT = Path(__file__).resolve().parents[1]
for p in (REPO_ROOT, REPO_ROOT / "src"):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)

# 确保 UTF-8 输出（-X utf8 或手动重配置）
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# sys.path 修改后的延迟导入（scripts 目录已在 pyproject.toml 中豁免 E402）
from autoyara.collectors.oh_crawler.cli import _apply_tokens_from_config_yaml
from autoyara.collectors.oh_crawler.discovery import fetch_bulletin, parse_all_links
from autoyara.collectors.oh_crawler.pipeline import process_item
from autoyara.generation.generate_json import generate_json
from autoyara.generation.generate_yara import generate_yara
from autoyara.llm.sync_client import SyncLLMClient
from autoyara.validation.runner import checkcve
from autoyara.ida.server import get_hex_from_ida
from autoyara.models import (
    sync_function_line_arrays,
    to_legacy_result_dict,
)
from configs.config import settings

_apply_tokens_from_config_yaml()

FIXED_ELF_PATH = settings.fixed_elf_path


log_dir = REPO_ROOT / "logs"
log_dir.mkdir(exist_ok=True)
log_path = log_dir / f"test_all_{time.strftime('%Y%m%d_%H%M%S')}.txt"


def log(s):
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(str(s) + "\n")


def call_function(func, *args, **kwargs):
    with (
        open(log_path, "a", encoding="utf-8") as f,
        redirect_stdout(f),
        redirect_stderr(f),
    ):
        return func(*args, **kwargs)


def build_item(cve_id: str, url: str, meta: dict) -> dict:
    """从公告链接构建 crawler_item，透传 vuln_type/vuln_impact 等公告元数据。"""
    url = re.sub(r"[?#].*$", "", url.strip())
    # 公告表格中的短标签字段
    common = {
        "cve": cve_id,
        "severity": meta.get("severity", ""),
        "version_label": meta.get("version_label", meta.get("version", "")),
        "vuln_title": meta.get("vuln_title", meta.get("title", "")),
        "vuln_type": meta.get("vuln_type", ""),
        "vuln_impact": meta.get("vuln_impact", ""),
    }
    pr_m = re.match(
        r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/(?:pulls|pull|merge_requests)/(\d+)",
        url,
        re.I,
    )
    if pr_m:
        return {
            **common,
            "url": url,
            "repo": meta.get("repo") or pr_m.group(2),
            "url_type": "pr",
        }
    cm = re.match(
        r"https?://(?:gitee|gitcode)\.com/([^/]+)/([^/]+)/commit/([0-9a-f]+)",
        url,
        re.I,
    )
    if cm:
        return {
            **common,
            "url": url,
            "repo": meta.get("repo") or cm.group(2),
            "url_type": "commit",
            "fix_sha": cm.group(3),
        }
    return {}


def run_collector(year, month, limit=50, do_llm=True) -> None:
    YEAR, MONTH, LIMIT = year, month, limit

    print(f"{'=' * 60}")
    print(f"【collector】OpenHarmony 安全公告 {YEAR}-{MONTH:02d}  前 {LIMIT} 个 CVE")
    print(f"【LLM】LLM 质量审查: {'启用' if do_llm else '跳过'}")
    print(f"{'=' * 60}")

    # ── 1. 拉公告 ───────────────────────────────────
    print("【collector】 拉取公告")
    md = call_function(fetch_bulletin, YEAR, MONTH)
    if not md:
        print("【collector】 无法获取公告，退出")
        sys.exit(1)

    # ── 2. 解析链接 ──────────────────────────────────
    print("【collector】 解析链接")
    all_links = parse_all_links(md)  # list of CrawlerItem-like dict
    log(f"  公告共含 {len(all_links)} 条链接")

    # 去重：每个 CVE 只取第一条（通常是 6.0.x 主版本）
    seen_cve: dict[str, dict] = {}
    for lk in all_links:
        cve = (lk.get("cve") or lk.get("cve_id") or "").upper()
        if cve and cve not in seen_cve:
            seen_cve[cve] = lk

    cve_list = list(seen_cve.items())[:LIMIT]
    print("【collector】 CVElist : ", end="")
    for cve, _lk in cve_list:
        print(f" {cve}  ")

    # ── 3. 逐个爬取 ──────────────────────────────────
    print("【collector】逐个爬取CVE")
    client = SyncLLMClient() if do_llm else None
    all_results: list[dict] = []

    try:
        for _idx, (cve_id, lk) in enumerate(cve_list, 1):
            url = lk.get("url") or lk.get("reference_url") or ""

            item = build_item(cve_id, url, lk)
            if not item:
                continue

            try:
                models = call_function(
                    process_item, item, quality_check=do_llm, llm_client=client
                )
            except Exception:
                models = []

            for m in models:
                row = to_legacy_result_dict(m)
                if m.validation is not None:
                    row["quality_ok"] = m.validation.is_valid
                    row["quality_score"] = m.validation.score
                    row["quality_reason"] = m.validation.details
                sync_function_line_arrays(row)
                all_results.append(row)

                fn = row.get("function_name", "")
                vf = row.get("vulnerable_function", "")
                ff = row.get("fixed_function", "")
                qok = row.get("quality_ok")
                qstr = "✓" if qok else "✗" if qok is False else "-"
                vtype = row.get("vuln_type", "")
                impact = row.get("vuln_impact", "")
                print(f"【{qstr}】 {fn}  before={len(vf)}c after={len(ff)}c")
                if vtype or impact:
                    log(f"       漏洞描述: {vtype}  漏洞影响: {impact}")
                if row.get("quality_reason"):
                    log(f"       LLM: {row['quality_reason'][:120]}")

                time.sleep(1.0)  # 礼貌间隔
    finally:
        if client:
            client.close()

    # ── 4. 写结果 ────────────────────────────────────
    print("\n【collector】 保存结果 …")
    out_dir = REPO_ROOT / "output"
    out_dir.mkdir(exist_ok=True)

    json_path = out_dir / "top10_2026_02.json"
    report_path = out_dir / "top10_2026_02.md"

    payload = {
        "year": YEAR,
        "month": MONTH,
        "total": len(all_results),
        "items": all_results,
    }
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    # 生成 Markdown 报告
    gen = REPO_ROOT / "scripts" / "gen_report.py"
    if gen.is_file():
        import subprocess

        r = subprocess.run(
            [sys.executable, str(gen), str(json_path), str(report_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        print(f"【collector】 已生成报告 → {report_path}")

    # ── 汇总打印 ─────────────────────────────────────
    ok = sum(1 for r in all_results if r.get("quality_ok") is True)
    fail = sum(1 for r in all_results if r.get("quality_ok") is False)
    skip = sum(1 for r in all_results if r.get("quality_ok") is None)
    if do_llm:
        print(f"【LLM】 LLM 审查: 通过={ok} 未通过={fail} 未审={skip}")

    seen_cves_out = []
    seen_cves_result = []
    for r in all_results:
        cve_out = r.get("cve") or r.get("cve_id", "")
        if r.get("quality_ok") is True and cve_out not in seen_cves_out:
            seen_cves_out.append(cve_out)
            seen_cves_result.append(r)

    print(f"  成功 CVE: {seen_cves_out}")

    # 枚举所有成功的 CVE，写入 /data/processed/cveid/cveinfo.json
    for r in seen_cves_result:
        cve_id = r.get("cve") or r.get("cve_id", "")
        if cve_id:
            out_dir = REPO_ROOT / "data" / "processed" / cve_id
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / "cveinfo.json"
            out_path.write_text(
                json.dumps(r, ensure_ascii=False, indent=2), encoding="utf-8"
            )
    return seen_cves_result


def run_generator(cves_result) -> None:
    print("=" * 60)
    print("【generator】开始生成yara/json文件")
    print("=" * 60)

    for cveitem in cves_result:
        cve_id = cveitem.get("cve") or cveitem.get("cve_id", "")
        function_name = cveitem.get("function_name", "")
        ida_name = function_name.split("(", 1)[0].strip().split()[-1].lstrip("*&")
        ida_result = get_hex_from_ida(FIXED_ELF_PATH, ida_name)
        hex_str = ida_result.split("\n", 1)[1].strip()
        hex_str = hex_str.split("\n", 1)[0].strip()

        print(f"【generator】生成 {cve_id} 的json文件")
        call_function(generate_json, cveitem)
        print(f"【generator】生成 {cve_id} 的yara规则")
        call_function(generate_yara, cveitem, hex_str)
        print(f"【generator】已生成 {cve_id}")
    pass


def run_validator(cves_result) -> None:
    print("=" * 60)
    print("【validator】开始验证yara文件")
    print("=" * 60)
    fail_cves = []
    success_cves = []
    for cveitem in cves_result:
        cve_id = cveitem.get("cve") or cveitem.get("cve_id", "")
        print(f"【validator】验证 {cve_id}")
        result = checkcve(cve_id)
        if result.return_code == 0:
            success_cves.append(cve_id)
            print(f"【validator】 {cve_id} 验证通过")
        else:
            fail_cves.append(cve_id)
            print(f"【validator】 {cve_id} 验证失败")
    print(f"【validator】验证完成\n 成功: {len(success_cves)} \n失败: {len(fail_cves)}")
