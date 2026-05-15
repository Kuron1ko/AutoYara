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

# Ensure UTF-8 stdout on Windows when possible.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Delayed imports after sys.path adjustment.
from autoyara.collectors.oh_crawler.cli import _apply_tokens_from_config_yaml
from autoyara.collectors.oh_crawler.discovery import fetch_bulletin, parse_all_links
from autoyara.collectors.oh_crawler.pipeline import process_item
from autoyara.generation.generate_json import generate_json
from autoyara.generation.generate_yara import generate_yara
from autoyara.llm.sync_client import SyncLLMClient
from autoyara.validation.runner import checkcve
from autoyara.models import sync_function_line_arrays, to_legacy_result_dict
from configs.config import settings
from autoyara.ReAct import AgentTask, AnalyzerAgent, LocatorAgent
from autoyara.llm.sync_client import create_sync_client

_apply_tokens_from_config_yaml()

FIXED_ELF_PATH = settings.fixed_elf_path
UNFIXED_ELF_PATH = settings.unfixed_elf_path

log_dir = REPO_ROOT / "logs"
log_dir.mkdir(exist_ok=True)
log_path = log_dir / f"test_all_{time.strftime('%Y%m%d_%H%M%S')}.txt"


def log(s):
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(str(s) + "\n")


def _version_list(value) -> list[str]:
    if isinstance(value, list):
        out = []
        for x in value:
            s = str(x).strip()
            if s and s not in out:
                out.append(s)
        return out
    s = str(value or "").strip()
    if not s:
        return []
    out = []
    for part in re.split(r"\s*/\s*|[;,]", s):
        v = part.strip()
        if v and v not in out:
            out.append(v)
    return out


def _version_suffix(versions: list[str]) -> str:
    if not versions:
        return "unknown"
    parts: list[str] = []
    for v in versions:
        t = re.sub(r"[^0-9A-Za-z]+", "_", v).strip("_").lower()
        if t:
            parts.append(t)
    return "_".join(parts) if parts else "unknown"


def _artifact_id(cve_id: str, version_value) -> str:
    versions = _version_list(version_value)
    return f"{cve_id}__{_version_suffix(versions)}"


def _version_name_candidates(version: str) -> list[str]:
    raw = str(version or "").strip()
    out: list[str] = []

    def _add(x: str) -> None:
        s = x.strip()
        if s and s not in out:
            out.append(s)

    if not raw:
        return out
    _add(raw)

    cleaned = re.sub(r"(?i)^openharmony[-_ ]*v?", "", raw).strip()
    _add(cleaned)
    _add(re.sub(r"(?i)[-_ ]*release$", "", cleaned).strip())
    _add(re.sub(r"(?i)\.x$", "", cleaned).strip())

    snapshot = list(out)
    for s in snapshot:
        _add(s.replace(".", "_"))
        _add(s.replace("-", "_"))
        _add(s.replace(" ", "_"))
    return out


def _resolve_versioned_elf(base_path: str, version_value, role: str) -> str:
    """Resolve ELF path for both modes.
    1) Old mode: base_path points to a single ELF file.
    2) New mode: base_path is a directory containing {version}_{role}[.elf].
    """
    p = Path(str(base_path or "").strip())
    if not str(base_path or "").strip():
        return ""

    # Old mode: direct file path.
    if (p.exists() and p.is_file()) or (p.suffix and not p.is_dir()):
        return str(p)

    versions = _version_list(version_value)
    v = versions[0] if versions else ""
    role_names = [role]
    if role == "unfix":
        role_names.append("unfixed")
    if role == "fixed":
        role_names.append("fix")

    cands: list[Path] = []
    for token in _version_name_candidates(v):
        for rn in role_names:
            for ext in (".elf", ".bin", ""):
                cands.append(p / f"{token}_{rn}{ext}")
                cands.append(p / f"{rn}_{token}{ext}")

    for c in cands:
        if c.exists() and c.is_file():
            return str(c)
    if cands:
        return str(cands[0])
    return str(p / f"unknown_{role}")


def call_function(func, *args, **kwargs):
    with (
        open(log_path, "a", encoding="utf-8") as f,
        redirect_stdout(f),
        redirect_stderr(f),
    ):
        return func(*args, **kwargs)


def build_item(cve_id: str, url: str, meta: dict) -> dict:
    """Build crawler item and pass through bulletin metadata fields."""
    url = re.sub(r"[?#].*$", "", url.strip())
    # Fields parsed from bulletin row.
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


def run_collector(year, month, start=1, end=50, do_llm=True) -> None:

    YEAR, MONTH, START, END = year, month, start, end
    if START < 1 or END < 1:
        raise ValueError("start and end must be >= 1")
    if START > END:
        raise ValueError("start cannot be greater than end")
    print(f"{'='*60}")
    print(f"[collector] OpenHarmony advisory {YEAR}-{MONTH:02d} range {START}-{END}")
    print(f"[LLM] quality check: {'on' if do_llm else 'off'}")

    # 1. Fetch bulletin
    print("[collector] fetching bulletin")
    md = call_function(fetch_bulletin, YEAR, MONTH)
    if not md:
        print("[collector] failed to fetch bulletin, exit")
        sys.exit(1)

    # 2. Parse links
    print("[collector] parsing links")
    all_links = parse_all_links(md)  # list of CrawlerItem-like dict
    log(f"  bulletin links total: {len(all_links)}")

    # Deduplicate by (CVE, version): keep one entry per pair.
    seen_entries: dict[tuple[str, str], dict] = {}
    for lk in all_links:
        cve = (lk.get("cve") or lk.get("cve_id") or "").upper()
        if not cve:
            continue
        ver = (lk.get("version_label") or lk.get("version") or "").strip() or "unknown"
        key = (cve, ver)
        if key not in seen_entries:
            seen_entries[key] = dict(lk)

    # Select by CVE range, but keep all versions for each selected CVE.
    entries_by_cve: dict[str, list[tuple[tuple[str, str], dict]]] = {}
    for item in seen_entries.items():
        (cve_id, _ver), _lk = item
        entries_by_cve.setdefault(cve_id, []).append(item)

    selected_cves = list(entries_by_cve.keys())[START - 1 : END]
    cve_list: list[tuple[tuple[str, str], dict]] = []
    for cve_id in selected_cves:
        cve_list.extend(entries_by_cve[cve_id])

    print("[collector] CVE list:")
    for (cve_id, ver), _ in cve_list:
        print(f" {cve_id} [{ver}] ")

    # 3. Process each CVE entry.
    print("[collector] processing CVE entries")
    client = SyncLLMClient() if do_llm else None
    all_results: list[dict] = []

    try:
        for _idx, ((cve_id, _ver), lk) in enumerate(cve_list, 1):
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
                row["bulletin_month"] = f"{YEAR}-{MONTH:02d}"
                sync_function_line_arrays(row)
                all_results.append(row)

                fn = row.get("function_name", "")
                vf = row.get("vulnerable_function", "")
                ff = row.get("fixed_function", "")
                qok = row.get("quality_ok")
                qstr = "PASS" if qok is True else "FAIL" if qok is False else "-"
                vtype = row.get("vuln_type", "")
                impact = row.get("vuln_impact", "")
                print(f"[{qstr}] {fn}  before={len(vf)}c after={len(ff)}c")
                if vtype or impact:
                    log(f"       vuln_type: {vtype}  vuln_impact: {impact}")
                if row.get("quality_reason"):
                    log(f"       LLM: {row['quality_reason'][:120]}")

                time.sleep(1.0)  # polite interval
    finally:
        if client:
            client.close()

    # 4. Save output
    print("\n[collector] saving output ...")
    out_dir = REPO_ROOT / "output"
    out_dir.mkdir(exist_ok=True)

    range_tag = f"{YEAR}_{MONTH:02d}_{START}_{END}"
    json_path = out_dir / f"range_{range_tag}.json"
    report_path = out_dir / f"range_{range_tag}.md"

    payload = {
        "year": YEAR,
        "month": MONTH,
        "start": START,
        "end": END,
        "total": len(all_results),
        "items": all_results,
    }
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    # Generate markdown report
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
        print(f"[collector] report generated: {report_path}")

    seen_cves_out = []
    seen_cves_result = []
    for r in all_results:
        cve_out = r.get("cve") or r.get("cve_id", "")
        ver_list = _version_list(r.get("version"))
        key = f"{cve_out}@{'|'.join(ver_list) if ver_list else 'unknown'}"
        if r.get("quality_ok") is True and key not in seen_cves_out:
            seen_cves_out.append(key)
        if r.get("quality_ok") is True:
            seen_cves_result.append(r)
    if do_llm:
        print(f"[LLM] passed={len(seen_cves_result)}")

    print(f"[collector] successful CVE keys: {seen_cves_out}")

    # Write successful CVE+version records into data/processed/<cve__version>/cveinfo.json
    for r in seen_cves_result:
        cve_id = r.get("cve") or r.get("cve_id", "")
        if cve_id:
            cveinfo = dict(r)
            cveinfo["version"] = _version_list(cveinfo.get("version"))
            artifact_id = _artifact_id(cve_id, cveinfo.get("version"))
            out_dir = REPO_ROOT / "data" / "processed" / artifact_id
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / "cveinfo.json"
            out_path.write_text(
                json.dumps(cveinfo, ensure_ascii=False, indent=2), encoding="utf-8"
            )
    return seen_cves_result


def run_validator(cves_result) -> None:
    print("=" * 60)
    print("[validator] start validating yara files")
    print("=" * 60)
    fail_cves = []
    success_cves = []
    for cveitem in cves_result:
        cve_id = cveitem.get("cve") or cveitem.get("cve_id", "")
        versions = _version_list(cveitem.get("version"))
        artifact_id = _artifact_id(cve_id, versions)
        fixed_elf_path = _resolve_versioned_elf(FIXED_ELF_PATH, versions, "fixed")
        unfixed_elf_path = _resolve_versioned_elf(UNFIXED_ELF_PATH, versions, "unfix")
        version_text = "/".join(versions) if versions else "unknown"
        key = f"{cve_id}@{version_text}"
        print(f"[validator] validating {key}")
        result = checkcve(
            cve_id,
            artifact_id=artifact_id,
            fixed_elf_path=fixed_elf_path,
            unfixed_elf_path=unfixed_elf_path,
        )
        if result.return_code == 0:
            success_cves.append(key)
            print(f"[validator] {key} pass")
        else:
            fail_cves.append(key)
            print(f"[validator] {key} fail")
    print(f"[validator] done\n success: {len(success_cves)} \nfail: {len(fail_cves)}")
    if len(success_cves) > 0:
        return 1
    else:
        return 0


def run_generator(cves_result) -> None:
    print("=" * 60)
    print("[generator] start generating yara/json files")
    print("=" * 60)

    client = create_sync_client()
    locator_agent = LocatorAgent(llm_client=client)
    analyzer_agent = AnalyzerAgent(llm_client=client)

    success_keys = []

    for cveitem in cves_result:
        cve_id = cveitem.get("cve", "")
        versions = _version_list(cveitem.get("version"))
        version_text = "/".join(versions) if versions else "unknown"
        success_key = f"{cve_id}@{version_text}"
        artifact_id = _artifact_id(cve_id, versions)
        fixed_elf_path = _resolve_versioned_elf(FIXED_ELF_PATH, versions, "fixed")
        unfixed_elf_path = _resolve_versioned_elf(UNFIXED_ELF_PATH, versions, "unfix")
        if success_key in success_keys:
            continue
        if not Path(unfixed_elf_path).is_file():
            print(
                f"[generator] skip {success_key}: unfixed ELF not found -> {unfixed_elf_path}"
            )
            continue
        if not Path(fixed_elf_path).is_file():
            print(
                f"[generator] skip {success_key}: fixed ELF not found -> {fixed_elf_path}"
            )
            continue

        function_name = cveitem.get("function_name", "")
        ida_name = (
            function_name.split("(", 1)[0]
            .strip()
            .split()[-1]
            .lstrip("*&")
            .rsplit("::", 1)[-1]
        )

        task = AgentTask(
            cve_id=cveitem.get("cve", ""),
            target_binary=unfixed_elf_path,
            description=(
                cveitem.get("vuln_description") or cveitem.get("description", "")
            ),
            vulnerable_code=cveitem.get("vulnerable_function", ""),
            fixed_code=cveitem.get("fixed_function", ""),
            function_name=ida_name,
        )
        vuln_res = locator_agent.run(task)
        task.target_binary = fixed_elf_path
        fixed_res = locator_agent.run(task)
        analyze_res = analyzer_agent.run(vuln_res, fixed_res, fixed_elf_path)

        hex_str = analyze_res.raw_hex
        print("=" * 20)
        print(analyze_res)
        # exit(0)
        resolved_function_name = (
            fixed_res.function_name or vuln_res.function_name or ida_name
        )
        json_meta = dict(cveitem)
        json_meta["version"] = versions
        json_meta["artifact_id"] = artifact_id
        json_meta["collector_function_name"] = cveitem.get("function_name", "")
        json_meta["function_name"] = resolved_function_name
        json_meta["binary_function_name"] = resolved_function_name
        json_meta["binary_signature_hex"] = hex_str
        json_meta["binary_evidence"] = {
            "binary_function_name": resolved_function_name,
            "collector_function_name": cveitem.get("function_name", ""),
            "vulnerable_elf": {
                "path": unfixed_elf_path,
                "start_address": vuln_res.start_address,
                "end_address": vuln_res.end_address,
            },
            "fixed_elf": {
                "path": fixed_elf_path,
                "start_address": fixed_res.start_address,
                "end_address": fixed_res.end_address,
            },
            "signature": {
                "raw_hex": hex_str,
                "rule_file": f"{artifact_id}.yara",
            },
        }

        log("=" * 20 + "vuln_res" + "=" * 20)
        log(vuln_res)
        log("=" * 20 + "fixed_res" + "=" * 20)
        log(fixed_res)
        log("=" * 20 + "analyze_res" + "=" * 20)
        log(analyze_res)
        print(f"[generator] {success_key} feature:", end="")
        print(hex_str)

        print(f"[generator] generating json for {success_key}")
        call_function(generate_json, json_meta)
        print(f"[generator] generating yara for {success_key}")
        yara_meta = dict(cveitem)
        yara_meta["version"] = versions
        yara_meta["artifact_id"] = artifact_id
        call_function(generate_yara, yara_meta, hex_str)
        print(f"[generator] generated {success_key}")

        cve_res = []
        cve_res.append(yara_meta)
        if run_validator(cve_res):
            success_keys.append(success_key)
            print(f"[generator] {success_key} generation pass")

    pass

    return len(success_keys)
