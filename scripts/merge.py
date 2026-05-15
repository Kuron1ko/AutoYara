from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Iterable


LICENSE_HEADER = """/*
 * Copyright (c) 2026 AutoYara Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */"""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _processed_dir() -> Path:
    return _repo_root() / "data" / "processed"


def _sanitize_identifier(text: str) -> str:
    cleaned = re.sub(r"[^0-9A-Za-z_]+", "_", (text or "").strip()).strip("_")
    return cleaned.lower() or "unknown"


def _extract_meta_block(yara_text: str) -> str:
    match = re.search(r"meta:\s*(.*?)\n\s*strings:", yara_text, flags=re.DOTALL)
    if not match:
        return 'date = ""\n        file = ""'
    block = match.group(1).strip("\n")
    lines = [line.rstrip() for line in block.splitlines()]
    normalized = []
    for line in lines:
        content = line.strip()
        if content:
            normalized.append(f"        {content}")
    return "\n".join(normalized) if normalized else '        date = ""\n        file = ""'


def _extract_condition(yara_text: str) -> str:
    match = re.search(r"condition:\s*(.*?)\n\}", yara_text, flags=re.DOTALL)
    if not match:
        return "$fix_flag"
    return match.group(1).strip()


def _extract_fix_hex(yara_text: str) -> str:
    match = re.search(r"\$fix_flag\s*=\s*\{([^}]*)\}", yara_text, flags=re.DOTALL)
    if not match:
        return ""
    raw = match.group(1)
    tokens = re.findall(r"[0-9A-Fa-f]{2}", raw)
    return " ".join(token.upper() for token in tokens)


def _extract_imports(yara_text: str) -> list[str]:
    imports = re.findall(r'^\s*import\s+"[^"]+"\s*$', yara_text, flags=re.MULTILINE)
    return [line.strip() for line in imports]


def _version_from_names(cve_id: str, folder_name: str, file_name: str) -> str:
    if folder_name.startswith(cve_id + "__"):
        return folder_name[len(cve_id) + 2 :]
    if folder_name.startswith(cve_id + "_"):
        return folder_name[len(cve_id) + 1 :]
    stem = Path(file_name).stem
    if stem.startswith(cve_id + "__"):
        return stem[len(cve_id) + 2 :]
    if stem.startswith(cve_id + "_"):
        return stem[len(cve_id) + 1 :]
    return "unknown"


def _iter_candidate_yaras(cve_id: str, processed_dir: Path) -> Iterable[tuple[str, Path]]:
    for folder in sorted(processed_dir.iterdir(), key=lambda p: p.name):
        if not folder.is_dir():
            continue
        if not folder.name.startswith(cve_id):
            continue
        if folder.name == cve_id:
            continue
        for yara_file in sorted(folder.glob("*.yara")):
            version = _version_from_names(cve_id, folder.name, yara_file.name)
            yield version, yara_file

    for yara_file in sorted(processed_dir.glob(f"{cve_id}_*.yara")):
        version = _version_from_names(cve_id, "", yara_file.name)
        yield version, yara_file
    for yara_file in sorted(processed_dir.glob(f"{cve_id}__*.yara")):
        version = _version_from_names(cve_id, "", yara_file.name)
        yield version, yara_file


def _iter_candidate_jsons(cve_id: str, processed_dir: Path) -> Iterable[tuple[str, Path]]:
    for folder in sorted(processed_dir.iterdir(), key=lambda p: p.name):
        if not folder.is_dir():
            continue
        if not folder.name.startswith(cve_id):
            continue
        if folder.name == cve_id:
            continue
        for json_file in sorted(folder.glob("*.json")):
            if json_file.name == "cveinfo.json":
                continue
            version = _version_from_names(cve_id, folder.name, json_file.name)
            yield version, json_file

    for json_file in sorted(processed_dir.glob(f"{cve_id}_*.json")):
        version = _version_from_names(cve_id, "", json_file.name)
        yield version, json_file
    for json_file in sorted(processed_dir.glob(f"{cve_id}__*.json")):
        version = _version_from_names(cve_id, "", json_file.name)
        yield version, json_file


def _dedup_keep_order(items: Iterable[str]) -> list[str]:
    out: list[str] = []
    for item in items:
        if item and item not in out:
            out.append(item)
    return out


def _replace_yara_rules(node: object, new_rule_name: str) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "yara_rules" and isinstance(value, list):
                node[key] = [new_rule_name]
            else:
                _replace_yara_rules(value, new_rule_name)
    elif isinstance(node, list):
        for item in node:
            _replace_yara_rules(item, new_rule_name)


def merge_yara(cve_id: str) -> Path:
    """Merge all version-specific YARA rules for one CVE into one OR-based rule."""
    processed_dir = _processed_dir()
    if not processed_dir.is_dir():
        raise FileNotFoundError(f"processed dir not found: {processed_dir}")

    candidates = list(_iter_candidate_yaras(cve_id, processed_dir))
    if not candidates:
        raise FileNotFoundError(f"no versioned yara files found for {cve_id}")

    signatures: list[tuple[str, str]] = []
    base_meta = ""
    base_condition = ""
    all_imports: list[str] = []

    for version, yara_path in candidates:
        text = yara_path.read_text(encoding="utf-8", errors="ignore")
        hex_str = _extract_fix_hex(text)
        if not hex_str:
            continue

        if not base_meta:
            base_meta = _extract_meta_block(text)
        if not base_condition:
            base_condition = _extract_condition(text)
        all_imports.extend(_extract_imports(text))

        name = f"fix_flag_{_sanitize_identifier(version)}"
        signatures.append((name, hex_str))

    if not signatures:
        raise ValueError(f"no non-empty $fix_flag signatures found for {cve_id}")

    unique_imports: list[str] = []
    for imp in all_imports:
        if imp not in unique_imports:
            unique_imports.append(imp)
    if not unique_imports:
        unique_imports = ['import "console"']

    or_expr = " or ".join(f"${name}" for name, _ in signatures)
    if "$fix_flag" in base_condition:
        merged_condition = re.sub(r"\$fix_flag\b", f"({or_expr})", base_condition)
    else:
        merged_condition = f"({or_expr}) and ({base_condition})"

    strings_block = "\n".join(
        f"        ${name} = {{{hex_str}}}" for name, hex_str in signatures
    )

    rule_name = cve_id.replace("-", "_")
    output_text = (
        f"{LICENSE_HEADER}\n"
        f"{chr(10).join(unique_imports)}\n"
        f"rule {rule_name}\n"
        "{\n"
        "    meta:\n"
        f"{base_meta}\n"
        "    strings:\n"
        f"{strings_block}\n"
        "    condition:\n"
        f"        {merged_condition}\n"
        "}\n"
    )

    out_dir = processed_dir / cve_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{cve_id}.yara"
    out_path.write_text(output_text, encoding="utf-8")
    return out_path


def merge_json(cve_id: str) -> Path:
    """Merge all version-specific JSON files for one CVE."""
    processed_dir = _processed_dir()
    if not processed_dir.is_dir():
        raise FileNotFoundError(f"processed dir not found: {processed_dir}")

    candidates = list(_iter_candidate_jsons(cve_id, processed_dir))
    if not candidates:
        raise FileNotFoundError(f"no versioned json files found for {cve_id}")

    parsed_items: list[tuple[str, Path, dict]] = []
    for version, json_path in candidates:
        try:
            data = json.loads(json_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        if isinstance(data, dict):
            parsed_items.append((version, json_path, data))

    if not parsed_items:
        raise ValueError(f"no valid json payloads found for {cve_id}")

    _, _, base = parsed_items[0]
    merged = json.loads(json.dumps(base, ensure_ascii=False))

    vulnerabilities = merged.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise ValueError(f"invalid json schema in {parsed_items[0][1]}")
    merged_vul = vulnerabilities[0]
    if not isinstance(merged_vul, dict):
        raise ValueError(f"invalid vulnerability entry in {parsed_items[0][1]}")

    merged_patch_info: dict = {}
    merged_versions: list[str] = []

    for version, _, data in parsed_items:
        vuls = data.get("vulnerabilities")
        if not isinstance(vuls, list) or not vuls:
            continue
        vul = vuls[0]
        if not isinstance(vul, dict):
            continue

        patch_info = vul.get("patch_info")
        if isinstance(patch_info, dict):
            for key, value in patch_info.items():
                if key not in merged_patch_info:
                    merged_patch_info[key] = value

        affected_versions = vul.get("affected_versions")
        if isinstance(affected_versions, list):
            merged_versions.extend(str(x).strip() for x in affected_versions if str(x).strip())
        else:
            v_clean = str(version).strip()
            if v_clean and v_clean != "unknown":
                merged_versions.append(v_clean.replace("_", "."))

    if merged_patch_info:
        merged_vul["patch_info"] = merged_patch_info
    if merged_versions:
        merged_vul["affected_versions"] = _dedup_keep_order(merged_versions)

    # Unified merged artifact uses merged yara file name without version suffix.
    _replace_yara_rules(merged_vul, f"{cve_id}.yara")

    out_dir = processed_dir / cve_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{cve_id}.json"
    out_path.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_path


def _main() -> int:
    parser = argparse.ArgumentParser(description="Merge versioned YARA rules by CVE id.")
    parser.add_argument("cve_id", help="CVE id, e.g. CVE-2026-33565")
    parser.add_argument("--json", action="store_true", help="also generate merged json")
    args = parser.parse_args()

    out_path = merge_yara(args.cve_id)
    print(f"[merge] generated: {out_path}")
    if args.json:
        json_out = merge_json(args.cve_id)
        print(f"[merge] generated: {json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = ["merge_yara", "merge_json"]
