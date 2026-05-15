import json
import re
from pathlib import Path

from autoyara.llm.response_parser import parse_llm_json
from autoyara.llm.sync_client import SyncLLMClient

REPO_ROOT = Path(__file__).resolve().parents[3]

_SYSTEM_PROMPT = """\
你是漏洞规则生成专家，你的任务是根据CVE漏洞信息和Jinja2模板，生成符合要求的JSON文件。按照以下要求进行：\
1. 你将收到一个CVE漏洞的字典dict，包含漏洞的详细信息\
2. 你将收到模板metadata.json.j2，定义了最终JSON的结构和字段\
3. 你将收到示例example.json，用于参考最终JSON的格式和内容\
4. 细节说明：\
    - 对于 patch_info 字段，每个补丁项应包含 patch_url，patch_file 和 diff_file
    - 对于 affacted_device 字段，需要保留所有设备类型，并对每个受影响的设备填写yara字段\
    - 如果没有和affacted_device相关的信息，则不需要生成affacted_device字段

仅返回最终生成的JSON字符串，不要添加注释或markdown格式
"""

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


def _artifact_id(cve_id: str, version_value, override: str = "") -> str:
    if override:
        return override
    versions = _version_list(version_value)
    if not versions:
        return f"{cve_id}__unknown"
    parts = []
    for v in versions:
        t = re.sub(r"[^0-9A-Za-z]+", "_", v).strip("_").lower()
        if t:
            parts.append(t)
    suffix = "_".join(parts) if parts else "unknown"
    return f"{cve_id}__{suffix}"


def generate_json(meta_dict: dict, client: SyncLLMClient | None = None):
    cve_id = meta_dict.get("cve")
    artifact_id = _artifact_id(
        cve_id, meta_dict.get("version"), override=meta_dict.get("artifact_id", "")
    )
    own_client = client is None
    if own_client:
        client = SyncLLMClient()
    try:
        template_dir = REPO_ROOT / "configs" / "templates"
        with open(template_dir / "meta_example.json", encoding="utf-8") as f:
            example = json.load(f)
        with open(template_dir / "metadata.json.j2", encoding="utf-8") as f:
            metadata_template = f.read()

        user_content = (
            f"CVE: {cve_id or '(unknown)'}\n\n"
            f"[Meta Dict]\n{meta_dict}\n\n"
            f"[Metadata Template]\n{metadata_template}\n\n"
            f"[Example]\n{example}"
        )
        raw = client.chat(
            [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ]
        )

        data = parse_llm_json(raw)
        out_path = REPO_ROOT / "data" / "processed" / artifact_id / f"{artifact_id}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        print(data)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    # print(f"[generate_json] generated: {out_path}")

    except Exception as exc:
        print(f"[generator] failed to generate json: {exc}")
        return
    finally:
        if own_client and client is not None:
            client.close()
