import json
from pathlib import Path

from autoyara.llm.response_parser import parse_llm_json
from autoyara.llm.sync_client import SyncLLMClient

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


def generate_json(meta_dict: dict, client: SyncLLMClient | None = None):
    cve_id = meta_dict.get("cve")
    own_client = client is None
    if own_client:
        client = SyncLLMClient()
    try:
        with open(Path("configs/templates/meta_example.json"), encoding="utf-8") as f:
            example = json.load(f)
        with open(Path("configs/templates/metadata.json.j2"), encoding="utf-8") as f:
            metadata_template = f.read()

        user_content = (
            f"CVE：{cve_id or '（未知）'}\n\n"
            f"【漏洞描述】\n{meta_dict}\n\n"
            f"【metadata】\n{metadata_template}\n\n"
            f"【example】\n{example}"
        )
        raw = client.chat(
            [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ]
        )

        data = parse_llm_json(raw)
        out_path = Path("data/processed") / cve_id / f"{cve_id}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        print(data)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    # print(f"【generate_json】 已生成 {out_path}")

    except Exception as exc:
        print(f"【generator】 失败: {exc}")
        return
    finally:
        if own_client and client is not None:
            client.close()
