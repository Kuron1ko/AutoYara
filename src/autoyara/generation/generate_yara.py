import os
from datetime import datetime

from jinja2 import Template


def split_hex_string(hex_str):
    if hex_str[3] == " ":
        return hex_str
    return " ".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2))


def generate_yara(cveitem: dict, hex_str: str) -> None:
    # 获取AutoYara根目录
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
    template_path = os.path.join(repo_root, "configs", "templates", "yara_rule.j2")
    with open(template_path, encoding="utf-8") as f:
        template_content = f.read()
    template = Template(template_content)

    cve_id = cveitem["cve"]
    file_name = cveitem["file"]

    date = datetime.now().strftime("%Y%m%d")
    rule_name = cve_id.replace("-", "_")
    output = template.render(
        cve_id=rule_name,
        date=date,
        file_name=file_name,
        hex_str=split_hex_string(hex_str),
        log_msg=f"{cve_id} testcase pass",
        copyright_year=datetime.now().year,
        copyright_holder="AutoYara Team",
    )

    out_dir = os.path.join(repo_root, "data", "processed", cve_id)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{cve_id}.yara")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(output)
