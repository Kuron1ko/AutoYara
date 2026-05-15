import os
import re
from datetime import datetime

from jinja2 import Template


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


def generate_yara(cveitem: dict, hex_str: str) -> None:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
    template_path = os.path.join(repo_root, "configs", "templates", "yara_rule.j2")
    with open(template_path, encoding="utf-8") as f:
        template_content = f.read()
    template = Template(template_content)

    cve_id = cveitem["cve"]
    artifact_id = _artifact_id(
        cve_id, cveitem.get("version"), override=cveitem.get("artifact_id", "")
    )
    file_name = cveitem["file"]

    date = datetime.now().strftime("%Y%m%d")
    rule_name = cve_id.replace("-", "_")
    output = template.render(
        cve_id=rule_name,
        date=date,
        file_name=file_name,
        hex_str=hex_str,
        log_msg=f"{cve_id} testcase pass",
        copyright_year=datetime.now().year,
        copyright_holder="Beijing University of Posts and Telecommunications",
    )

    out_dir = os.path.join(repo_root, "data", "processed", artifact_id)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{artifact_id}.yara")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(output)

