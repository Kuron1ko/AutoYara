import json
import re
from pathlib import Path

from autoyara.llm.response_parser import parse_llm_json
from autoyara.llm.sync_client import SyncLLMClient

REPO_ROOT = Path(__file__).resolve().parents[3]

_SYSTEM_PROMPT = """\
浣犳槸婕忔礊瑙勫垯鐢熸垚涓撳锛屼綘鐨勪换鍔℃槸鏍规嵁CVE婕忔礊淇℃伅鍜孞inja2妯℃澘锛岀敓鎴愮鍚堣姹傜殑JSON鏂囦欢銆傛寜鐓т互涓嬭姹傝繘琛岋細\
1. 浣犲皢鏀跺埌涓€涓狢VE婕忔礊鐨勫瓧鍏竏ict锛屽寘鍚紡娲炵殑璇︾粏淇℃伅\
2. 浣犲皢鏀跺埌妯℃澘metadata.json.j2锛屽畾涔変簡鏈€缁圝SON鐨勭粨鏋勫拰瀛楁\
3. 浣犲皢鏀跺埌绀轰緥example.json锛岀敤浜庡弬鑰冩渶缁圝SON鐨勬牸寮忓拰鍐呭\
4. 缁嗚妭璇存槑锛歕
    - 瀵逛簬 patch_info 瀛楁锛屾瘡涓ˉ涓侀」搴斿寘鍚?patch_url锛宲atch_file 鍜?diff_file
    - 瀵逛簬 affacted_device 瀛楁锛岄渶瑕佷繚鐣欐墍鏈夎澶囩被鍨嬶紝骞跺姣忎釜鍙楀奖鍝嶇殑璁惧濉啓yara瀛楁\
    - 濡傛灉娌℃湁鍜宎ffacted_device鐩稿叧鐨勪俊鎭紝鍒欎笉闇€瑕佺敓鎴恆ffacted_device瀛楁

浠呰繑鍥炴渶缁堢敓鎴愮殑JSON瀛楃涓诧紝涓嶈娣诲姞娉ㄩ噴鎴杕arkdown鏍煎紡
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
