from __future__ import annotations

import sys
from pathlib import Path

from merge import merge_json, merge_yara
from run_stages import run_collector, run_generator

REPO_ROOT = Path(__file__).resolve().parents[1]
for p in (REPO_ROOT, REPO_ROOT / "src"):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)

# 生成2025年11月前五条
if __name__ == "__main__":
    success = []
    fail = []
    version = []

    for index in range(1, 6):
        cves_result = run_collector(2025, 11, index, index, do_llm=True)

        versions = []
        for item in cves_result:
            version = item.get("version")
            if version and version not in versions:
                versions.append(version)

        if not cves_result:
            continue

        res = run_generator(cves_result)
        if res == len(versions):
            success.append(cves_result[0].get("cve"))
        else:
            fail.append(cves_result[0].get("cve"))
    
    for cve_id in dict.fromkeys(success):
        if not cve_id:
            continue
        try:
            merge_yara(cve_id)
            merge_json(cve_id)
            print(f"[merge] {cve_id} merged yara/json")
        except Exception as exc:
            print(f"[merge] {cve_id} merge failed: {exc}")

    print(f"成功的CVE索引: {success}")
    print(f"失败的CVE索引: {fail}")
