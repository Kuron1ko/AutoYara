from __future__ import annotations

import sys
from pathlib import Path
from run_stages import run_collector, run_generator, run_validator

REPO_ROOT = Path(__file__).resolve().parents[1]
for p in (REPO_ROOT, REPO_ROOT / "src"):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)


if __name__ == "__main__":
    # 从2025年9月的公告中爬取前10条，并使用LLM解析
    cves_result = run_collector(2025, 9, 10, do_llm=True)
    run_generator(cves_result)
    run_validator(cves_result)
