
import sys
from pathlib import Path

# 设置 sys.path 指向 autoyara/src 目录
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "src"))
from autoyara.validation.runner import checkcve  # noqa: E402


def main():
    if len(sys.argv) != 2:
        print("用法: python test_validation.py <cve_id>")
        sys.exit(1)
    cve_id = sys.argv[1]
    try:
        result = checkcve(cve_id)
        print(f"{result.message}")
        print(f"fixed_matched: {result.fixed_matched}")
        print(f"unfixed_matched: {result.unfixed_matched}")
        print(f"return_code: {result.return_code}")
        sys.exit(result.return_code)
    except Exception as e:
        print(f"发生错误: {e}")
        sys.exit(-1)


if __name__ == "__main__":
    main()