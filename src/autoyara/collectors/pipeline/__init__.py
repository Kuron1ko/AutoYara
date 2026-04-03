"""CVE 条目处理流水线：拆分为上下文构建与按文件/函数提取。"""

from .process import process_item

__all__ = ["process_item"]
