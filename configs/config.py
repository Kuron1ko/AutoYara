# 项目全局配置：python 可执行路径等

import os
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = Path(__file__).parent / "config.yaml"


def _load_config():
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return yaml.safe_load(f)
    raise FileNotFoundError(
        f"配置文件未找到: {CONFIG_PATH}\n请参考 config.yaml.example 创建 config.yaml"
    )


_config = _load_config()


def get_python_path() -> str:
    return _config["PYTHON_PATH"]


def get_ida_path() -> str:
    return _config["IDA_PATH"]


def get_log_dir() -> str:
    log_dir = os.path.join(PROJECT_ROOT, "logs")
    os.makedirs(log_dir, exist_ok=True)
    return log_dir


def get_tmp_dir() -> str:
    tmp_dir = os.path.join(PROJECT_ROOT, "tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    return tmp_dir


def get_openai_api_key() -> str:
    return _config.get("OPENAI_API_KEY", "")


def get_server_cmd():
    return [
        get_python_path(),
        str(PROJECT_ROOT / "src" / "AutoYara" / "ida" / "server.py"),
    ]


__all__ = [
    "get_tmp_dir",
    "get_python_path",
    "get_ida_path",
    "get_log_dir",
    "get_openai_api_key",
    "get_server_cmd",
]
