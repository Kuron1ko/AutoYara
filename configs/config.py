import os
from dataclasses import dataclass
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = Path(__file__).parent / "config.yaml"


@dataclass(slots=True)
class Settings:
    python_path: str
    ida_path: str
    openai_api_key: str = ""
    openai_base_url: str = ""
    fixed_elf_path: str = ""
    unfixed_elf_path: str = ""

    @property
    def log_dir(self) -> str:
        log_dir = os.path.join(PROJECT_ROOT, "logs")
        os.makedirs(log_dir, exist_ok=True)
        return log_dir

    @property
    def tmp_dir(self) -> str:
        tmp_dir = os.path.join(PROJECT_ROOT, "tmp")
        os.makedirs(tmp_dir, exist_ok=True)
        return tmp_dir

    @property
    def server_cmd(self) -> list[str]:
        return [
            self.python_path,
            str(PROJECT_ROOT / "src" / "autoyara" / "ida" / "server.py"),
        ]

    @property
    def data_dir(self) -> str:
        data_dir = os.path.join(PROJECT_ROOT, "data")
        os.makedirs(data_dir, exist_ok=True)
        return data_dir


def _load_settings() -> Settings:
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"配置文件未找到: {CONFIG_PATH}\n请参考 config.yaml.example 创建 config.yaml"
        )
    with open(CONFIG_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return Settings(
        python_path=data["PYTHON_PATH"],
        ida_path=data["IDA_PATH"],
        fixed_elf_path=data["FIXED_ELF_PATH"],
        unfixed_elf_path=data["UNFIXED_ELF_PATH"],
        openai_api_key=data.get("OPENAI_API_KEY", ""),
        openai_base_url=data.get("OPENAI_BASE_URL", ""),
    )


settings = _load_settings()

__all__ = ["settings", "Settings"]
