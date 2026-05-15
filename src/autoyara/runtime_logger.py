from __future__ import annotations

import os
import time
from dataclasses import dataclass

from autoyara.config import settings

ENV_CONSOLE_LOG = "AUTOYARA_LOG_TO_CONSOLE"
ENV_LOG_LEVEL = "AUTOYARA_LOG_LEVEL"
DEFAULT_LEVEL = "INFO"
DEBUG_LEVEL = "DEBUG"
_LEVEL_PRIORITY = {
    "DEBUG": 10,
    "INFO": 20,
    "WARN": 30,
    "ERROR": 40,
}

_RESET = "\033[0m"
_TIME_COLOR = "\033[90m"
_LEVEL_COLORS = {
    "DEBUG": "\033[94m",
    "INFO": "\033[36m",
    "WARN": "\033[33m",
    "ERROR": "\033[31m",
}
_CONTENT_COLOR = "\033[37m"
_DETAIL_COLORS = {
    "TASK": "\033[34m",
    "STEP": "\033[35m",
    "LLM_RESPONSE": "\033[96m",
    "THOUGHT": "\033[94m",
    "ACTION": "\033[95m",
    "ACTION_INPUT": "\033[93m",
    "TOOL_EXEC": "\033[92m",
    "OBSERVATION": "\033[92m",
    "FINAL_ANSWER": "\033[32m",
    "ERROR": "\033[31m",
}
_DETAIL_DEFAULT_COLOR = "\033[35m"


def _console_enabled() -> bool:
    value = os.getenv(ENV_CONSOLE_LOG, "0").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _read_log_level() -> str:
    value = os.getenv(ENV_LOG_LEVEL, DEFAULT_LEVEL).strip().upper()
    return value if value in _LEVEL_PRIORITY else DEFAULT_LEVEL


def _build_log_path(prefix: str, task_id: str) -> str:
    ts = int(time.time())
    safe_task_id = "".join(
        ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in task_id
    )
    return os.path.join(settings.log_dir, f"{prefix}_{safe_task_id}_{ts}.log")


@dataclass(slots=True)
class RuntimeLogger:
    file_path: str
    enable_console: bool = False
    min_level: str = DEFAULT_LEVEL

    def log(self, detail: str, message: str, level: str = DEFAULT_LEVEL) -> None:
        level_text = (level or DEFAULT_LEVEL).upper()
        threshold = _LEVEL_PRIORITY.get(
            self.min_level.upper(), _LEVEL_PRIORITY[DEFAULT_LEVEL]
        )
        current = _LEVEL_PRIORITY.get(level_text, _LEVEL_PRIORITY["ERROR"])
        if current < threshold:
            return
        detail_text = (detail or "GENERAL").strip().upper()
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        lines = message.splitlines() or [""]
        with open(self.file_path, "a", encoding="utf-8") as f:
            for line in lines:
                f.write(f"[{ts}] [{level_text}] [{detail_text}] {line}\n")
        if self.enable_console:
            detail_color = _DETAIL_COLORS.get(detail_text, _DETAIL_DEFAULT_COLOR)
            level_color = _LEVEL_COLORS.get(level_text, _LEVEL_COLORS["INFO"])
            for line in lines:
                print(
                    f"{_TIME_COLOR}[{ts}]{_RESET} "
                    f"{level_color}[{level_text}]{_RESET} "
                    f"{detail_color}[{detail_text}]{_RESET} "
                    f"{_CONTENT_COLOR}{line}{_RESET}"
                )

    def info(self, detail: str, message: str) -> None:
        self.log(detail=detail, message=message, level=DEFAULT_LEVEL)

    def debug(self, detail: str, message: str) -> None:
        self.log(detail=detail, message=message, level=DEBUG_LEVEL)

    def warn(self, detail: str, message: str) -> None:
        self.log(detail=detail, message=message, level="WARN")

    def warning(self, detail: str, message: str) -> None:
        self.warn(detail=detail, message=message)

    def error(self, detail: str, message: str) -> None:
        self.log(detail=detail, message=message, level="ERROR")


def create_runtime_logger(prefix: str, task_id: str) -> RuntimeLogger:
    return RuntimeLogger(
        file_path=_build_log_path(prefix=prefix, task_id=task_id),
        enable_console=_console_enabled(),
        min_level=_read_log_level(),
    )
