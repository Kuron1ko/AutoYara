"""Compatibility shim for modules that import ``autoyara.config``."""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
project_root_str = str(PROJECT_ROOT)
if project_root_str not in sys.path:
    sys.path.insert(0, project_root_str)

from configs.config import Settings, settings

__all__ = ["Settings", "settings"]
