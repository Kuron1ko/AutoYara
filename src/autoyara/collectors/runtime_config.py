"""将 CollectorConfig 应用到运行环境（环境变量、HTTP 超时等）。"""

import os

from autoyara.models import CollectorConfig

from . import http_client


def apply_collector_config(config: CollectorConfig) -> None:
    if config.github_token.strip():
        os.environ["GITHUB_TOKEN"] = config.github_token.strip()
    if config.gitcode_token.strip():
        os.environ["GITCODE_PRIVATE_TOKEN"] = config.gitcode_token.strip()
    if config.http_timeout_sec and config.http_timeout_sec > 0:
        http_client.HTTP_TIMEOUT_SEC = int(config.http_timeout_sec)
