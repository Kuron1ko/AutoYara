# OpenHarmony CVE 采集模块

从 OpenHarmony 安全公告或单条 commit 链接拉取补丁，解析并提取修复前/后函数代码，结果为 **`CVEItem`**（定义在 `autoyara.models`）。流水线内部使用 **`CrawlerLink`**（`collectors/internal_types.py`），不放入 `models`。

**不提供** `python -m …` 或包内 CLI；本地试跑请使用仓库根目录 **`scripts/`** 下的示例脚本，业务代码请 **`import autoyara.collector`**。

---

## 下游模块推荐用法

### 一键采集（最简）

```python
from autoyara.collector import CollectorConfig, collect_cve_items

cfg = CollectorConfig(
    year=2026,
    month=3,
    end_year=None,        # 与 end_month 同时设置则拉多月公告（闭区间）
    end_month=None,
    max_links=20,
    github_token="",      # 非空则写入 GITHUB_TOKEN 环境变量
    gitcode_token="",     # 非空则写入 GITCODE_PRIVATE_TOKEN 环境变量
    http_timeout_sec=25,
)
items = collect_cve_items(cfg, delay_between_links_sec=1.0)
for it in items:
    print(it.cve_id, it.file_path, len(it.vulnerable_code))
```

### 单条 commit

```python
from autoyara.collector import CollectorConfig, collect_cve_items

# commit_url 支持 gitee / gitcode / github commit 地址
cfg = CollectorConfig(
    commit_url="https://github.com/openharmony/kernel_linux_5.10/commit/<sha>",
    cve_override="CVE-2024-0000",
    local_patch_path=None,  # 或指向本地 .patch 文件以跳过在线拉 diff
)
items = collect_cve_items(cfg, delay_between_links_sec=0.0)
```

### 自行编排（细粒度）

```python
from autoyara.collector import (
    CollectorConfig,
    apply_collector_config,
    fetch_bulletin,
    parse_all_links,
    process_item,
)

cfg = CollectorConfig(year=2026, month=3, max_links=10)
apply_collector_config(cfg)          # 将 token/timeout 写入运行时环境
md = fetch_bulletin(2026, 3)         # 拉取安全公告 Markdown
for link in parse_all_links(md):     # 解析所有 CVE 链接
    for item in process_item(link):  # 每条链接 → list[CVEItem]
        print(item.cve_id, item.function_name)
```

序列化：`dataclasses.asdict(item)` 得到可直接 `json.dumps` 的字典（字段名：`cve_id`、`vulnerable_code`、`fixed_code`、`description` 等）。

---

## 目录与职责

| 位置 | 说明 |
|------|------|
| `autoyara.collector` | 对外导出 API |
| `collectors/orchestrate.py` | `links_from_config`、`collect_cve_items` |
| `collectors/runtime_config.py` | `apply_collector_config` |
| `collectors/pipeline/` | `process_item` 流水线 |
| `collectors/discovery.py` | 公告与链接解析 |
| `collectors/diff_utils.py` | 取 diff、解析 hunk |
| `collectors/analysis.py` | 源码与函数提取 |
| `collectors/gitcode.py` | GitCode API |
| `collectors/http_client.py` | HTTP 会话与 `get` |

---

## 本地示例脚本

| 脚本 | 作用 |
|------|------|
| `scripts/run_bulletin_month.py` | 按年月采集，写入 `output/bulletin_sample.json` |
| `scripts/run_single_commit.py` | 单 commit 模板（需改 `COMMIT_URL`） |

安装与运行（在仓库根目录）：

```bash
pip install -e .          # 自动安装 requests、urllib3 等依赖
python scripts/run_bulletin_month.py
```

---

## 环境变量（可选）

- `GITHUB_TOKEN` / `GITHUB_API_TOKEN`
- `GITCODE_PRIVATE_TOKEN` / `GITCODE_TOKEN`

也可通过 **`CollectorConfig.github_token` / `gitcode_token`** 在运行时注入（由 `apply_collector_config` 写入环境变量）。

**说明（GitCode commit 链接）**：漏洞标题/正文优先从 **GitHub** 上的 `.patch` 邮件头解析；并会用 **GitHub commit API** 补全说明。若你所在网络访问 GitHub 不稳定，请配置代理或 `GITHUB_TOKEN`。仅走 GitCode 时，**commit 页面多为前端渲染**，匿名调用 **GitCode REST 可能返回 403**，此时需要 **`GITCODE_PRIVATE_TOKEN`** 才能从 API 取提交说明。

---

## 对外 API 摘要

- **编排**：`collect_cve_items`、`links_from_config`、`apply_collector_config`
- **单链处理**：`process_item(link)`
- **公告**：`fetch_bulletin`、`parse_all_links`、`classify_url`
- **Diff**：`fetch_diff_text`、`parse_diff_full`、`pick_best_pr_commit_diff`
- **分析**：`fetch_source`、`get_parent_sha`、`fetch_vuln_description`、`extract_function` 等
- **模型**：`CollectorConfig`、`CVEItem`（从 `autoyara.models` 经 `autoyara.collector` 一并导出）
