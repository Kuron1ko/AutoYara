# OpenHarmony CVE Crawler

本项目用于抓取 OpenHarmony 安全公告中的 CVE 链接，拉取修复补丁，提取漏洞函数（修复前）与修复函数（修复后），并输出为终端文本、JSON 或 TXT 报告。

当前主流程已采用统一数据模型：`process_item(item)` 返回 `list[AutoYaraDataModel]`。

## 项目结构与文件职责

当前代码以 `oh_crawler` 包组织，核心文件如下：

- `crawler.py`
  - 根目录启动入口（兼容旧方式）
  - 执行 `python crawler.py ...` 时会转到 `oh_crawler.cli.main()`

- `oh_crawler/__main__.py`
  - 包入口
  - 支持 `python -m oh_crawler ...`

- `oh_crawler/__init__.py`
  - 对外 API 门面
  - 统一导出常用函数（见 `__all__`），下游可直接 `from oh_crawler import ...`

- `oh_crawler/http_client.py`
  - 通用 HTTP 能力
  - 提供全局 `SESSION`、请求头 `H`、`get()` 方法

- `oh_crawler/gitcode.py`
  - GitCode API 适配层
  - 包含 token 读取、鉴权头、diff 归一化、PR/commit/blob/parent 相关接口

- `oh_crawler/discovery.py`
  - 公告与链接发现层
  - `fetch_bulletin(year, month)` 拉公告
  - `parse_all_links(md)` 解析 CVE 与链接条目
  - `classify_url(url)` 判断 commit/pr/patch 类型
  - `UPSTREAM` 第三方仓库映射

- `oh_crawler/diff_utils.py`
  - 补丁获取与解析层
  - `fetch_diff_text(item)` 根据链接条目拿 unified diff
  - `parse_diff_full(diff)` 将 diff 解析为结构化 hunk 数据
  - `pick_best_pr_commit_diff(...)` PR 多提交时选择主修复提交

- `oh_crawler/analysis.py`
  - 分析与提取层（源码、漏洞描述、函数重建）
  - 源码相关：`fetch_source()`、`get_parent_sha()`、`fetch_source_upstream()`
  - 漏洞描述：`fetch_vuln_description()`、`parse_vuln_desc_from_patch_text()`
  - 函数提取：`extract_function()`、`reconstruct_old_from_new()`、`derive_vulnerable()`

- `oh_crawler/pipeline.py`
  - 主流程编排层
  - `process_item(item)`：对单个链接条目执行完整处理并返回统一模型列表

- `oh_crawler/cli.py`
  - 命令行层
  - `main(argv=None)` 负责参数解析、执行流程、输出文件
  - `print_result(r)` 负责格式化打印结果

## 快速开始

## 环境要求

- Python 3.9+（建议）
- 依赖：`requests`、`urllib3`

安装依赖示例：

```bash
pip install requests urllib3
```

## 方式一：命令行运行（推荐）

### 1) 按年月抓公告并处理

```bash
python crawler.py --year 2026 --month 3 --json result.json --txt report.txt
```

或：

```bash
python -m oh_crawler --year 2026 --month 3 --max 20
```

### 2) 单条 commit 模式

```bash
python crawler.py --commit-url "https://gitcode.com/<owner>/<repo>/commit/<sha>" --cve CVE-XXXX-YYYY --json one.json
```

如果已有本地补丁可加速/兜底：

```bash
python crawler.py --commit-url "https://gitcode.com/<owner>/<repo>/commit/<sha>" --patch local.diff --json one.json
```

## 方式二：作为 Python 库调用

### 1) 推荐：从 `autoyara` 顶层导入（统一入口）

```python
from autoyara import fetch_bulletin, parse_all_links, process_item

md = fetch_bulletin(2026, 3)
items = parse_all_links(md)
models = process_item(items[0])  # list[AutoYaraDataModel]
first = models[0]
print(first.vulnerability.cve, first.function_location.file_path)
```

### 2) 兼容旧结构：转换为历史 dict

```python
from autoyara import process_item, to_legacy_result_dict

models = process_item(item)
legacy_rows = [to_legacy_result_dict(m) for m in models]
print(legacy_rows[0]["cve"], legacy_rows[0]["file"])
```

### 3) 分层调用（高级用法）

```python
from oh_crawler import fetch_diff_text, parse_diff_full

diff, repo, sha = fetch_diff_text(item)
hunks = parse_diff_full(diff)
```

```python
from oh_crawler import extract_function

func_text = extract_function(source_text, func_hint, target_lineno)
```

## 对外导出 API（`oh_crawler.__all__`）

常用函数包括：

- 主流程：`process_item`
- 公告/链接：`fetch_bulletin`、`parse_all_links`、`classify_url`
- diff：`fetch_diff_text`、`parse_diff_full`
- 源码/父提交：`fetch_source`、`get_parent_sha`、`get_upstream_commit_from_patch`
- 漏洞描述：`fetch_vuln_description`、`parse_vuln_desc_from_patch_text`
- 函数提取：`extract_function`
- 命令行：`main`、`print_result`

此外，项目已提供更稳定的公共导出入口：

- `autoyara`（推荐）：核心函数 + 公共数据模型
- `autoyara.collectors`：采集侧核心函数
- `autoyara.models`：统一数据模型、接口与兼容转换函数

## 结果数据说明

`process_item(item)` 返回 `list[AutoYaraDataModel]`。

你可以按对象属性访问：

- `model.vulnerability.cve`、`model.vulnerability.repository`
- `model.function_location.file_path`、`model.function_location.function_name`
- `model.diff_analysis.added_lines`、`model.diff_analysis.removed_lines`
- `model.function_location.vulnerable_function`
- `model.function_location.fixed_function`

如需兼容历史调用方，可通过 `to_legacy_result_dict(model)` 转成旧版字典，字段包括：

- `cve`、`repo`、`severity`、`version`
- `file`、`function_name`、`hunk_headers`
- `removed_lines`、`added_lines`
- `vuln_title`、`vuln_description`、`vuln_cve_hint`
- `vulnerable_function`（漏洞函数，修复前）
- `fixed_function`（修复函数，修复后）

## 漏洞函数保存在哪里

提取的漏洞文件 `vulnerable_function`。

- 运行中：保存在统一模型 `model.function_location.vulnerable_function`
- CLI 兼容输出：会自动转为历史字典并保存在 `all_results`
- 导出 JSON（`--json`）：位于 `items[].vulnerable_function`
- 导出 TXT（`--txt`）：在文本段落 `[1] VULNERABLE FUNCTION (before fix):` 下

对应修复函数字段为 `fixed_function`。

## 常见环境变量

- `GITCODE_PRIVATE_TOKEN` 或 `GITCODE_TOKEN`
  - 可选；用于访问受限仓库或提升 GitCode API 稳定性（公开仓库可匿名）
- `GITHUB_TOKEN` 或 `GITHUB_API_TOKEN`
  - 用于提升 GitHub API 限流稳定性

PowerShell 示例：

```powershell
$env:GITCODE_PRIVATE_TOKEN="your_token"
$env:GITHUB_TOKEN="your_token"
```

## 兼容性与入口说明

- `python crawler.py ...`：兼容旧入口
- `python -m oh_crawler ...`：包入口
- 下游模块建议：`from autoyara import process_item, AutoYaraDataModel, ...`
- 旧导入方式 `from oh_crawler import ...` 仍可使用（兼容保留）

## 最小下游接入模板

```python
from autoyara import fetch_bulletin, parse_all_links, process_item

def run_once(year: int, month: int):
    md = fetch_bulletin(year, month)
    if not md:
        return []
    items = parse_all_links(md)
    out = []
    for it in items:
        out.extend(process_item(it))
    return out
```
