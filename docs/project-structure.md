# AutoYara 项目文件结构

## 1. 设计目标

这一版目录结构完全按当前 MVP 目标收敛，只保留最核心的分析闭环与必要支撑目录。

它服务的重点只有两件事：

- 支撑 `定位函数 -> 分析差异 -> 提取特征 -> 生成 hex -> 验证 -> 生成 YARA/JSON` 主链路
- 保留原始结果、处理结果、输出产物、临时文件和日志，方便调试与复盘

## 2. 约定目录树

```text
AutoYara/
├─ README.md
├─ docs/                        # 文档
│  ├─ architecture.md
│  └─ project-structure.md
├─ src/
│  └─ autoyara/
│     ├─ ReAct/                 # Agent状态维护和动作选择
│     ├─ ida/                   # IDA核心功能
│     ├─ analysis/              # 分析（定位函数 -> 分析差异 -> 提取特征 -> 生成 hex）
│     ├─ validation/            # 验证
│     ├─ generation/            # 生成Yara和Json
│     └─ models/                # 数据结构
├─ scripts/                     # 运行脚本
├─ data/
│  ├─ raw/                      # 原始结果
│  └─ processed/                # 处理后的结果
├─ output/                      # 输出产物
├─ tmp/                         # 临时目录
└─ logs/                        # 日志
```

## 3. 各目录职责

### `docs/`

存放项目设计文档。当前只保留两份最关键的文档：

- `architecture.md`：讲清系统模块、执行流程和数据流
- `project-structure.md`：讲清仓库组织方式和目录职责

### `src/autoyara/ReAct/`

这是系统的控制中枢，负责 agent 的状态维护和动作选择。

建议这里承担：

- 当前漏洞案例的运行状态
- ReAct 主循环调度
- 调用 IDA、分析、验证、生成模块
- 根据验证结果决定继续、回退或结束

### `src/autoyara/ida/`

封装与 IDA MCP 或其他 IDA 自动化能力的交互。

建议所有 IDA 调用都从这里走，避免上层逻辑直接依赖具体工具细节。

### `src/autoyara/analysis/`

负责最核心的业务分析流程：

- 定位旧版本漏洞函数
- 定位新版本修复函数
- 分析两个函数差异
- 提取补丁引入的关键逻辑
- 生成候选特征代码
- 进一步转换为 hex

### `src/autoyara/validation/`

负责执行验证并返回结果。

它需要告诉 ReAct 模块：

- 当前候选特征是否有效
- 失败原因是什么
- 应该回退到哪一步

### `src/autoyara/generation/`

负责把验证通过的结果转换成最终产物：

- `YARA`
- `JSON`

### `src/autoyara/models/`

定义统一数据结构，避免模块之间直接传递零散字典。

建议至少覆盖：

- 漏洞信息
- 函数定位结果
- 差异分析结果
- 特征候选
- 验证结果
- 生成结果

### `scripts/`

存放运行脚本，用于启动或串接主流程，例如：

- 单案例运行
- 验证执行
- 批量处理

### `data/raw/`

保存原始结果，不做覆盖式修改。

例如：

- 抓取到的漏洞页面
- 原始 patch 或 diff
- 原始二进制或镜像信息
- IDA 直接导出的原始内容

### `data/processed/`

保存处理后的结构化结果。

例如：

- 函数定位结果
- 差异分析结果
- 候选特征
- 验证结果

建议按漏洞编号组织子目录，便于追踪。

### `output/`

保存最终输出产物。

例如：

- YARA 规则
- JSON 元数据
- 可提交文件

### `tmp/`

保存运行过程中的临时文件，不要求长期保留。

### `logs/`

保存系统日志、调试日志和运行记录。

## 4. 推荐的最小落地方式

第一阶段建议先让下面这条链路跑通：

`patch/diff + 新旧版本输入 -> IDA 定位 -> 差异分析 -> 特征提取 -> hex 生成 -> 验证 -> YARA/JSON 生成`

这意味着最先需要实现的是：

1. `models/`
2. `ida/`
3. `analysis/`
4. `validation/`
5. `generation/`
6. `ReAct/`

## 5. 数据落盘建议

建议每个漏洞案例单独保存到 `data/processed/<CVE编号>/` 下，例如：

```text
data/processed/CVE-2025-38466/
├─ old_function.json
├─ new_function.json
├─ diff_result.json
├─ feature_candidates.json
├─ validation_result.json
└─ final_output.json
```

最终输出则放到 `output/<CVE编号>/` 下，例如：

```text
output/CVE-2025-38466/
├─ rule.yar
└─ metadata.json
```
