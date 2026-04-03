# AutoYara 项目文件结构

## 当前仓库实际布局（以采集为主）

```text
AutoYara/
├─ README.md
├─ pyproject.toml
├─ docs/                    # 文档
├─ scripts/                 # 调用采集 API 的示例脚本
├─ src/autoyara/
│  ├─ collector/            # 对外导入入口（聚合 collectors + models 常用符号）
│  ├─ collectors/           # OpenHarmony CVE 采集实现（含 pipeline）
│  └─ models/               # CollectorConfig、CVEItem
├─ data/                    # 预留数据目录（仅占位 .gitkeep）
├─ output/                  # 脚本输出目录（*.json 已加入 .gitignore）
├─ tmp/、logs/              # 见 .gitignore，通常不提交
```

后续若接入 ReAct、IDA、分析/验证/生成等模块，再在 `src/autoyara/` 下按包扩展即可。
