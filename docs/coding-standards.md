# AutoYara 编码规范

## 快速开始

```bash
# 1. 安装依赖
pip install -e ".[dev]"

# 2. 初始化 pre-commit
pre-commit install

# 3. 格式化代码
black .
ruff format .

# 4. 检查代码
ruff check .
```

---

## 日常使用

### 提交代码

```bash
git add .
git commit -m "feat: add new feature"
# pre-commit 会自动运行 black 和 ruff
```

如果检查失败，修复后重新提交即可。

### 手动运行

```bash
# 格式化
black .
ruff format .

# 检查
ruff check .

# 对所有文件运行 pre-commit
pre-commit run --all-files
```

### 临时跳过检查

```bash
git commit -m "WIP: work in progress" --no-verify
```

---

## Commit 消息格式

采用 [Conventional Commits](https://www.conventionalcommits.org/) 规范:

```
<type>(<scope>): <subject>
```

### Type 类型

| Type | 说明 |
|------|------|
| `feat` | 新功能 |
| `fix` | Bug 修复 |
| `docs` | 文档更新 |
| `style` | 代码格式 |
| `refactor` | 重构 |
| `perf` | 性能优化 |
| `test` | 测试相关 |
| `chore` | 构建/工具 |

### Scope 范围

- `collector` - 对外采集 API（`autoyara.collector`）
- `collectors` - 采集内部实现（pipeline、analysis、diff_utils 等）
- `models` - 数据模型（`CollectorConfig`、`CVEItem`）
- `scripts` - 示例脚本
- `docs` - 文档

### 示例

```bash
feat(collectors): add fuzzy hunk matching in reconstruct
fix(collector): support github commit URL in commit_url
docs: update collectors README with token usage
refactor(models): simplify CVEItem fields
```

---

## Git 协作规范

### 分支命名

| 分支类型 | 命名格式 |
|---------|---------|
| 主分支 | `main` |
| 功能分支 | `feature/<name>` |
| 修复分支 | `fix/<description>` |
| 实验分支 | `experiment/<name>` |

### 工作流程

```bash
git checkout -b feature/your-feature
# 开发并提交
git push origin feature/your-feature
# 创建 Pull Request
```

---

## IDE 集成

### VS Code

安装扩展：**Black Formatter**、**Ruff**

在 `.vscode/settings.json` 中添加:

```json
{
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    }
}
```

### PyCharm

1. Settings → Tools → Ruff → Enable
2. Settings → Tools → Black → Enable
3. 勾选 "Run on Save"
