# Validation 模块

## 概述

Validation（验证）模块用于自动化检测 YARA 规则对修复前/后的样本文件的匹配情况，常用于漏洞检测、规则有效性验证等场景。

## 用法

### 基本用法

```python
from autoyara.validation.runner import checkcve

result = checkcve("CVE-2025-38095")
print(result)
```

### 结果说明

返回值为 `ValidationResult` 对象，包含如下字段：
- `cve_id`：CVE编号
- `fixed_matched`：修复后样本是否匹配
- `unfixed_matched`：修复前样本是否匹配
- `return_code`：结果代码（0=通过，1/2/3=不同失败类型）
- `message`：详细说明

## 配置

在 `configs/config.yaml` 中添加：

```yaml
FIXED_ELF_PATH: "修复后样本的绝对路径"
UNFIXED_ELF_PATH: "修复前样本的绝对路径"
```

## 测试

python test_validation.py CVE-xxxx-xxxx

## 依赖
- 需要配置 YARA 路径（tools/yara64.exe）
- 需要生成对应的 JSON 和 YARA 文件（如 tmp/CVE-xxxx-xxxx/CVE-xxxx-xxxx.json 和 .yara）


