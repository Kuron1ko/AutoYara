# AutoYara

AutoYara 是一个面向 OpenHarmony 漏洞补丁验证场景的自动化系统。

系统目标是围绕 `CVE -> 修复 diff -> 新旧版本二进制差异 -> 特征提取 -> YARA/JSON 生成 -> 验证 -> 提交` 这一闭环，构建一个由爬虫、ReAct agent、IDA MCP、验证脚本和提交模块组成的工作流。

当前仓库处于项目初始化阶段，优先完善架构设计和目录结构，再逐步落地各模块。

## 当前设计重点

- 基于安全披露页面和代码仓自动抓取 CVE 与修复链接
- 结合 IDA MCP 对新旧版本函数进行定位、比对和特征抽取
- 用 ReAct 循环驱动“推理-执行-验证-回退”
- 自动输出 YARA 规则和配套 JSON 元数据
- 对接验证脚本与最终提交流程

## 文档

- [编码约定](docs/coding-standards.md)
- [项目文件结构](docs/project-structure.md)
- 采集模块说明见 [src/autoyara/collectors/README.md](src/autoyara/collectors/README.md)

## 核心流程

1. 抓取 OpenHarmony 的 CVE 信息与修复 diff
2. 获取目标漏洞对应的新旧版本镜像
3. 通过 IDA MCP 分别定位旧版本漏洞函数和新版本修复后函数
4. 比较两个函数差异，抽取补丁引入的关键逻辑
5. 将关键逻辑映射为可稳定匹配的特征代码与 hex
6. 运行验证脚本检查规则是否能区分修复前后版本
7. 验证通过后生成 YARA 和 JSON，并进入提交流程

## 下一步

- 落地数据模型与中间产物 schema
- 明确 IDA MCP 的工具接口封装
- 搭建最小可运行的验证闭环
- 按模块实现 ReAct orchestrator
