"""爬取质量校验：LLM 全量评估。

三个维度统一交给 LLM 判断：
1. 漏洞描述（description）—— 是否包含对漏洞成因或影响的实质性说明
2. 修复前函数（vulnerable_function）—— 是否为完整函数体
3. 修复后函数（fixed_function）—— 同上
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .response_parser import parse_llm_json
from .sync_client import SyncLLMClient

_PATCH_CONTEXT_PREFIX = "/* patch context"
_MAX_CODE_CHARS = 8000  # 扩大到8000字符，覆盖大多数libpng大函数
_MAX_DESC_CHARS = 1200

_SYSTEM_PROMPT = """\
你是漏洞情报质量评审专家。你将收到一条自动爬取的 CVE 漏洞记录，包含三个字段。
你需要逐一判断每个字段是否完整有效，并以 JSON 格式返回结果。

判断标准：
- 漏洞描述，漏洞类型(type)和漏洞影响(impact)。描述可以缺少，但一定要有类型和影响字段
  仅有 git commit message（如 "Fix CVE-xxx"）、文件路径或补丁名称列表均不合格。
- 修复前函数：必须是完整的 C/C++ 函数体（有签名、函数体、闭合花括号）；
  以注释 "/* patch context - source file unavailable */" 开头的是 diff 上下文片段，不合格。
- 修复后函数：判断标准同修复前函数。
- 正确性与一致性：描述与两段代码在漏洞点、涉及 API 上应合理对应；明显无关则判不合格。
  若修复前与修复后实质相同（除空白外），且描述未说明「无代码变更」类情形，则函数侧至少一侧不合格。

仅返回如下 JSON，不要加 markdown 代码块：
{
  "description_ok": true/false,
  "vulnerable_function_ok": true/false,
  "fixed_function_ok": true/false,
  "overall_ok": true/false,
  "reason": "overall_ok 为 false 时给出简短说明，否则留空"
}
"""


@dataclass
class QualityCheckResult:
    """LLM 质量校验结果。"""

    overall_ok: bool
    description_ok: bool
    vulnerable_function_ok: bool
    fixed_function_ok: bool
    reason: str = ""
    details: dict[str, str] = field(default_factory=dict)
    #: True 表示网络/鉴权/解析等导致未拿到 LLM 结论，与「模型判定内容不合格」不同
    llm_request_failed: bool = False

    @property
    def is_complete(self) -> bool:
        return self.overall_ok

    def failed_fields(self) -> list[str]:
        if self.llm_request_failed:
            return []
        return [
            name
            for name, ok in [
                ("description", self.description_ok),
                ("vulnerable_function", self.vulnerable_function_ok),
                ("fixed_function", self.fixed_function_ok),
            ]
            if not ok
        ]

    def passed_fields(self) -> list[str]:
        if self.llm_request_failed:
            return []
        return [
            name
            for name, ok in [
                ("description", self.description_ok),
                ("vulnerable_function", self.vulnerable_function_ok),
                ("fixed_function", self.fixed_function_ok),
            ]
            if ok
        ]

    @property
    def score(self) -> float | None:
        if self.llm_request_failed:
            return None
        return round(len(self.passed_fields()) / 3, 2)


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n... [截断，原文 {len(text)} 字符]"


def _smart_truncate_func(code: str, max_chars: int) -> str:
    """对超长函数体保留头部+尾部，让LLM能判断签名和闭合括号。"""
    if len(code) <= max_chars:
        return code
    head = max_chars * 2 // 3
    tail = max_chars - head
    omitted = len(code) - head - tail
    return (
        code[:head]
        + f"\n\n... [省略中间 {omitted} 字符，函数体过长] ...\n\n"
        + code[-tail:]
    )


def _annotate_function(code: str | None) -> str:
    """为函数代码加上已知状态注释，帮助 LLM 更准确判断。"""
    if not code or not code.strip():
        return "（空）"
    if code.lstrip().startswith(_PATCH_CONTEXT_PREFIX):
        return f"[已知：源文件不可用，以下为 diff 上下文片段]\n{_truncate(code, _MAX_CODE_CHARS)}"
    return _smart_truncate_func(code, _MAX_CODE_CHARS)


def check_quality(
    description: str,
    vuln_type: str,
    vuln_impact: str,
    vulnerable_function: str,
    fixed_function: str,
    cve_id: str = "",
    *,
    client: SyncLLMClient | None = None,
    review_round: str = "",
) -> QualityCheckResult:
    """调用 LLM 校验单条爬取结果的完整性与（在终审轮）正确性。

    Args:
        review_round: 日志标签，如 ``"第1轮-爬取"``、``"第2轮-终审"``，便于区分多次审查。
    """
    own_client = client is None
    if own_client:
        client = SyncLLMClient()
    print(f"andi?  ,{description}")
    user_content = (
        f"CVE：{cve_id or '（未知）'}\n\n"
        f"【漏洞描述】\n{_truncate(description or '（空）', _MAX_DESC_CHARS)}\n\n"
        f"【漏洞类型】\n {vuln_type or '（空）'}\n\n"
        f"【漏洞影响】\n {vuln_impact or '（空）'}\n\n"
        f"【修复前函数】\n{_annotate_function(vulnerable_function)}\n\n"
        f"【修复后函数】\n{_annotate_function(fixed_function)}"
    )

    try:
        raw = client.chat(
            [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ]
        )
        print("=" * 30)
        print(raw)
        print("=" * 30)
        data = parse_llm_json(raw)
        result = QualityCheckResult(
            overall_ok=bool(data.get("overall_ok", False)),
            description_ok=bool(data.get("description_ok", False)),
            vulnerable_function_ok=bool(data.get("vulnerable_function_ok", False)),
            fixed_function_ok=bool(data.get("fixed_function_ok", False)),
            reason=str(data.get("reason", "")),
        )
    except Exception as exc:
        result = QualityCheckResult(
            overall_ok=False,
            description_ok=False,
            vulnerable_function_ok=False,
            fixed_function_ok=False,
            reason=f"LLM 校验失败：{exc}",
            llm_request_failed=True,
        )
    finally:
        if own_client:
            client.close()

    round_bit = f" {review_round}" if review_round else ""
    tag = f"[quality]{round_bit} {cve_id}" if cve_id else f"[quality]{round_bit}"
    if result.overall_ok:
        print(f"  {tag} OK")
    else:
        print(f"  {tag} FAIL — {result.reason}")

    return result


# ---------------------------------------------------------------------------
# 三方库漏洞描述/漏洞影响 LLM 提炼
# ---------------------------------------------------------------------------

_SUMMARIZE_SYSTEM = """\
你是漏洞信息提炼专家。给定一段 CVE 漏洞的英文描述，请用中文提炼出：
1. 漏洞描述，包含漏洞的成因，触发条件，漏洞类型，以及可能的攻击方式。需要具体到函数或语句，不超过50字 \
    其中的漏洞类型示例放在漏洞描述的最后，形如：漏洞类型为堆缓冲区溢出 \
    漏洞类型为整数溢出、漏洞类型为SQL注入等，不超过10个字

2. 漏洞影响（漏洞被利用后的简短影响，20字以内，格式类似"本地攻击者可造成系统崩溃"、\
"远程攻击者可执行任意代码"、"攻击者可造成拒绝服务"）


仅返回如下 JSON，不要加 markdown 代码块：
{"vuln_type": "...", "vuln_impact": "...", "test": ""}
"""


def summarize_bulletin_fields(
    description: str,
    cve_id: str = "",
    *,
    client: SyncLLMClient | None = None,
) -> dict[str, str]:
    """从 NVD 英文描述提炼简短的「漏洞描述」和「漏洞影响」（专用于三方库 CVE）。

    Returns:
        {"vuln_type": "...", "vuln_impact": "..."}，失败时两值为空字符串。
    """
    empty: dict[str, str] = {"vuln_type": "", "vuln_impact": ""}
    desc = (description or "").strip()
    print(f"kurotest {desc[:2000]}")
    if len(desc) < 20:
        return empty

    own_client = client is None
    if own_client:
        client = SyncLLMClient()

    try:
        raw = client.chat(
            [
                {"role": "system", "content": _SUMMARIZE_SYSTEM},
                {"role": "user", "content": f"CVE：{cve_id}\n\n描述：{desc}"},
            ]
        )
        data = parse_llm_json(raw)
        print(f"kuroniko {raw}")
        vt = str(data.get("vuln_type", "")).strip()
        vi = str(data.get("vuln_impact", "")).strip()
        print(f"  [llm-summarize] {cve_id}  type={vt!r}  impact={vi!r}")
        return {"vuln_type": vt, "vuln_impact": vi}
    except Exception as exc:
        print(f"  [llm-summarize] 失败: {exc}")
        return empty
    finally:
        if own_client and client is not None:
            client.close()
