from __future__ import annotations

import json
import re
from collections.abc import Any, Callable
from dataclasses import dataclass

from autoyara.ida.mcptools import get_hex_by_address_range
from autoyara.llm.sync_client import SyncLLMClient
from autoyara.ReAct.locator_agent import LocatorResult
from autoyara.runtime_logger import create_runtime_logger


@dataclass(slots=True)
class AnalyzerResult:
    """Output of the analyzer stage."""

    success: bool
    cve_id: str
    diff_analysis: str
    raw_hex: str
    confidence: float
    explanation: str
    raw_output: str = ""


class AnalyzerAgent:
    """Compare vulnerable and fixed snippets, then extract fixed-version hex."""

    def __init__(self, llm_client: SyncLLMClient, max_steps: int = 5):
        self.llm = llm_client
        self.max_steps = max_steps
        self.tools: dict[str, Callable[..., Any]] = {
            "get_hex_by_address_range": get_hex_by_address_range,
        }

    def _get_prompt(
        self,
        vuln_res: LocatorResult,
        fixed_res: LocatorResult,
        fixed_binary: str,
    ) -> str:
        return f"""You are a binary security analyst.

Your task:
1. Compare the vulnerable and fixed code/assembly.
2. Identify the patch-relevant change.
3. Extract a real raw hex sequence from the fixed binary that captures the patch.

Hard rules:
- The hex must come from the fixed binary: {fixed_binary}
- Do not invent bytes.
- Do not use masks such as ??.
- You must call get_hex_by_address_range(elf_file_path, start_addr, end_addr) before giving a final answer.
- Optimization goal: keep the signature as short as possible while still distinguishing fixed vs vulnerable.
- Use a short-first strategy:
  1) First try a patch-centric 16-byte range around changed branch/compare/check instructions.
  2) If not distinctive enough, expand by small steps (typically +4 bytes) and retry.
  3) Stop at the shortest range that is clearly distinctive.
- Target length: usually 16-24 bytes. Do not exceed 32 bytes unless every <=32-byte candidate is ambiguous.
- Never return a full-function dump or an unnecessarily long contiguous block.
- If no useful string anchor exists, do NOT guess random absolute addresses.
  Use the fixed-version function range above and pick a nearby sub-range from real disassembly evidence.

Input:
CVE: {vuln_res.cve_id}

Vulnerable version:
- Function: {vuln_res.function_name}
- Address range: {vuln_res.start_address} - {vuln_res.end_address}
- Decompiled code:
{vuln_res.vulnerable_code_segment}
- Assembly:
{vuln_res.vulnerable_assembly_segment}

Fixed version:
- Function: {fixed_res.function_name}
- Address range: {fixed_res.start_address} - {fixed_res.end_address}
- Decompiled code:
{fixed_res.vulnerable_code_segment}
- Assembly:
{fixed_res.vulnerable_assembly_segment}

Output protocol:
Before extracting hex, respond with JSON only:
{{
  "thought": "brief reasoning",
  "action": "get_hex_by_address_range",
  "action_input": {{
    "start_addr": "...",
    "end_addr": "..."
  }},
  "final_answer": null
}}

After receiving the tool result, respond with JSON only:
{{
  "thought": "brief reasoning",
  "final_answer": {{
    "success": true,
    "diff_analysis": "assembly-level patch difference",
    "raw_hex": "AA BB CC DD",
    "explanation": "why this is the shortest distinctive signature and its byte length",
    "confidence": 0.95
  }}
}}
"""

    def _extract_llm_json_payloads(self, text: str) -> list[dict[str, Any]]:
        raw = (text or "").strip()
        if not raw:
            return []

        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return [data]
        except json.JSONDecodeError:
            pass

        def find_json_blocks(s: str) -> list[str]:
            blocks: list[str] = []
            stack = 0
            start = -1
            for i, char in enumerate(s):
                if char == "{":
                    if stack == 0:
                        start = i
                    stack += 1
                elif char == "}":
                    if stack > 0:
                        stack -= 1
                        if stack == 0 and start >= 0:
                            blocks.append(s[start : i + 1])
            return blocks

        blocks = find_json_blocks(raw)
        if not blocks:
            match = re.search(r"(\{[\s\S]*\})", raw)
            if not match:
                return []
            try:
                data = json.loads(match.group(1))
                if isinstance(data, dict):
                    return [data]
            except json.JSONDecodeError:
                return []
            return []

        payloads: list[dict[str, Any]] = []
        for block in blocks:
            try:
                data = json.loads(block)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                payloads.append(data)
        return payloads

    def _extract_hex_candidate(self, observation: Any) -> str:
        match = re.search(
            r"(?:[0-9A-Fa-f]{2}\s+){4,}[0-9A-Fa-f]{2}",
            str(observation),
        )
        if match:
            return match.group(0).strip()
        return ""

    def _is_all_ff_hex(self, hex_text: str) -> bool:
        tokens = [t for t in hex_text.strip().split() if t]
        if not tokens:
            return False
        return all(t.upper() == "FF" for t in tokens)

    def run(
        self,
        vuln_res: LocatorResult,
        fixed_res: LocatorResult,
        fixed_binary: str,
    ) -> AnalyzerResult:
        """Run the analyzer loop."""

        logger = create_runtime_logger(prefix="analyzer", task_id=vuln_res.cve_id)
        history = self._get_prompt(vuln_res, fixed_res, fixed_binary)
        hex_extracted = False
        hex_candidate = ""
        last_action_sig = ""
        repeated_action_rejects = 0

        for step_idx in range(self.max_steps):
            logger.info("step", f"--- Step {step_idx + 1} ---")
            logger.info("llm_call", "Waiting for LLM response...")
            try:
                response = self.llm.prompt(history)
                logger.info("response", response)
            except KeyboardInterrupt:
                logger.warn("interrupt", "User interrupted.")
                raise
            except Exception as exc:
                logger.error("error", f"LLM error: {exc}")
                break

            payloads = self._extract_llm_json_payloads(response)
            if not payloads:
                logger.error("error", f"Failed to parse JSON: {response}")
                break

            normalized_payloads: list[dict[str, Any]] = []
            for payload in payloads:
                thought = str(payload.get("thought", ""))
                action = payload.get("action")
                action_input = payload.get("action_input", {})
                final_answer = payload.get("final_answer")

                if (
                    not action
                    and not final_answer
                    and "start_addr" in payload
                    and "end_addr" in payload
                ):
                    action = "get_hex_by_address_range"
                    action_input = dict(payload)

                normalized_payloads.append(
                    {
                        "thought": thought,
                        "action": action,
                        "action_input": action_input,
                        "final_answer": final_answer,
                    }
                )

            action_payload = next(
                (
                    payload
                    for payload in normalized_payloads
                    if payload.get("action") in self.tools
                ),
                None,
            )
            if action_payload:
                thought = str(action_payload.get("thought", ""))
                action = str(action_payload.get("action"))
                action_input = action_payload.get("action_input", {})

                logger.info("thought", thought)
                if action_payload.get("final_answer") is not None:
                    logger.warn(
                        "validation",
                        "Ignoring final_answer from the same LLM response as a tool call.",
                    )

                if not isinstance(action_input, dict):
                    action_input = {}
                if "elf_file_path" not in action_input:
                    action_input["elf_file_path"] = fixed_binary

                action_sig = (
                    f"{action}:"
                    f"{json.dumps(action_input, ensure_ascii=False, sort_keys=True)}"
                )
                if action_sig == last_action_sig:
                    repeated_action_rejects += 1
                    logger.warn(
                        "validation",
                        "Repeated identical tool call detected. Forcing a different range.",
                    )
                    history += (
                        "\nObservation: Error: You just repeated the exact same "
                        "get_hex_by_address_range call and got no new evidence. "
                        "Choose a different start_addr/end_addr inside the fixed function."
                    )
                    if repeated_action_rejects >= 2:
                        logger.error(
                            "validation",
                            "Too many repeated identical tool calls. Aborting analyzer loop.",
                        )
                        break
                    continue
                last_action_sig = action_sig
                repeated_action_rejects = 0

                logger.info("action", f"{action}({action_input})")
                try:
                    observation = self.tools[action](**action_input)
                    logger.info("observation", str(observation)[:200] + "...")
                    if action == "get_hex_by_address_range" and "Error" not in str(
                        observation
                    ):
                        hex_extracted = True
                        extracted_hex = self._extract_hex_candidate(observation)
                        if extracted_hex:
                            if self._is_all_ff_hex(extracted_hex):
                                logger.warn(
                                    "validation",
                                    "Extracted hex is all FF; forcing the model to choose another range.",
                                )
                                hex_candidate = ""
                                hex_extracted = False
                                history += (
                                    "\nObservation: Error: Extracted bytes are all FF "
                                    "(likely unmapped/padding/wrong range). "
                                    "Choose another address range with real instructions."
                                )
                                continue
                            hex_candidate = extracted_hex
                except Exception as exc:
                    observation = f"Error: {exc}"
                    logger.error("error", observation)

                history += (
                    f"\nThought: {thought}\nAction: {action}\n"
                    f"Action Input: {json.dumps(action_input)}\nObservation: {observation}"
                )
                if hex_candidate:
                    history += f"\nHEX_OBSERVATION: {hex_candidate}"
                continue

            final_payload = next(
                (
                    payload
                    for payload in reversed(normalized_payloads)
                    if payload.get("final_answer") is not None
                ),
                None,
            )
            if final_payload:
                thought = str(final_payload.get("thought", ""))
                final_answer = final_payload.get("final_answer")

                logger.info("thought", thought)
                if not hex_extracted and final_answer.get("success", True):
                    logger.warn(
                        "validation",
                        "Final answer provided without extracting real hex. Forcing extraction...",
                    )
                    history += (
                        f"\nThought: {thought}\nAction: error\nObservation: Error: "
                        "You have not called get_hex_by_address_range yet. "
                        "Extract the real hex first, then provide the final answer."
                    )
                    continue

                if hex_candidate:
                    if (
                        final_answer.get("raw_hex")
                        and final_answer.get("raw_hex") != hex_candidate
                    ):
                        logger.warn(
                            "validation",
                            "Replacing model-provided raw_hex with tool-extracted bytes.",
                        )
                    final_answer["raw_hex"] = hex_candidate

                return AnalyzerResult(
                    success=final_answer.get("success", True),
                    cve_id=vuln_res.cve_id,
                    diff_analysis=final_answer.get("diff_analysis", ""),
                    raw_hex=final_answer.get("raw_hex", ""),
                    confidence=float(final_answer.get("confidence", 0.0)),
                    explanation=final_answer.get("explanation", ""),
                    raw_output=response,
                )

            logger.error(
                "error", f"No actionable tool call or final answer: {response}"
            )
            break

        return AnalyzerResult(
            success=False,
            cve_id=vuln_res.cve_id,
            diff_analysis="",
            raw_hex="",
            confidence=0.0,
            explanation="Max steps reached without final answer",
            raw_output="",
        )
