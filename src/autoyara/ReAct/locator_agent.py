from __future__ import annotations

import json
import re
from collections.abc import Any, Callable
from dataclasses import dataclass, field

from autoyara.ida.mcptools import (
    get_decompiled_code,
    get_disassembly_by_address_range,
    get_disassembly_code,
    get_function_name_by_string,
    get_hex_by_code_snippet,
    get_hex_by_decompiled_snippet,
)
from autoyara.llm.sync_client import SyncLLMClient
from autoyara.runtime_logger import create_runtime_logger

from .internal_types import AgentState, AgentStep, AgentTask


@dataclass(slots=True)
class LocatorResult:
    """Output of the locator stage."""

    success: bool
    cve_id: str
    function_name: str
    vulnerable_code_segment: str
    vulnerable_assembly_segment: str
    start_address: str
    end_address: str
    reasoning: str
    confidence: float
    raw_output: str = ""
    steps: list[dict[str, Any]] = field(default_factory=list)


class LocatorAgent:
    """Locate vulnerable logic inside a binary with tool-assisted ReAct steps."""

    def __init__(
        self,
        llm_client: SyncLLMClient,
        max_steps: int = 8,
    ):
        self.llm = llm_client
        self.max_steps = max_steps
        self.tools: dict[str, Callable] = {
            "get_decompiled_code": get_decompiled_code,
            "get_disassembly_code": get_disassembly_code,
            "get_disassembly_by_address_range": get_disassembly_by_address_range,
            "get_function_name_by_string": get_function_name_by_string,
            "get_hex_by_code_snippet": get_hex_by_code_snippet,
            "get_hex_by_decompiled_snippet": get_hex_by_decompiled_snippet,
        }

    def _get_prompt(self, task: AgentTask) -> str:
        return f"""You are AutoYara's Locator Agent.
Your only task is to use the CVE information and source snippets to locate the affected code region in the target binary and extract the related assembly.

You have access to real binary-analysis tools.
You must call tools by outputting JSON in the required format. Do not describe tool usage in natural language; the backend will execute your requested action and return the observation.

### Task Information
CVE ID: {task.cve_id}
Target binary: {task.target_binary}
Target function: {task.function_name}
CVE description: {task.description}
Relevant source snippets:
{task.vulnerable_code if task.vulnerable_code else "No vulnerable source snippet provided."}
{task.fixed_code if task.fixed_code else "No fixed source snippet provided."}

### Core Workflow
1. Get code first: call `get_decompiled_code` to retrieve the full pseudocode of the target function.
2. Locate the logic: align the vulnerable logic from the CVE description/source with the pseudocode.
3. Extract assembly:
   - Option A: use `get_hex_by_decompiled_snippet` with a key pseudocode line to recover the address range.
   - Option B: use `get_disassembly_by_address_range` to fetch assembly for a specific address range.
4. Verify before finishing: only return `final_answer` after you have obtained real assembly text for the vulnerable logic.

### Available Tools
- `get_decompiled_code(elf_file_path, function_name)`: get the function pseudocode.
- `get_disassembly_code(elf_file_path, function_name)`: get the full disassembly of the function.
- `get_disassembly_by_address_range(elf_file_path, start_addr, end_addr)`: get disassembly for a specific address range.
- `get_hex_by_decompiled_snippet(elf_file_path, function_name, code_snippet)`: map a pseudocode snippet back to its address range.

### Important Rules
- Do not say that you cannot execute tools. Just emit an `action` JSON block.
- Emit exactly one JSON block per turn.
- Do not output a successful `final_answer` before you have real assembly text.

If you need to call a tool, output:
{{
    "thought": "your reasoning",
    "action": "tool_name",
    "action_input": {{ ... }}
}}

Only after all required information has been gathered may you output:
{{
    "thought": "summary of reasoning",
    "final_answer": {{
        "success": true,
        "reasoning": "how you located the code",
        "confidence": 0.95,
        "function_name": "function name",
        "vulnerable_code_segment": "key C/pseudocode segment",
        "vulnerable_assembly_segment": "matching assembly instructions",
        "start_address": "start address",
        "end_address": "end address"
    }}
}}
start address and end address should be in hex format

Remember:
1. Emit exactly one JSON block per turn.
2. Do not output `action` and `final_answer` in the same response.
3. You must call `get_decompiled_code` before using snippet/address tools, and you may only finish after obtaining assembly."""

    def _parse_llm_json(self, text: str) -> dict[str, Any] | None:
        raw = (text or "").strip()
        if not raw:
            return None

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        def find_json_blocks(s: str) -> list[str]:
            blocks = []
            stack = []
            start = -1
            for i, char in enumerate(s):
                if char == "{":
                    if not stack:
                        start = i
                    stack.append("{")
                elif char == "}":
                    if stack:
                        stack.pop()
                        if not stack:
                            blocks.append(s[start : i + 1])
            return blocks

        blocks = find_json_blocks(raw)
        if not blocks:
            m = re.search(r"(\{[\s\S]*\})", raw)
            if m:
                try:
                    data = json.loads(m.group(1))
                    if isinstance(data, dict):
                        return data
                except json.JSONDecodeError:
                    pass
            return None

        for block in reversed(blocks):
            try:
                data = json.loads(block)
                if isinstance(data, dict):
                    if "thought" in data and (
                        "action" in data or "final_answer" in data
                    ):
                        return data
            except json.JSONDecodeError:
                continue

        for block in reversed(blocks):
            try:
                data = json.loads(block)
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                continue

        return None

    def run(self, task: AgentTask) -> LocatorResult:
        state = AgentState(max_steps=self.max_steps)
        prompt = self._get_prompt(task)
        history = prompt
        logger = create_runtime_logger(prefix="locator", task_id=task.cve_id)
        logger.info("task", f"Starting localization for {task.cve_id}")
        stop_reason = "Max steps reached or parsing error"
        last_action_sig = ""
        repeated_identical_calls = 0
        not_found_streak = 0

        for step_idx in range(self.max_steps):
            logger.info("step", f"--- Step {step_idx + 1} ---")
            logger.info("llm_call", "Waiting for LLM response...")
            try:
                response = self.llm.prompt(history)
            except KeyboardInterrupt:
                logger.warn("interrupt", "User interrupted the process.")
                raise
            except Exception as e:
                logger.error("llm_error", f"LLM prompt failed: {e}")
                stop_reason = f"LLM prompt failed: {e}"
                break

            logger.debug("llm_response", f"Received: {response[:200]}...")
            payload = self._parse_llm_json(response)

            if not payload:
                logger.error("error", f"Failed to parse JSON: {response}")
                stop_reason = "Failed to parse LLM JSON"
                break

            thought = payload.get("thought", "")
            action = payload.get("action")
            action_input = payload.get("action_input", {})
            final_answer = payload.get("final_answer")

            logger.info("thought", thought)

            if action and action in self.tools:
                if not isinstance(action_input, dict):
                    action_input = {}
                if "elf_file_path" not in action_input:
                    action_input["elf_file_path"] = task.target_binary

                if action == "get_disassembly_by_address_range":
                    if (
                        "start_address" in action_input
                        and "start_addr" not in action_input
                    ):
                        action_input["start_addr"] = action_input.pop("start_address")
                    if "end_address" in action_input and "end_addr" not in action_input:
                        action_input["end_addr"] = action_input.pop("end_address")

                if action == "get_disassembly_code" and (
                    "start_addr" in action_input or "start_address" in action_input
                ):
                    action = "get_disassembly_by_address_range"
                    if (
                        "start_address" in action_input
                        and "start_addr" not in action_input
                    ):
                        action_input["start_addr"] = action_input.pop("start_address")
                    if "end_address" in action_input and "end_addr" not in action_input:
                        action_input["end_addr"] = action_input.pop("end_address")

                action_sig = (
                    f"{action}:"
                    f"{json.dumps(action_input, ensure_ascii=False, sort_keys=True)}"
                )
                if action_sig == last_action_sig:
                    repeated_identical_calls += 1
                    logger.warn(
                        "validation",
                        "Repeated identical tool call detected. Forcing a different strategy.",
                    )
                    history += (
                        "\nObservation: Error: You repeated the same tool call with "
                        "the same parameters. Choose a different function clue/string "
                        "or different address strategy."
                    )
                    if repeated_identical_calls >= 2:
                        stop_reason = "Repeated identical tool calls"
                        logger.error("early_stop", stop_reason)
                        break
                    continue
                last_action_sig = action_sig
                repeated_identical_calls = 0

                logger.info("action", f"{action}({action_input})")
                try:
                    observation = self.tools[action](**action_input)
                    logger.info("observation", str(observation)[:200] + "...")
                except Exception as e:
                    observation = f"Error: {e}"
                    logger.error("error", observation)

                obs_text = str(observation)
                not_found_hit = (
                    "找不到函数" in obs_text or "Function not found" in obs_text
                )
                if not_found_hit and action in {
                    "get_decompiled_code",
                    "get_disassembly_code",
                    "get_hex_by_decompiled_snippet",
                    "get_hex_by_code_snippet",
                }:
                    not_found_streak += 1
                else:
                    not_found_streak = 0
                if not_found_streak >= 3:
                    stop_reason = (
                        "Function symbol not found repeatedly; stopping early "
                        "to avoid wasted retries"
                    )
                    logger.error("early_stop", stop_reason)
                    state.steps.append(
                        AgentStep(thought, action, action_input, obs_text)
                    )
                    break

                state.steps.append(
                    AgentStep(thought, action, action_input, str(observation))
                )
                history += (
                    f"\nThought: {thought}\nAction: {action}\n"
                    f"Action Input: {json.dumps(action_input)}\nObservation: {observation}"
                )
                continue

            if final_answer:
                if not isinstance(final_answer, dict):
                    logger.warn(
                        "validation",
                        "Final answer is not a JSON object. Forcing LLM to retry...",
                    )
                    history += (
                        f"\nThought: {thought}\nAction: error\nObservation: Error: "
                        "Your final_answer must be a JSON object."
                    )
                    continue

                asm_seg_raw = final_answer.get("vulnerable_assembly_segment", "")
                asm_seg = (
                    asm_seg_raw
                    if isinstance(asm_seg_raw, str)
                    else ("" if asm_seg_raw is None else str(asm_seg_raw))
                )
                start_addr_raw = final_answer.get("start_address", "")
                start_addr = "" if start_addr_raw is None else str(start_addr_raw)
                end_addr_raw = final_answer.get("end_address", "")
                end_addr = "" if end_addr_raw is None else str(end_addr_raw)

                if final_answer.get("success", True):
                    if not asm_seg or not start_addr or "N/A" in str(asm_seg):
                        logger.warn(
                            "validation",
                            "Final answer is missing assembly or address. Forcing LLM to retry...",
                        )
                        history += (
                            f"\nThought: {thought}\nAction: error\nObservation: Error: "
                            "Your final_answer is missing vulnerable_assembly_segment or "
                            "the address range. Extract real assembly before finishing."
                        )
                        continue
                    has_real_disasm = any(
                        s.action
                        in {"get_disassembly_code", "get_disassembly_by_address_range"}
                        and not str(s.observation).strip().startswith("Error")
                        for s in state.steps
                    )
                    if not has_real_disasm:
                        logger.warn(
                            "validation",
                            "Final answer has no tool-backed disassembly evidence. Forcing retry...",
                        )
                        history += (
                            f"\nThought: {thought}\nAction: error\nObservation: Error: "
                            "You must call get_disassembly_code or "
                            "get_disassembly_by_address_range and use the real observation "
                            "before returning final_answer."
                        )
                        continue

                logger.info(
                    "final_answer",
                    "Localization completed. "
                    f"Extracted {len(asm_seg)} "
                    "bytes of assembly text.",
                )
                code_seg_raw = final_answer.get("vulnerable_code_segment", "")
                code_seg = (
                    code_seg_raw
                    if isinstance(code_seg_raw, str)
                    else ("" if code_seg_raw is None else str(code_seg_raw))
                )
                fn_raw = final_answer.get("function_name")
                fn_val = (
                    fn_raw if isinstance(fn_raw, str) and fn_raw else task.function_name
                )
                reasoning_raw = final_answer.get("reasoning", "")
                reasoning = (
                    reasoning_raw
                    if isinstance(reasoning_raw, str)
                    else ("" if reasoning_raw is None else str(reasoning_raw))
                )
                confidence_raw = final_answer.get("confidence", 0.0)
                try:
                    confidence_val = float(confidence_raw)
                except (TypeError, ValueError):
                    confidence_val = 0.0
                res = LocatorResult(
                    success=final_answer.get("success", True),
                    cve_id=task.cve_id,
                    function_name=fn_val,
                    vulnerable_code_segment=code_seg,
                    vulnerable_assembly_segment=asm_seg,
                    start_address=start_addr,
                    end_address=end_addr,
                    reasoning=reasoning,
                    confidence=confidence_val,
                    raw_output=json.dumps(final_answer),
                    steps=[
                        {
                            "thought": s.thought,
                            "action": s.action,
                            "observation": s.observation,
                        }
                        for s in state.steps
                    ],
                )
                logger.info("result", f"Summary: {res.reasoning[:100]}...")
                logger.info("result", f"Range: {res.start_address} - {res.end_address}")
                return res

        return LocatorResult(
            success=False,
            cve_id=task.cve_id,
            function_name=task.function_name,
            vulnerable_code_segment="",
            vulnerable_assembly_segment="",
            start_address="",
            end_address="",
            reasoning=stop_reason,
            confidence=0.0,
        )
