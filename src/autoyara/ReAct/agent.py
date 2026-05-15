from __future__ import annotations

import json
import re
from typing import Any, Callable

from autoyara.ida.mcptools import (
    get_decompiled_code,
    get_disassembly_code,
    get_function_name_by_hex,
    get_function_name_by_string,
    get_hex_by_code_snippet,
    get_hex_by_decompiled_snippet,
    get_hex_from_ida,
)
from autoyara.llm.sync_client import SyncLLMClient
from autoyara.runtime_logger import create_runtime_logger

from .internal_types import AgentResult, AgentState, AgentStep, AgentTask


class ReActAgent:
    def __init__(
        self,
        llm_client: SyncLLMClient,
        max_steps: int = 15,
    ):
        self.llm = llm_client
        self.max_steps = max_steps
        self.tools: dict[str, Callable] = {
            "get_hex_from_ida": get_hex_from_ida,
            "get_function_name_by_hex": get_function_name_by_hex,
            "get_function_name_by_string": get_function_name_by_string,
            "get_decompiled_code": get_decompiled_code,
            "get_disassembly_code": get_disassembly_code,
            "get_hex_by_code_snippet": get_hex_by_code_snippet,
            "get_hex_by_decompiled_snippet": get_hex_by_decompiled_snippet,
        }

    def _get_prompt(self, task: AgentTask) -> str:
        prompt = f"""
You are an expert security researcher specializing in vulnerability analysis and binary matching.
Your goal is to analyze a CVE based on its description and source code changes.
You are given a patched ELF file. Based on the CVE description and the code changes, you need to extract a feature string that can be used to determine whether this vulnerability has been fixed.

TASK INFORMATION:
- CVE ID: {task.cve_id}
- Target Function: {task.function_name}
- Target Binary: {task.target_binary}
- CVE Description: {task.description}
- Vulnerable Source Code:
```c
{task.vulnerable_code}
```
- Fixed Source Code:
```c
{task.fixed_code}
```

TOOLS:
1. get_decompiled_code(elf_file_path: str, function_name: str) -> str:
   Returns the decompiled pseudo-code (C-like) for a given function in the binary.
2. get_disassembly_code(elf_file_path: str, function_name: str) -> str:
   Returns the assembly code for a given function. Use this for precise hex extraction.
3. get_hex_by_code_snippet(elf_file_path: str, function_name: str, code_snippet: str) -> str:
   Finds the specific assembly code snippet in the function and returns its hex bytes.
4. get_hex_by_decompiled_snippet(elf_file_path: str, function_name: str, code_snippet: str) -> str:
   Maps a snippet of decompiled pseudo-code back to its original hex bytes in the binary.
5. get_function_name_by_string(elf_file_path: str, search_str: str) -> list[str]:
   Finds function names that reference the given string literal.
6. get_function_name_by_hex(elf_file_path: str, hex_str: str) -> list[str]:
   Verifies if a hex pattern is unique by finding all functions containing it.
7. get_hex_from_ida(elf_file_path: str, function_name: str) -> str:
   Extracts the hex string for the ENTIRE function.

GUIDELINES & REASONING FLOW:
1. **Locate**: Start by getting the decompiled code of the target function to verify its structure matches the source code provided.
2. **Analyze Diff**: Compare the decompiled code with the vulnerable/fixed source code to identify the exact lines of code that were changed.
3. **Identify Vulnerable Pattern**: Look for unique logic in the vulnerable version that is absent or changed in the fixed version. Focus on constants, specific API calls, or unique control flow.
4. **Extract Hex**: 
   - Use `get_hex_by_decompiled_snippet` to get hex for the specific vulnerable logic you identified.
   - Alternatively, use `get_disassembly_code` and then `get_hex_by_code_snippet` for more precision.
5. **Verify Uniqueness**: Use `get_function_name_by_hex` to ensure the extracted hex pattern doesn't match too many unrelated functions.
6. **Generate YARA Rule**: The `final_answer` should be a valid YARA rule containing the extracted hex patterns.

RESPONSE FORMAT:
You must return ONLY a valid JSON object,the structure is as follows:
{{
  "thought": "Your detailed reasoning process",
  "action": "tool_name" | null,
  "action_input": {{ "param": "value" }} | {{}},
  "final_answer": "The generated YARA rule or analysis result" | null
}}
You should not make any changes to field names, nor should you omit any symbols.

Begin!
"""
        return prompt

    def _parse_llm_json(self, text: str) -> dict[str, Any] | None:
        raw = (text or "").strip()
        if not raw:
            return None
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
            return None
        except json.JSONDecodeError:
            pass
        m = re.search(r"\{[\s\S]*\}", raw)
        if not m:
            return None
        try:
            parsed = json.loads(m.group(0))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None
        return None

    def run(self, task: AgentTask) -> AgentResult:
        state = AgentState(max_steps=self.max_steps)
        prompt = self._get_prompt(task)
        history = prompt
        logger = create_runtime_logger(prefix="agent", task_id=task.cve_id)
        logger.info("task", f"Starting task: {task.cve_id}")

        for step_idx in range(self.max_steps):
            logger.info("step", f"--- Step {step_idx + 1} ---")
            response = self.llm.prompt(history)
           # print(f"LLM Response:\n{history}\n")
            logger.debug("llm_response_raw", response)
            payload = self._parse_llm_json(response)
            if payload is None:
                logger.info("error", "Failed to parse LLM JSON response")
                state.finished = True
                state.result = f"Failed to parse LLM JSON response: {response}"
                break

            thought = str(payload.get("thought") or "").strip()
            action = payload.get("action")
            final_answer = payload.get("final_answer")
            action_input = payload.get("action_input")

            logger.info("thought", thought or "(empty)")

            if action:
                action_name = str(action).strip()
                if not isinstance(action_input, dict):
                    observation = (
                        f"Error: Invalid action_input, expected object: {action_input}"
                    )
                    logger.info("error", observation)
                    history += (
                        f"\nTool Observation:\n{observation}\nRespond with JSON only."
                    )
                    continue

                logger.info("action", action_name)
                logger.info(
                    "action_input", json.dumps(action_input, ensure_ascii=False)
                )

                if action_name in self.tools:
                    try:
                        logger.info("tool_exec", f"Executing {action_name}")
                        observation = self.tools[action_name](**action_input)
                        logger.info("observation", str(observation))
                    except Exception as e:
                        observation = f"Error: Failed to execute {action_name}: {e}"
                        logger.info("error", observation)
                else:
                    observation = f"Error: Unknown tool: {action_name}"
                    logger.info("error", observation)

                step = AgentStep(
                    thought=thought,
                    action=action_name,
                    action_input=action_input,
                    observation=str(observation),
                )
                state.steps.append(step)
                history += (
                    f"\nTool Observation:\n{observation}\nRespond with JSON only."
                )
                continue

            if final_answer:
                final_text = str(final_answer).strip()
                logger.info("final_answer", final_text)
                state.steps.append(
                    AgentStep(
                        thought=thought,
                        action="final_answer",
                        action_input={},
                        observation=final_text,
                    )
                )
                state.finished = True
                state.result = final_text
                break

            logger.info("error", "No action and no final_answer in LLM JSON response")
            state.finished = True
            state.result = f"Invalid LLM JSON response: {response}"
            break

        logger.info("task", f"Task finished. Success: {state.finished}")
        return AgentResult(
            success=state.finished and "Error" not in state.result,
            output=state.result,
            steps=[
                {
                    "thought": s.thought,
                    "action": s.action,
                    "action_input": s.action_input,
                    "observation": s.observation,
                }
                for s in state.steps
            ],
        )
