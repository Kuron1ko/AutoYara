from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AgentStep:
    """Single ReAct execution step."""

    thought: str
    action: str
    action_input: dict[str, Any]
    observation: str


@dataclass(slots=True)
class AgentState:
    """Mutable state tracked across a ReAct loop."""

    steps: list[AgentStep] = field(default_factory=list)
    max_steps: int = 10
    finished: bool = False
    result: str = ""


@dataclass(slots=True)
class AgentTask:
    """Shared input for ReAct-based analysis stages."""

    cve_id: str
    target_binary: str
    function_name: str
    description: str = ""
    vulnerable_code: str = ""
    fixed_code: str = ""
    extra_context: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AgentResult:
    """Generic result produced by the base ReAct agent."""

    success: bool
    output: str
    steps: list[dict[str, Any]] = field(default_factory=list)
