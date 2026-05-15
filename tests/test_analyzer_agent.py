import importlib.util
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path


def _install_stub_package(name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__path__ = []
    sys.modules[name] = module
    return module


def _load_analyzer_module():
    module_name = "test_analyzer_agent_under_test"
    for name in [
        module_name,
        "autoyara",
        "autoyara.ReAct",
        "autoyara.ReAct.locator_agent",
        "autoyara.ida",
        "autoyara.ida.mcptools",
        "autoyara.llm",
        "autoyara.llm.sync_client",
        "autoyara.runtime_logger",
    ]:
        sys.modules.pop(name, None)

    _install_stub_package("autoyara")
    _install_stub_package("autoyara.ReAct")
    _install_stub_package("autoyara.ida")
    _install_stub_package("autoyara.llm")

    locator_module = types.ModuleType("autoyara.ReAct.locator_agent")

    @dataclass(slots=True)
    class LocatorResult:
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
        steps: list[dict[str, str]] = field(default_factory=list)

    locator_module.LocatorResult = LocatorResult
    sys.modules["autoyara.ReAct.locator_agent"] = locator_module

    mcptools_module = types.ModuleType("autoyara.ida.mcptools")
    mcptools_module.get_hex_by_address_range = lambda **_: ""
    sys.modules["autoyara.ida.mcptools"] = mcptools_module

    llm_module = types.ModuleType("autoyara.llm.sync_client")
    llm_module.SyncLLMClient = object
    sys.modules["autoyara.llm.sync_client"] = llm_module

    runtime_logger_module = types.ModuleType("autoyara.runtime_logger")

    class DummyLogger:
        def info(self, *_args, **_kwargs):
            return None

        def warn(self, *_args, **_kwargs):
            return None

        def error(self, *_args, **_kwargs):
            return None

    runtime_logger_module.create_runtime_logger = lambda **_: DummyLogger()
    sys.modules["autoyara.runtime_logger"] = runtime_logger_module

    analyzer_path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "autoyara"
        / "ReAct"
        / "analyzer_agent.py"
    )
    spec = importlib.util.spec_from_file_location(module_name, analyzer_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_analyzer_ignores_same_turn_final_answer_and_uses_tool_hex():
    analyzer_module = _load_analyzer_module()
    AnalyzerAgent = analyzer_module.AnalyzerAgent
    LocatorResult = sys.modules["autoyara.ReAct.locator_agent"].LocatorResult

    class FakeLLM:
        def __init__(self):
            self.calls = 0

        def prompt(self, _history: str) -> str:
            self.calls += 1
            if self.calls == 1:
                return """{"thought":"extract bytes","action":"get_hex_by_address_range","action_input":{"start_addr":"0x1000","end_addr":"0x1010"},"final_answer":null}
{"thought":"hallucinated final","final_answer":{"success":true,"diff_analysis":"wrong turn","raw_hex":"11 22 33 44","explanation":"should be ignored","confidence":0.1}}"""
            return """{"thought":"use observed bytes","final_answer":{"success":true,"diff_analysis":"real final","raw_hex":"11 22 33 44","explanation":"tool-backed","confidence":0.95}}"""

    vuln_res = LocatorResult(
        success=True,
        cve_id="CVE-TEST",
        function_name="func_vuln",
        vulnerable_code_segment="vuln code",
        vulnerable_assembly_segment="vuln asm",
        start_address="0x1000",
        end_address="0x1010",
        reasoning="",
        confidence=0.9,
    )
    fixed_res = LocatorResult(
        success=True,
        cve_id="CVE-TEST",
        function_name="func_fixed",
        vulnerable_code_segment="fixed code",
        vulnerable_assembly_segment="fixed asm",
        start_address="0x2000",
        end_address="0x2010",
        reasoning="",
        confidence=0.9,
    )

    agent = AnalyzerAgent(FakeLLM(), max_steps=3)
    agent.tools["get_hex_by_address_range"] = (
        lambda **_: "E0 85 8A D2 C2 F2 00 F0 42 80 2A 91 00 42 A9 F2"
    )

    result = agent.run(vuln_res, fixed_res, "fixed.elf")

    assert result.success is True
    assert result.diff_analysis == "real final"
    assert result.explanation == "tool-backed"
    assert result.raw_hex == "E0 85 8A D2 C2 F2 00 F0 42 80 2A 91 00 42 A9 F2"
    assert agent.llm.calls == 2
