import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from autoyara.llm.response_parser import parse_llm_json


def test_parse_plain_json():
    raw = '{"month":"2025-09","ok":true}'
    data = parse_llm_json(raw)
    assert data["month"] == "2025-09"
    assert data["ok"] is True


def test_parse_fenced_json():
    raw = '```json\n{"ok": true, "name": "cve"}\n```'
    data = parse_llm_json(raw)
    assert data == {"ok": True, "name": "cve"}


def test_parse_python_literal_bools():
    raw = '{"affected_device": {"standard": {"linux": {"arm64": {"enable": False, "ists": {"enable": True}}}}}}'
    data = parse_llm_json(raw)
    arm64 = data["affected_device"]["standard"]["linux"]["arm64"]
    assert arm64["enable"] is False
    assert arm64["ists"]["enable"] is True


def test_parse_with_prefix_suffix_text():
    raw = "Result follows:\\n\\n{'ok': True, 'score': 3}\\n\\nThanks."
    data = parse_llm_json(raw)
    assert data["ok"] is True
    assert data["score"] == 3


def test_parse_with_unmatched_extra_closer():
    raw = '{"month":"2025-09","vulnerabilities":[{"id":"CVE-2025-37839"}]]}'
    data = parse_llm_json(raw)
    assert data["month"] == "2025-09"
    assert data["vulnerabilities"][0]["id"] == "CVE-2025-37839"
