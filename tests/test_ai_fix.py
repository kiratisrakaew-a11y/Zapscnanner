import json
import types
from scanner import ai_fix


def _mock_openai(monkeypatch, capture=None):
    class FakeCompletions:
        def create(self, **kwargs):
            if capture is not None:
                capture.update(kwargs)
            msg = types.SimpleNamespace(content=json.dumps({"fix_prompt": "แก้แบบนี้"}))
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)])

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.chat = types.SimpleNamespace(completions=FakeCompletions())

    monkeypatch.setattr("openai.OpenAI", FakeOpenAI)


def test_generate_returns_prompt(monkeypatch):
    _mock_openai(monkeypatch)
    out = ai_fix.generate({"name": "XSS", "risk": "High", "url": "u"}, "gpt-4o-mini", "sk-x")
    assert out == "แก้แบบนี้"


def test_generate_without_key_returns_empty(monkeypatch):
    _mock_openai(monkeypatch)
    assert ai_fix.generate({"name": "x", "risk": "High"}, "gpt-4o-mini", "") == ""


def test_medium_prompt_is_cautious(monkeypatch):
    cap = {}
    _mock_openai(monkeypatch, cap)
    ai_fix.generate({"name": "CSP", "risk": "Medium", "url": "u"}, "gpt-4o-mini", "sk-x")
    sent = cap["messages"][0]["content"]
    assert "อาจไม่ได้เกิดจากโค้ด" in sent      # Medium gets the cautionary framing
