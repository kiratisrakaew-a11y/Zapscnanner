import json
import types
from web.config import Settings
from web.models import Finding
from web.services.ai_service import AIService


def _finding():
    return Finding(alert_id="1", name="CSP missing", risk="Medium", url="https://example.com",
                   zap_description="desc", zap_solution="sol")


def test_enrich_fallback_without_key():
    finding = AIService(Settings(openai_api_key=None)).enrich(_finding())
    assert finding.ai_available is False
    assert finding.plain_language_title == "CSP missing"      # filled from ZAP name
    assert finding.business_impact == ""                       # only AI sets this


def test_enrich_uses_openai(monkeypatch):
    payload = {"plain_language_title": "หัวข้อ", "plain_language_summary": "สรุป",
               "business_impact": "ผลกระทบ", "recommended_action": "ทำสิ่งนี้",
               "owasp_category": "A05: Security Misconfiguration"}

    class FakeCompletions:
        def create(self, **kwargs):
            msg = types.SimpleNamespace(content=json.dumps(payload))
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)])

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.chat = types.SimpleNamespace(completions=FakeCompletions())

    monkeypatch.setattr("openai.OpenAI", FakeOpenAI)
    finding = AIService(Settings(openai_api_key="sk-test", openai_model="gpt-4o-mini")).enrich(_finding())
    assert finding.ai_available is True
    assert finding.business_impact == "ผลกระทบ"
    assert finding.plain_language_title == "หัวข้อ"
    assert finding.owasp_category == "A05: Security Misconfiguration"
