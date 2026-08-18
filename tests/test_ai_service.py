import json
import types
from web.api.scans import enriched_findings
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


def test_base_url_without_scheme_gets_https(monkeypatch):
    captured = {}

    class FakeCompletions:
        def create(self, **kwargs):
            msg = types.SimpleNamespace(content=json.dumps({"business_impact": "x"}))
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)])

    class FakeOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            self.chat = types.SimpleNamespace(completions=FakeCompletions())

    monkeypatch.setattr("openai.OpenAI", FakeOpenAI)
    AIService(Settings(openai_api_key="x", openai_base_url="gen.ai.kku.ac.th/okmd/api/v1")).enrich(_finding())
    assert captured["base_url"] == "https://gen.ai.kku.ac.th/okmd/api/v1"


def test_enriched_findings_dedup_by_name(monkeypatch):
    findings = [Finding(alert_id=str(i), name=("A" if i % 2 == 0 else "B"), risk="Low", url="u") for i in range(10)]

    class Store:
        def __init__(self, fs): self._f = fs; self.saved = None
        def get_findings(self, sid): return self._f
        def save_findings(self, sid, fs): self.saved = fs

    calls = {"n": 0}
    ai = AIService(Settings(openai_api_key="x"))
    def fake_enrich(f):
        calls["n"] += 1; f.business_impact = "X"; f.ai_available = True; return f
    monkeypatch.setattr(ai, "enrich", fake_enrich)
    app = types.SimpleNamespace(store=Store(findings),
                                settings=Settings(openai_api_key="x", ai_enrich_per_request=20), ai=ai)
    out = enriched_findings(app, "s")
    assert calls["n"] == 2                      # one call per distinct name (A, B), not 10
    assert all(f.ai_available for f in out)
    assert app.store.saved is not None          # persisted


def test_enriched_findings_caps_calls(monkeypatch):
    findings = [Finding(alert_id=str(i), name=f"name-{i}", risk="Low", url="u") for i in range(50)]

    class Store:
        def get_findings(self, sid): return findings
        def save_findings(self, sid, fs): pass

    calls = {"n": 0}
    ai = AIService(Settings(openai_api_key="x"))
    def fake_enrich(f):
        calls["n"] += 1; f.ai_available = True; return f
    monkeypatch.setattr(ai, "enrich", fake_enrich)
    app = types.SimpleNamespace(store=Store(),
                                settings=Settings(openai_api_key="x", ai_enrich_per_request=15), ai=ai)
    enriched_findings(app, "s")
    assert calls["n"] == 15                      # bounded by ai_enrich_per_request
