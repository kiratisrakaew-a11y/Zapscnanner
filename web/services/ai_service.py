import json
from web.config import Settings
from web.models import Finding


class AIService:
    def __init__(self, settings: Settings): self.settings = settings

    def enrich(self, finding: Finding) -> Finding:
        """Interpret a ZAP finding only; never creates or changes findings/severity."""
        if not self.settings.gemini_api_key:
            finding.plain_language_title = finding.plain_language_title or finding.name
            finding.plain_language_summary = finding.plain_language_summary or finding.zap_description
            finding.recommended_action = finding.recommended_action or finding.zap_solution
            finding.ai_available = False
            return finding
        from google import genai
        client = genai.Client(api_key=self.settings.gemini_api_key)
        prompt = "อธิบาย ZAP finding ที่ให้เท่านั้นเป็นภาษาไทย ห้ามสร้าง finding หรือเปลี่ยน severity ตอบ JSON: plain_language_title, plain_language_summary, business_impact, recommended_action, owasp_category.\n" + finding.model_dump_json()
        try:
            response = client.models.generate_content(model=self.settings.gemini_model, contents=prompt, config={"response_mime_type": "application/json"})
            data = json.loads(response.text)
            for field in data:
                if field in {"plain_language_title", "plain_language_summary", "business_impact", "recommended_action", "owasp_category"}: setattr(finding, field, data[field])
            finding.ai_available = True
        except Exception:
            finding.ai_available = False
        return finding
