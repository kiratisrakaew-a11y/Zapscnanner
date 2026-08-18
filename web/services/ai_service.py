import json
import logging
from web.config import Settings
from web.models import Finding

logger = logging.getLogger("aegis.ai")


class AIService:
    def __init__(self, settings: Settings): self.settings = settings

    def enrich(self, finding: Finding) -> Finding:
        """Interpret a ZAP finding only; never creates or changes findings/severity."""
        if not self.settings.openai_api_key:
            logger.warning("OPENAI_API_KEY not configured; using ZAP fallback for %s", finding.alert_id)
            finding.plain_language_title = finding.plain_language_title or finding.name
            finding.plain_language_summary = finding.plain_language_summary or finding.zap_description
            finding.recommended_action = finding.recommended_action or finding.zap_solution
            finding.ai_available = False
            return finding
        from openai import OpenAI
        base_url = self.settings.openai_base_url or None
        if base_url and not base_url.startswith(("http://", "https://")):
            base_url = "https://" + base_url  # tolerate a base_url configured without a scheme
        client = OpenAI(api_key=self.settings.openai_api_key, base_url=base_url)
        prompt = "อธิบาย ZAP finding ที่ให้เท่านั้นเป็นภาษาไทย ห้ามสร้าง finding หรือเปลี่ยน severity ตอบเป็น JSON object: plain_language_title, plain_language_summary, business_impact, recommended_action, owasp_category.\n" + finding.model_dump_json()
        try:
            response = client.chat.completions.create(model=self.settings.openai_model, messages=[{"role": "user", "content": prompt}], response_format={"type": "json_object"})
            data = json.loads(response.choices[0].message.content)
            for field in data:
                if field in {"plain_language_title", "plain_language_summary", "business_impact", "recommended_action", "owasp_category"}: setattr(finding, field, data[field])
            finding.ai_available = True
        except Exception:
            logger.exception("OpenAI enrichment failed for %s (model=%s)", finding.alert_id, self.settings.openai_model)
            finding.ai_available = False
        return finding
