import json
import logging
from web.config import Settings
from web.models import Finding

logger = logging.getLogger("aegis.ai")


class AIService:
    def __init__(self, settings: Settings): self.settings = settings

    def _client(self):
        from openai import OpenAI
        base_url = self.settings.openai_base_url or None
        if base_url and not base_url.startswith(("http://", "https://")):
            base_url = "https://" + base_url  # tolerate a base_url configured without a scheme
        # Fail fast so a broken endpoint/key surfaces quickly instead of hanging on retries.
        return OpenAI(api_key=self.settings.openai_api_key, base_url=base_url, max_retries=0, timeout=15)

    def enrich(self, finding: Finding) -> Finding:
        """Interpret a ZAP finding only; never creates or changes findings/severity."""
        if not self.settings.openai_api_key:
            logger.warning("OPENAI_API_KEY not configured; using ZAP fallback for %s", finding.alert_id)
            finding.plain_language_title = finding.plain_language_title or finding.name
            finding.plain_language_summary = finding.plain_language_summary or finding.zap_description
            finding.recommended_action = finding.recommended_action or finding.zap_solution
            finding.ai_available = False
            return finding
        prompt = "อธิบาย ZAP finding ที่ให้เท่านั้นเป็นภาษาไทย ห้ามสร้าง finding หรือเปลี่ยน severity ตอบเป็น JSON object: plain_language_title, plain_language_summary, business_impact, recommended_action, owasp_category.\n" + finding.model_dump_json()
        try:
            response = self._client().chat.completions.create(model=self.settings.openai_model, messages=[{"role": "user", "content": prompt}], response_format={"type": "json_object"})
            data = json.loads(response.choices[0].message.content)
            for field in data:
                if field in {"plain_language_title", "plain_language_summary", "business_impact", "recommended_action", "owasp_category"}: setattr(finding, field, data[field])
            finding.ai_available = True
        except Exception:
            logger.exception("OpenAI enrichment failed for %s (model=%s)", finding.alert_id, self.settings.openai_model)
            finding.ai_available = False
        return finding

    def summarize(self, target: str, counts: dict, names: list[str]) -> str:
        """Generate a Thai business-oriented executive summary from ZAP findings.

        Returns "" on any failure (no key, API error) so the caller can fall back.
        """
        if not self.settings.openai_api_key:
            logger.warning("OPENAI_API_KEY not configured; no executive summary for %s", target)
            return ""
        prompt = ("เขียนบทสรุปผู้บริหาร (Executive Summary) ภาษาไทยเชิงธุรกิจ 3-5 ประโยค จากผลสแกนความปลอดภัยเว็บนี้ "
                  "ห้ามแต่งข้อมูลเกินจากที่ให้ ตอบเป็น JSON object รูปแบบ {\"executive_summary\": \"...\"}\n"
                  f"target={target} counts={json.dumps(counts, ensure_ascii=False)} "
                  f"alert_types={json.dumps(names[:60], ensure_ascii=False)}")
        try:
            response = self._client().chat.completions.create(model=self.settings.openai_model, messages=[{"role": "user", "content": prompt}], response_format={"type": "json_object"})
            return json.loads(response.choices[0].message.content).get("executive_summary", "") or ""
        except Exception:
            logger.exception("OpenAI summary failed for %s (model=%s)", target, self.settings.openai_model)
            return ""
