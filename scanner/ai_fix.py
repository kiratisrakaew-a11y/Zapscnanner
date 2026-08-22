"""AI-generated remediation prompt for the scanner job.

Produces a ready-to-paste Thai instruction the user can hand to their own AI coding
assistant (Cursor/Copilot/"vibe coding") to fix a finding. Only meant for High/Medium
findings. Self-contained (the scanner image ships only scanner/, so it cannot import
web.services.ai_service).
"""
import json
import os
import sys


def _client(api_key, base_url):
    from openai import OpenAI
    base_url = (base_url or "").strip()
    if base_url and not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    # Always pass an explicit, scheme-qualified base_url: with base_url=None the SDK
    # falls back to OPENAI_BASE_URL, which Cloud Run may set to "" -> UnsupportedProtocol.
    return OpenAI(api_key=api_key, base_url=base_url or "https://api.openai.com/v1",
                  max_retries=0, timeout=20)


def generate(finding: dict, model: str, api_key: str, base_url: str = "") -> str:
    """Return a Thai fix-prompt for the finding, or "" on any failure/no key."""
    if not api_key:
        return ""
    risk = (finding.get("risk") or "").lower()
    if risk.startswith("high"):
        tone = ("ระดับความรุนแรงสูง: ให้คำสั่งที่เจาะจงและลงมือแก้ได้ทันที ระบุไฟล์/ส่วนของโค้ดที่ควรแก้ "
                "และผลลัพธ์ที่คาดหวังหลังแก้")
    else:
        tone = ("ระดับความรุนแรงปานกลาง: เปิดด้วยหมายเหตุว่าช่องโหว่นี้ 'อาจไม่ได้เกิดจากโค้ดที่ผู้ใช้เขียนเอง' "
                "(อาจมาจากค่า default ของ hosting/framework) แล้วค่อยให้คำแนะนำกลาง ๆ ที่ทำได้ถ้าเกี่ยวกับโค้ด")
    prompt = (
        "คุณเป็นผู้ช่วยด้านความปลอดภัย เขียน 'prompt ภาษาไทย' ที่ผู้ใช้จะคัดลอกไปสั่ง AI coding assistant "
        "(เช่น Cursor/Copilot) เพื่อแก้ช่องโหว่นี้ในโปรเจกต์ของเขา ตอบเป็น JSON object รูปแบบ "
        '{"fix_prompt": "..."} เท่านั้น. ห้ามแต่งข้อมูลเกินจากที่ให้ ห้ามสมมติเทคโนโลยีที่ไม่ทราบ '
        "ให้ prompt สั้นกระชับ นำไปใช้ได้จริง. " + tone + "\n\nรายละเอียดช่องโหว่:\n"
        + json.dumps({k: finding.get(k, "") for k in ("name", "risk", "url", "zap_description", "zap_solution")},
                     ensure_ascii=False)
    )
    try:
        resp = _client(api_key, base_url).chat.completions.create(
            model=model, messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"})
        return json.loads(resp.choices[0].message.content).get("fix_prompt", "") or ""
    except Exception as exc:
        print(f"ai_fix failed for {finding.get('alert_id')}: {exc}", file=sys.stderr)
        return ""
