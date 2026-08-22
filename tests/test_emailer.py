from datetime import date
from scanner.emailer import business_days_from, build_message, build_ics


def test_business_days_skips_weekend():
    # Mon 2024-01-01 + 5 business days -> Mon 2024-01-08 (skips Sat 6, Sun 7)
    assert business_days_from(date(2024, 1, 1), 5) == date(2024, 1, 8)
    # Fri 2024-01-05 + 1 business day -> Mon 2024-01-08
    assert business_days_from(date(2024, 1, 5), 1) == date(2024, 1, 8)


def test_build_message_has_findings_and_followup():
    findings = [{"risk": "Medium", "name": "CSP missing", "url": "https://x", "zap_solution": "add header"}]
    counts = {"high": 0, "medium": 1, "low": 0, "info": 2}
    subject, html, text = build_message("https://x", 92, "MEDIUM", counts, findings, date(2024, 1, 8))
    assert "https://x" in subject
    assert "CSP missing" in html and "08/01/2024" in html and "นัดหมาย" in html
    assert "08/01/2024" in text


def test_build_message_includes_fix_prompts_for_high_medium():
    findings = [
        {"risk": "High", "name": "XSS", "url": "u", "zap_solution": "s", "fix_prompt": "สั่ง AI แก้ XSS"},
        {"risk": "Low", "name": "Cookie", "url": "u", "zap_solution": "s", "fix_prompt": "ไม่ควรโผล่"},
    ]
    counts = {"high": 1, "medium": 0, "low": 1, "info": 0}
    subject, html, text = build_message("https://x", 80, "HIGH", counts, findings, date(2024, 1, 8))
    assert "คำแนะนำแก้ไข" in html
    assert "สั่ง AI แก้ XSS" in html and "สั่ง AI แก้ XSS" in text   # High shown
    assert "ไม่ควรโผล่" not in html                                   # Low excluded


def test_build_ics_is_vevent():
    ics = build_ics("https://x", date(2024, 1, 8))
    assert "BEGIN:VEVENT" in ics and "DTSTART;VALUE=DATE:20240108" in ics
