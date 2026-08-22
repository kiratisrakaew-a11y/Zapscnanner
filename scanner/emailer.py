import smtplib
from datetime import date, timedelta
from email.message import EmailMessage
from html import escape


def business_days_from(start: date, n: int = 5) -> date:
    """Return the date n business days after `start` (skips Sat/Sun)."""
    d, added = start, 0
    while added < n:
        d += timedelta(days=1)
        if d.weekday() < 5:
            added += 1
    return d


def build_message(target, score, risk, counts, findings, followup):
    followup_str = followup.strftime("%d/%m/%Y")
    subject = f"[Aegis] ผลประเมินความปลอดภัย {target} — score {score}/100 ({risk})"
    appt = ("โปรดนำระบบกลับมาประเมินความปลอดภัยซ้ำภายใน 5 วันทำการ "
            f"(ภายในวันที่ {followup_str}) เพื่อยืนยันว่าช่องโหว่ได้รับการแก้ไขแล้ว")
    rows = "".join(
        f"<tr><td>{escape(str(f.get('risk', '')))}</td><td>{escape(str(f.get('name', '')))}</td>"
        f"<td>{escape(str(f.get('url', '')))}</td><td>{escape(str(f.get('zap_solution', '')))}</td></tr>"
        for f in findings
    )
    # AI fix prompts (High/Medium only) — ready to paste into the user's AI coding assistant.
    fixes = [f for f in findings
             if (f.get("risk") or "").lower().startswith(("high", "medium")) and f.get("fix_prompt")]
    fix_html = fix_text = ""
    if fixes:
        blocks = "".join(
            f'<div style="margin:14px 0"><b>{escape(str(f.get("name", "")))}</b> '
            f'<span style="color:#888">({escape(str(f.get("risk", "")))})</span>'
            f'<pre style="white-space:pre-wrap;word-break:break-word;background:#0f151d;color:#e6edf3;'
            f'padding:12px;border-radius:8px;font-size:13px;margin:6px 0 0">{escape(str(f.get("fix_prompt", "")))}</pre></div>'
            for f in fixes)
        fix_html = ('<h3>🛠️ คำแนะนำแก้ไข (คัดลอกไปสั่ง AI ที่คุณใช้พัฒนา)</h3>'
                    '<p style="color:#555;font-size:13px">คัดลอกข้อความด้านล่างไปวางใน AI coding assistant '
                    '(เช่น Cursor/Copilot) เพื่อช่วยแก้ช่องโหว่ระดับ High/Medium</p>' + blocks)
        fix_text = ("\n\nคำแนะนำแก้ไข (คัดลอกไปสั่ง AI ที่คุณใช้พัฒนา):\n" +
                    "\n\n".join(f"- {f.get('name', '')} ({f.get('risk', '')}):\n{f.get('fix_prompt', '')}"
                                for f in fixes))
    html = (
        '<div style="font-family:Arial,sans-serif;color:#111">'
        "<h2>ผลการประเมินความปลอดภัย</h2>"
        f"<p>เป้าหมาย: <b>{escape(str(target))}</b><br>Security Score: <b>{score}/100</b> — "
        f"ระดับความเสี่ยง: <b>{escape(str(risk))}</b><br>"
        f"High {counts.get('high', 0)} · Medium {counts.get('medium', 0)} · "
        f"Low {counts.get('low', 0)} · Info {counts.get('info', 0)}</p>"
        f'<p style="background:#fff4d6;border:1px solid #e5c76b;padding:12px">📅 <b>นัดหมาย:</b> {appt}</p>'
        f"<h3>รายการ Finding ({len(findings)})</h3>"
        '<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-size:13px">'
        '<tr style="background:#f0f0f0"><th>Risk</th><th>Finding</th><th>URL</th><th>คำแนะนำ</th></tr>'
        f"{rows}</table>"
        + fix_html +
        '<p style="color:#888;font-size:12px">รายงานนี้อ้างอิงผลจาก OWASP ZAP ในการประเมินครั้งนี้เท่านั้น</p></div>'
    )
    text = (f"ผลการประเมิน {target}\nSecurity Score {score}/100 ({risk})\n"
            f"High {counts.get('high', 0)} Medium {counts.get('medium', 0)} "
            f"Low {counts.get('low', 0)} Info {counts.get('info', 0)}\n\n"
            f"นัดหมาย: {appt}\n\nจำนวน Finding: {len(findings)}" + fix_text)
    return subject, html, text


def build_ics(target, followup) -> str:
    start = followup.strftime("%Y%m%d")
    end = (followup + timedelta(days=1)).strftime("%Y%m%d")
    stamp = date.today().strftime("%Y%m%d")
    return ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Aegis//Rescan//TH\r\n"
            "BEGIN:VEVENT\r\n"
            f"UID:rescan-{stamp}-{abs(hash(target)) % 10**10}@aegis\r\n"
            f"DTSTAMP:{stamp}T000000Z\r\n"
            f"DTSTART;VALUE=DATE:{start}\r\nDTEND;VALUE=DATE:{end}\r\n"
            f"SUMMARY:สแกนความปลอดภัยซ้ำ - {target}\r\n"
            "DESCRIPTION:กำหนดนำระบบกลับมาประเมินความปลอดภัยซ้ำภายใน 5 วันทำการ\r\n"
            "END:VEVENT\r\nEND:VCALENDAR\r\n")


def send(host, port, user, password, sender, to, subject, html, text, ics=None):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender or user
    msg["To"] = to
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    if ics:
        msg.add_attachment(ics.encode("utf-8"), maintype="text", subtype="calendar", filename="rescan.ics")
    with smtplib.SMTP(host, int(port), timeout=30) as server:
        server.starttls()
        server.login(user, password)
        server.send_message(msg)
