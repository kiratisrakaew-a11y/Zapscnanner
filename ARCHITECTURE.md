# Architecture

```text
Browser -> Cloud Run Web (FastAPI) -> Firestore scans/audit_logs
                         | async dispatch
                         v
                 Cloud Run Job (OWASP ZAP)
                         |
                  JSON parser -> Firestore alerts
                         |
                 optional Gemini interpretation
```

Web instance ไม่ถือ scan state ใน production. Firestore เป็น source of truth; `MemoryStore` มีไว้ local/test เท่านั้น Scanner Job ใช้ Quick plan (Spider + Passive) หรือ Standard plan (Spider + Passive + Active) และไม่รับ login credentials

## Security boundaries

API ตรวจ scheme/hostname/DNS/IP และปฏิเสธ non-global destinations ก่อนสร้างงาน Scanner ควรทำ validation ซ้ำรวมทั้งทุก redirect ที่ network egress proxy/firewall เพราะ DNS rebinding และ redirect เกิดหลัง dispatch ได้ Production ควรจำกัด egress, deny metadata `169.254.169.254`, ใช้ session identity ที่เชื่อถือได้แทน client header, เปิด Cloud Armor rate limits และอนุญาต job service account เฉพาะ Firestore documents ที่จำเป็น

AI รับเฉพาะ ZAP finding ที่มีอยู่แล้ว และห้ามเปลี่ยน severity หรือสร้าง finding. AI เป็น optional enrichment; ZAP fields คือ fallback

